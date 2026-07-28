"""
browser_auth.py - External browser sign-in for the IDA client.

The client opens the dashboard in the user's browser, waits on a loopback
HTTP callback, and stores the sign-in credential returned by the signed-in
dashboard session.
"""

from __future__ import annotations

import html
import base64
import hashlib
import json
import secrets
import threading
import time
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

from .config import ACTIVE_API_URL, ACTIVE_DASHBOARD_URL, CLIENT_USER_AGENT
from . import device_identity


class BrowserAuthError(Exception):
    pass


class BrowserAuthCancelled(BrowserAuthError):
    """Raised when the host dialog cancels an in-progress browser sign-in."""


def dashboard_url_for() -> str:
    return ACTIVE_DASHBOARD_URL


def sign_in_with_browser(
    timeout_s: int = 180,
    cancel_event: threading.Event | None = None,
) -> dict:
    if cancel_event is not None and cancel_event.is_set():
        raise BrowserAuthCancelled("Browser sign-in was cancelled.")
    state = secrets.token_urlsafe(24)
    code_verifier = secrets.token_urlsafe(48)
    code_challenge = _code_challenge(code_verifier)
    device_public_key = device_identity.public_key(ACTIVE_API_URL)
    dashboard_origin = _origin(ACTIVE_DASHBOARD_URL)
    server = _CallbackServer(("127.0.0.1", 0), state, dashboard_origin)
    port = server.server_address[1]
    callback = f"http://127.0.0.1:{port}/decompile-auth/callback"

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        auth_url = _auth_url(
            dashboard_url_for(), callback, state, code_challenge, device_public_key
        )
        if not webbrowser.open(auth_url, new=1, autoraise=True):
            raise BrowserAuthError(f"Could not open browser. Visit this URL manually:\n{auth_url}")

        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if cancel_event is not None and cancel_event.is_set():
                raise BrowserAuthCancelled("Browser sign-in was cancelled.")
            if server.auth_code:
                exchange = _exchange_auth_code(server.auth_code, state, code_verifier)
                return {
                    "refresh_token": exchange["refresh_token"],
                    "user_id": exchange.get("user_id", ""),
                    "email": exchange.get("email", ""),
                    "name": exchange.get("profile_name", "") or exchange.get("email", ""),
                    "avatar_url": exchange.get("avatar_url", ""),
                    "device_fingerprint": device_public_key,
                    "server_url": ACTIVE_API_URL,
                }
            if server.error:
                raise BrowserAuthError(server.error)
            if cancel_event is not None:
                cancel_event.wait(0.1)
            else:
                time.sleep(0.1)
        raise BrowserAuthError("Timed out waiting for browser sign-in.")
    finally:
        server.shutdown()
        server.server_close()


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _exchange_auth_code(auth_code: str, state: str, code_verifier: str) -> dict:
    payload = {
        "auth_code": auth_code,
        "state": state,
        "code_verifier": code_verifier,
    }
    payload.update(
        device_identity.code_exchange_proof(
            ACTIVE_API_URL, auth_code, state, code_verifier
        )
    )
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{ACTIVE_API_URL}/auth/client-codes/exchange",
        data=body,
        headers={
            "content-type": "application/json",
            "accept": "application/json",
            "user-agent": CLIENT_USER_AGENT,
        },
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(_NoRedirectHandler())
        with opener.open(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        raise BrowserAuthError(f"Could not exchange browser sign-in code: {e}") from e

    token = str(data.get("refresh_token", "") or "")
    if not token:
        raise BrowserAuthError("Sign-in exchange did not return a credential.")
    return {
        "refresh_token": token,
        "user_id": str(data.get("user_id", "") or ""),
        "email": str(data.get("email", "") or ""),
        "profile_name": str(data.get("profile_name", "") or ""),
        "avatar_url": str(data.get("avatar_url", "") or ""),
    }


def _auth_url(
    dashboard_url: str,
    callback: str,
    state: str,
    code_challenge: str,
    device_public_key: str,
) -> str:
    params = urllib.parse.urlencode({
        "callback": callback,
        "state": state,
        "challenge": code_challenge,
        "device_key": device_public_key,
        "client": "ida_pro",
    })
    return f"{dashboard_url.rstrip('/')}/client-auth?{params}"


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _origin(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}"


class _CallbackServer(HTTPServer):
    def __init__(self, address, state: str, expected_origin: str):
        super().__init__(address, _CallbackHandler)
        self.expected_state = state
        self.expected_origin = expected_origin
        self.auth_code: str = ""
        self.error: str = ""


class _CallbackHandler(BaseHTTPRequestHandler):
    server: _CallbackServer

    def finish(self):
        super().finish()
        auth_code = getattr(self, "_accepted_auth_code", "")
        if auth_code:
            self.server.auth_code = auth_code

    def do_GET(self):  # noqa: N802 - http.server API
        target = urllib.parse.urlsplit(self.path)
        if target.path != "/decompile-auth/callback" or target.query:
            self._send_html(404, "Invalid callback path.")
            return
        self._send_html(
            200,
            "Waiting for the dashboard to finish sign-in. You can return to IDA.",
        )

    def do_POST(self):  # noqa: N802 - http.server API
        target = urllib.parse.urlsplit(self.path)
        if target.path != "/decompile-auth/callback" or target.query:
            self._send_html(404, "Invalid callback path.")
            return
        origin = self.headers.get("origin", "")
        if origin != self.server.expected_origin:
            self.server.error = "Invalid callback origin."
            self._send_html(403, self.server.error)
            return
        try:
            length = int(self.headers.get("content-length", "0") or "0")
        except ValueError:
            length = -1
        if length < 1 or length > 16 * 1024:
            self._send_html(413, "Invalid callback body size.")
            return
        raw = self.rfile.read(length)
        state, auth_code, error = self._parse_body(raw)

        if error:
            self.server.error = error
            self._send_html(400, error)
            return
        if state != self.server.expected_state:
            self.server.error = "Browser sign-in state mismatch."
            self._send_html(400, self.server.error)
            return
        if not auth_code:
            self.server.error = "Dashboard callback did not include a sign-in code."
            self._send_html(400, self.server.error)
            return
        if not _is_url_token(auth_code, 32, 128):
            self.server.error = "Dashboard callback included an invalid sign-in code."
            self._send_html(400, self.server.error)
            return

        completion_url = (
            f"{self.server.expected_origin}/client-auth/complete?"
            + urllib.parse.urlencode({"state": self.server.expected_state})
        )
        self._send_redirect(completion_url)
        self._accepted_auth_code = auth_code

    def log_message(self, _fmt, *_args):
        return

    def _parse_body(self, raw: bytes) -> tuple[str, str, str | None]:
        content_type = self.headers.get("content-type", "")
        try:
            if "application/json" in content_type:
                body = json.loads(raw.decode("utf-8"))
                return (
                    str(body.get("state", "")),
                    str(body.get("auth_code", "")),
                    str(body.get("error", "")) or None,
                )
            form = urllib.parse.parse_qs(raw.decode("utf-8"))
            return (
                _first(form, "state"),
                _first(form, "auth_code"),
                _first(form, "error") or None,
            )
        except Exception as e:
            return "", "", f"Could not parse dashboard callback: {e}"

    def _send_html(self, status: int, message: str):
        safe = html.escape(message)
        body = (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>Decompile.re sign-in</title></head>"
            "<body style='font-family:system-ui,sans-serif;margin:3rem'>"
            f"<h1>{safe}</h1></body></html>"
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("content-type", "text/html; charset=utf-8")
        self.send_header("cache-control", "no-store, max-age=0")
        self.send_header("content-security-policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_redirect(self, location: str):
        self.send_response(303)
        self.send_header("location", location)
        self.send_header("cache-control", "no-store, max-age=0")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("content-length", "0")
        self.end_headers()


def _first(values: dict, key: str) -> str:
    vals = values.get(key, [])
    return vals[0] if vals else ""


def _is_url_token(value: str, minimum: int, maximum: int) -> bool:
    return minimum <= len(value) <= maximum and all(
        char.isascii() and (char.isalnum() or char in "-_") for char in value
    )
