"""
session.py - HTTP session client for the Go analysis server.

Implements the browser-issued refresh-token + short-lived access-JWT flow.
The long-lived credential and per-install signing key are stored in the OS
credential store. This module:

  1. Exchanges the refresh token for a short-lived ES256 access JWT via
     POST /auth/refresh/exchange, persisting the rotated refresh token on
     every successful exchange.
  2. Injects `Authorization: Bearer <access_jwt>` + `X-Decompile-Fingerprint`
     on every /session* and /me/* call, transparently re-exchanging when
     the cached access JWT is missing or about to expire.

The access JWT lives in process memory only and is never written to disk
or logged. Refresh tokens are never logged either.

Protocol (analysis lifecycle):

  POST   /session              -> start analysis, receive {session_id}
  GET    /session/{id}/next   -> long-poll after the last committed sequence
  POST   /session/{id}/commands/{command_id}/result -> submit an idempotent result
  POST   /session/{id}/commands/results -> submit an idempotent result batch
  POST   /session/{id}/resume -> recover after an API restart
  DELETE /session/{id}        -> cancel
  GET    /session/history     -> list persisted sessions for this account
  GET    /session/{id}/history -> load one persisted session for display
  DELETE /session/{id}/history -> permanently delete a persisted session
"""

from __future__ import annotations

import platform
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any

import requests
from requests.adapters import HTTPAdapter

from . import device_identity, secret_store
from .config import CLIENT_USER_AGENT, is_loopback_server_url, validate_server_url


# Refresh the access JWT this many seconds before its server-reported expiry.
_ACCESS_JWT_REFRESH_LEEWAY_S = 60
_PROTOCOL_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")


class AuthError(Exception):
    """Raised when the server refuses our refresh token (401/403).

    The worker thread catches this and asks the user to sign in again.
    """

    def __init__(self, message: str, rejected: bool = False, reason: str = ""):
        super().__init__(message)
        self.rejected = rejected
        self.reason = reason


class BillingError(Exception):
    """Raised on HTTP 402 from /session.

    `reason` is the machine-readable code from the server response body
    (one of usage_limit_reached / model_tier_not_in_plan /
    concurrency_limit_reached / token_velocity_cap / etc).
    """

    def __init__(self, message: str, reason: str = ""):
        super().__init__(message)
        self.reason = reason


class SessionStartError(Exception):
    """Raised when an account or service state prevents a new analysis."""

    def __init__(self, message: str, reason: str = ""):
        super().__init__(message)
        self.reason = reason


class ServerProtocolError(RuntimeError):
    """Raised when the analysis server returns an invalid protocol payload."""


def _require_protocol_id(value: object, label: str) -> str:
    if not isinstance(value, str) or not _PROTOCOL_ID_RE.fullmatch(value):
        raise ServerProtocolError(f"Invalid {label} received from server.")
    return value


class AuthContext:
    """Process-local authentication state shared by one account and device."""

    def __init__(
        self,
        server_url: str,
        refresh_token: str,
        device_fingerprint: str,
        account_id: str = "",
    ):
        self.server_url = validate_server_url(server_url)
        self.refresh_token = refresh_token or ""
        self.device_fingerprint = device_fingerprint or ""
        self.account_id = account_id
        self.access_jwt = ""
        self.access_jwt_exp = 0.0
        self.last_auth_info: dict[str, Any] = {}
        self.auth_required: bool | None = None
        self.lock = threading.RLock()

    def clear(self) -> None:
        with self.lock:
            self.refresh_token = ""
            self.access_jwt = ""
            self.access_jwt_exp = 0.0
            self.last_auth_info = {}
            self.auth_required = None


_AUTH_CONTEXTS: dict[tuple[str, str, str], AuthContext] = {}
_AUTH_CONTEXTS_LOCK = threading.Lock()


def get_shared_auth_context(
    server_url: str,
    refresh_token: str,
    device_fingerprint: str,
    account_id: str = "",
) -> AuthContext:
    normalized_url = validate_server_url(server_url)
    key = (normalized_url, account_id or "default", device_fingerprint or "")
    with _AUTH_CONTEXTS_LOCK:
        context = _AUTH_CONTEXTS.get(key)
        if context is None:
            context = AuthContext(
                normalized_url,
                refresh_token,
                device_fingerprint,
                account_id,
            )
            _AUTH_CONTEXTS[key] = context
        return context


def find_shared_auth_context(
    server_url: str,
    account_id: str = "",
) -> AuthContext | None:
    """Return the existing process-local context for one server/account."""
    normalized_url = validate_server_url(server_url)
    account_key = account_id or "default"
    with _AUTH_CONTEXTS_LOCK:
        matches = [
            context
            for (url, saved_account, _device), context in _AUTH_CONTEXTS.items()
            if url == normalized_url and saved_account == account_key
        ]
    return matches[0] if len(matches) == 1 else None


def reset_shared_auth_context(account_id: str = "", server_url: str = "") -> None:
    normalized_url = validate_server_url(server_url) if server_url else ""
    removed = []
    with _AUTH_CONTEXTS_LOCK:
        for key, context in list(_AUTH_CONTEXTS.items()):
            if account_id and key[1] != account_id:
                continue
            if normalized_url and key[0] != normalized_url:
                continue
            removed.append(context)
            del _AUTH_CONTEXTS[key]
    for context in removed:
        context.clear()


class ServerSession:
    """Manages a single analysis session against the Go server.

    Analysis state is private to this instance. Authentication state may be
    shared with other sessions for the same account and device.
    """

    def __init__(
        self,
        server_url: str,
        refresh_token: str,
        device_fingerprint: str,
        account_id: str = "",
        auth_context: AuthContext | None = None,
    ):
        normalized_url = validate_server_url(server_url)
        if auth_context is not None and auth_context.server_url != normalized_url:
            raise ValueError("Authentication context belongs to a different server")
        if auth_context is not None and auth_context.account_id != (account_id or ""):
            raise ValueError("Authentication context belongs to a different account")
        if auth_context is not None and auth_context.device_fingerprint != (device_fingerprint or ""):
            raise ValueError("Authentication context belongs to a different device")
        self._auth_context = auth_context or AuthContext(
            normalized_url,
            refresh_token,
            device_fingerprint,
            account_id,
        )
        self.server_url = self._auth_context.server_url
        self._device_fingerprint = self._auth_context.device_fingerprint
        self._account_id = self._auth_context.account_id
        self.session_id: str | None = None
        self._http = self._make_client()
        self._poll_http = self._make_client()
        self._auth_lock = self._auth_context.lock
        self._http_lock = threading.Lock()
        self._last_sequence = 0

    @property
    def _refresh_token(self) -> str:
        return self._auth_context.refresh_token

    @_refresh_token.setter
    def _refresh_token(self, value: str) -> None:
        self._auth_context.refresh_token = value

    @property
    def _access_jwt(self) -> str:
        return self._auth_context.access_jwt

    @_access_jwt.setter
    def _access_jwt(self, value: str) -> None:
        self._auth_context.access_jwt = value

    @property
    def _access_jwt_exp(self) -> float:
        return self._auth_context.access_jwt_exp

    @_access_jwt_exp.setter
    def _access_jwt_exp(self, value: float) -> None:
        self._auth_context.access_jwt_exp = value

    @property
    def _last_auth_info(self) -> dict[str, Any]:
        return self._auth_context.last_auth_info

    @_last_auth_info.setter
    def _last_auth_info(self, value: dict[str, Any]) -> None:
        self._auth_context.last_auth_info = value

    # ── HTTP plumbing ────────────────────────────────────────────────────────

    @staticmethod
    def _make_client() -> requests.Session:
        s = requests.Session()
        adapter = HTTPAdapter(max_retries=0, pool_connections=4, pool_maxsize=4)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
        return s

    def _auth_headers(self) -> dict:
        with self._auth_lock:
            headers: dict = {"User-Agent": CLIENT_USER_AGENT}
            if self._access_jwt:
                headers["Authorization"] = f"Bearer {self._access_jwt}"
            if self._device_fingerprint:
                headers["X-Decompile-Fingerprint"] = self._device_fingerprint
            return headers

    def _request(self, method: str, url: str, **kwargs):
        with self._http_lock:
            return getattr(self._http, method.lower())(url, **kwargs)

    def close(self) -> None:
        """Release HTTP connection pools owned by this session."""
        self._poll_http.close()
        with self._http_lock:
            self._http.close()

    @staticmethod
    def _check_authenticated_response(resp, action: str) -> None:
        if resp.status_code not in (401, 403):
            return
        payload = {}
        try:
            payload = resp.json()
        except Exception:
            pass
        if not isinstance(payload, dict):
            payload = {}
        reason = str(payload.get("reason", "") or "")
        error = str(payload.get("error", "") or "")
        if reason == "account_banned":
            raise SessionStartError(
                error or "This account has been suspended.",
                reason="account_banned",
            )
        message = error or f"{action} rejected: HTTP {resp.status_code}"
        if reason:
            message = f"{message} (reason={reason})"
        raise AuthError(
            message,
            rejected=True,
            reason=reason,
        )

    # ── Refresh-token exchange ───────────────────────────────────────────────

    def _ensure_access_jwt(self) -> None:
        with self._auth_lock:
            self._ensure_access_jwt_locked()

    def _ensure_access_jwt_locked(self) -> None:
        """Ensure a fresh access JWT is cached. Re-exchanges as needed.

        Raises AuthError on 401/403 from the server (caller asks the user to
        sign in again).

        When no refresh token is configured, this is a no-op. This preserves
        anonymous local/self-hosted use while allowing a local API configured
        with authentication to verify and revoke a saved credential normally.
        """
        if not self._refresh_token:
            return  # local/self-hosted mode — no token needed

        # A loopback companion server can explicitly advertise that it runs in
        # memory-only, unauthenticated mode. Cache that capability so a saved
        # production refresh token is neither exchanged nor overwritten while
        # the local reconstruction backend is selected.
        if is_loopback_server_url(self.server_url):
            if self._auth_context.auth_required is None:
                self._auth_context.auth_required = self._discover_auth_requirement()
            if not self._auth_context.auth_required:
                return

        now = time.time()
        if self._access_jwt and now < (self._access_jwt_exp - _ACCESS_JWT_REFRESH_LEEWAY_S):
            return

        rotation_request_id = device_identity.refresh_rotation_request_id(
            self.server_url,
            self._refresh_token,
        )
        body = {
            "refresh_token":      self._refresh_token,
            "rotation_request_id": rotation_request_id,
            "device_fingerprint": self._device_fingerprint,
            "hostname":           platform.node() or "",
        }
        body.update(device_identity.refresh_exchange_proof(
            self.server_url,
            self._refresh_token,
            rotation_request_id,
        ))
        try:
            resp = self._request(
                "POST",
                f"{self.server_url}/auth/refresh/exchange",
                json=body,
                timeout=15,
                headers={"User-Agent": CLIENT_USER_AGENT},
                allow_redirects=False,
            )
        except requests.exceptions.RequestException as e:
            raise AuthError(f"Refresh exchange failed: network error: {e}") from e

        if resp.status_code in (401, 403):
            reason = ""
            try:
                reason = resp.json().get("reason", "") or ""
            except Exception:
                pass
            msg = "Refresh token rejected"
            if reason:
                msg = f"{msg} (reason={reason})"
            raise AuthError(msg, rejected=True, reason=reason)

        if resp.status_code != 200:
            raise AuthError(f"Refresh exchange failed: HTTP {resp.status_code}")

        try:
            data = resp.json()
        except ValueError as e:
            raise AuthError(f"Refresh exchange returned non-JSON body: {e}") from e
        if not isinstance(data, dict):
            raise AuthError("Refresh exchange returned an invalid response object")

        new_jwt = data.get("access_jwt", "") or ""
        new_refresh = data.get("refresh_token_new", "") or ""
        exp_at = data.get("expires_at", "")

        if not new_jwt or not new_refresh:
            raise AuthError("Refresh exchange response missing fields")

        # Persist the rotated refresh token before updating in-memory state.
        # Refresh tokens must only be stored in the OS credential store.
        try:
            if self._account_id:
                secret_store.save_refresh_token(new_refresh, self._account_id, self.server_url)
            else:
                secret_store.save_refresh_token(new_refresh, server_url=self.server_url)
        except secret_store.CredentialStoreUnavailable as e:
            raise AuthError(str(e)) from e
        self._refresh_token = new_refresh
        self._access_jwt = new_jwt
        self._access_jwt_exp = self._parse_expiry(exp_at)
        self._last_auth_info = {
            "user_id": data.get("user_id", "") or "",
            "email": data.get("email", "") or "",
            "tier": data.get("tier", "") or "",
        }

    def _discover_auth_requirement(self) -> bool:
        """Return False only for an explicit capability from a loopback server."""
        try:
            resp = self._request(
                "GET",
                f"{self.server_url}/health",
                timeout=(2, 5),
                headers={"User-Agent": CLIENT_USER_AGENT},
                allow_redirects=False,
            )
            if resp.status_code == 200:
                payload = resp.json()
                if isinstance(payload, dict):
                    return payload.get("auth_required") is not False
                return True
        except (requests.exceptions.RequestException, ValueError):
            pass
        return True

    @staticmethod
    def _parse_expiry(exp_at: str) -> float:
        """Parse an ISO-8601 expires_at into unix seconds.

        Falls back to "5 minutes from now" if the server omits it or sends
        an unparseable value (defence in depth; the server always sends one
        in v1 but we don't want to crash if format ever changes).
        """
        if exp_at:
            try:
                s = exp_at.replace("Z", "+00:00")
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.timestamp()
            except ValueError:
                pass
        return time.time() + 5 * 60

    # ── Session lifecycle ────────────────────────────────────────────────────

    def start(
        self,
        root_ea: int,
        user_prompt: str,
        model_tier: str,
        auto_renames: bool,
        auto_types: bool,
        auto_structs: bool,
        rename_style: str,
        struct_member_style: str,
        skip_reversing: bool,
        max_call_depth: int,
        decompiler: str = "ida",
    ) -> str:
        """Start a new analysis session. Returns the session ID.

        Raises AuthError on 401/403 and BillingError on 402.
        """
        self._ensure_access_jwt()
        body = {
            "root_ea":              hex(root_ea),
            "user_prompt":          user_prompt,
            "model_tier":           model_tier,
            "auto_renames":         auto_renames,
            "auto_types":           auto_types,
            "auto_structs":         auto_structs,
            "rename_style":         rename_style,
            "struct_member_style":  struct_member_style,
            "skip_reversing":       skip_reversing,
            "max_call_depth":       max_call_depth,
            "decompiler":           decompiler,
            "protocol_version":     1,
        }
        resp = self._request(
            "POST",
            f"{self.server_url}/session",
            json=body,
            timeout=15,
            headers=self._auth_headers(),
            allow_redirects=False,
        )

        self._check_authenticated_response(resp, "Session start")

        if resp.status_code == 402:
            reason = ""
            error_msg = "Payment required"
            try:
                payload = resp.json()
                reason = payload.get("reason", "") or ""
                error_msg = payload.get("error", error_msg) or error_msg
            except Exception:
                pass
            raise BillingError(error_msg, reason=reason)

        if resp.status_code == 503:
            payload = {}
            try:
                payload = resp.json()
            except Exception:
                pass
            if not isinstance(payload, dict):
                payload = {}
            raise SessionStartError(
                payload.get("error") or "The service is temporarily unavailable.",
                reason=payload.get("reason", "service_unavailable"),
            )

        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ServerProtocolError(
                "Session start returned invalid JSON."
            ) from exc
        if not isinstance(payload, dict):
            raise ServerProtocolError(
                "Session start returned an invalid response object."
            )
        try:
            session_id = _require_protocol_id(
                payload.get("session_id"),
                "session ID",
            )
        except ServerProtocolError as exc:
            raise ServerProtocolError(
                "Session start response did not include a valid session ID."
            ) from exc
        self.session_id = session_id
        self._last_sequence = 0
        return self.session_id

    def resume(self) -> bool:
        """Ask the server to recover this session from its durable checkpoint."""
        if not self.session_id:
            return False
        session_id = _require_protocol_id(self.session_id, "session ID")
        self._ensure_access_jwt()
        resp = self._request(
            "POST",
            f"{self.server_url}/session/{session_id}/resume",
            timeout=(5, 20),
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Session resume")
        if resp.status_code == 409:
            return False
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ServerProtocolError(
                "Session resume returned invalid JSON."
            ) from exc
        if not isinstance(payload, dict) or not isinstance(
            payload.get("resumed"), bool
        ):
            raise ServerProtocolError(
                "Session resume returned an invalid response object."
            )
        resumed = payload["resumed"]
        if resumed:
            self._last_sequence = 0
        return resumed

    def commit_sequence(self, sequence: int) -> None:
        if sequence > self._last_sequence:
            self._last_sequence = sequence

    def next_command(self) -> list[dict]:
        """Poll the server for the next batch of IDA commands.

        The server returns a JSON array. Fire-and-forget notifications are
        batched so multiple tree/log updates arrive in one round-trip.
        A batch may contain multiple commands that need results. The worker
        executes IDA operations serially on IDA's main thread and submits
        their results together.
        """
        session_id = _require_protocol_id(self.session_id, "session ID")
        self._ensure_access_jwt()
        resp = self._poll_http.get(
            f"{self.server_url}/session/{session_id}/next",
            params={"after": self._last_sequence},
            timeout=(5, 20),
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Session poll")
        resp.raise_for_status()
        try:
            data = resp.json()
        except ValueError as exc:
            raise ServerProtocolError(
                "Session poll returned invalid JSON."
            ) from exc
        # Normalise: server always returns a list, but guard against old servers.
        if isinstance(data, dict):
            data = [data]
        if not isinstance(data, list) or any(
            not isinstance(command, dict) for command in data
        ):
            raise ServerProtocolError(
                "Session poll returned an invalid command batch."
            )
        for command in data:
            command_type = command.get("type")
            if not isinstance(command_type, str) or not command_type:
                raise ServerProtocolError(
                    "Session poll returned a command without a valid type."
                )
            if "needs_result" in command and not isinstance(
                command["needs_result"], bool
            ):
                raise ServerProtocolError(
                    "Session poll returned an invalid needs_result flag."
                )
            command_id = command.get("id")
            if command.get("needs_result") is True:
                _require_protocol_id(command_id, "command ID")
            elif command_id not in (None, ""):
                _require_protocol_id(command_id, "command ID")
        return data

    def post_result(self, command_id: str, result: dict) -> str:
        """Send the result of a command back to the server."""
        session_id = _require_protocol_id(self.session_id, "session ID")
        command_id = _require_protocol_id(command_id, "command ID")
        self._ensure_access_jwt()
        result = dict(result)
        resp = self._request(
            "POST",
            f"{self.server_url}/session/{session_id}/commands/{command_id}/result",
            json=result,
            timeout=(5, 30),
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Result post")
        if resp.status_code in (404, 409):
            try:
                status = resp.json().get("status")
                if status in ("unknown", "pending"):
                    return status
            except (AttributeError, TypeError, ValueError):
                pass
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ServerProtocolError(
                "Result acknowledgement returned an invalid response object."
            )
        status = payload.get("status", "")
        if status not in ("accepted", "duplicate"):
            raise RuntimeError(
                f"Unexpected result acknowledgement: {status or 'missing'}"
            )
        return status

    def post_results(self, results: list[tuple[str, dict]]) -> dict[str, str]:
        """Submit several command results in one idempotent HTTP request."""
        session_id = _require_protocol_id(self.session_id, "session ID")
        if not results:
            return {}
        if len(results) > 64:
            raise ValueError("A result batch cannot contain more than 64 commands.")

        payload_results = []
        expected_ids = set()
        for command_id, result in results:
            command_id = _require_protocol_id(command_id, "command ID")
            if command_id in expected_ids:
                raise ValueError("A result batch cannot contain duplicate command IDs.")
            if not isinstance(result, dict):
                raise TypeError("Command result must be an object.")
            expected_ids.add(command_id)
            payload_results.append({
                "command_id": command_id,
                "result": dict(result),
            })

        self._ensure_access_jwt()
        resp = self._request(
            "POST",
            f"{self.server_url}/session/{session_id}/commands/results",
            json={"results": payload_results},
            timeout=(5, 30),
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Result batch post")
        resp.raise_for_status()
        try:
            payload = resp.json()
        except ValueError as exc:
            raise ServerProtocolError(
                "Result batch acknowledgement returned invalid JSON."
            ) from exc
        acknowledgements = payload.get("results") if isinstance(payload, dict) else None
        if not isinstance(acknowledgements, list):
            raise ServerProtocolError(
                "Result batch acknowledgement returned an invalid response object."
            )

        statuses: dict[str, str] = {}
        for acknowledgement in acknowledgements:
            if not isinstance(acknowledgement, dict):
                raise ServerProtocolError(
                    "Result batch acknowledgement contained an invalid item."
                )
            command_id = _require_protocol_id(
                acknowledgement.get("command_id"), "command ID"
            )
            status = acknowledgement.get("status")
            if command_id not in expected_ids or command_id in statuses:
                raise ServerProtocolError(
                    "Result batch acknowledgement contained an unexpected command ID."
                )
            if status not in ("accepted", "duplicate", "pending", "unknown"):
                raise ServerProtocolError(
                    "Result batch acknowledgement contained an invalid status."
                )
            statuses[command_id] = status
        if set(statuses) != expected_ids:
            raise ServerProtocolError(
                "Result batch acknowledgement omitted one or more commands."
            )
        return statuses

    def send_chat(self, message: str) -> None:
        """Send a follow-up chat message to an active (post-analysis) session.

        The server queues the message and delivers the response asynchronously
        as a 'chat_response' command via the normal GET /next poll.

        Raises AuthError on 401/403. Raises RuntimeError on other failures.
        """
        if not self.session_id:
            return
        session_id = _require_protocol_id(self.session_id, "session ID")
        self._ensure_access_jwt()
        try:
            resp = self._request(
                "POST",
                f"{self.server_url}/session/{session_id}/chat",
                json={"message": message},
                timeout=10,
                headers=self._auth_headers(),
                allow_redirects=False,
            )
        except Exception as e:
            raise RuntimeError(f"Chat send failed: network error: {e}") from e

        self._check_authenticated_response(resp, "Chat")
        if resp.status_code == 409:
            raise RuntimeError("Analysis not yet complete — chat is not available yet.")
        if resp.status_code not in (200, 202):
            try:
                err = resp.json().get("error", "")
            except (AttributeError, TypeError, ValueError):
                err = ""
            raise RuntimeError(f"Chat send failed: HTTP {resp.status_code} {err}")

    def cancel(self) -> None:
        """Cancel the session. Swallows transport errors -- best-effort."""
        if not self.session_id:
            return
        try:
            session_id = _require_protocol_id(self.session_id, "session ID")
            self._ensure_access_jwt()
            self._request(
                "DELETE",
                f"{self.server_url}/session/{session_id}",
                timeout=5,
                headers=self._auth_headers(),
                allow_redirects=False,
            )
        except Exception:
            pass
        finally:
            self.session_id = None

    def delete_history(self) -> None:
        """Permanently delete a completed analysis session."""
        if not self.session_id:
            return
        session_id = _require_protocol_id(self.session_id, "session ID")
        self._ensure_access_jwt()
        resp = self._request(
            "DELETE",
            f"{self.server_url}/session/{session_id}/history",
            timeout=10,
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Session deletion")
        if resp.status_code == 409:
            try:
                message = resp.json().get("error", "")
            except (AttributeError, TypeError, ValueError):
                message = ""
            raise RuntimeError(message or "Running sessions cannot be deleted.")
        resp.raise_for_status()
        self.session_id = None

    def rename_history(self, name: str) -> str:
        """Rename an account-owned persisted analysis session."""
        if not self.session_id:
            raise RuntimeError("Session is not available yet.")
        session_id = _require_protocol_id(self.session_id, "session ID")
        name = name.strip()
        if not name:
            raise ValueError("Session name must not be empty.")
        if len(name.encode("utf-8")) > 256:
            raise ValueError("Session name must not exceed 256 bytes.")

        self._ensure_access_jwt()
        resp = self._request(
            "PUT",
            f"{self.server_url}/session/{session_id}/name",
            timeout=10,
            headers=self._auth_headers(),
            json={"name": name},
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Session rename")
        resp.raise_for_status()
        try:
            renamed = str(resp.json().get("name", "") or "").strip()
        except (AttributeError, TypeError, ValueError):
            renamed = ""
        return renamed or name

    def list_history(self) -> list[dict]:
        """List persisted analysis session names and IDs for this account."""
        self._ensure_access_jwt()
        resp = self._request(
            "GET",
            f"{self.server_url}/session/history",
            timeout=15,
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Session history")
        resp.raise_for_status()
        payload = resp.json()
        if not isinstance(payload, dict):
            raise ServerProtocolError(
                "Session history returned an invalid response object."
            )
        sessions = payload.get("sessions", [])
        return sessions if isinstance(sessions, list) else []

    def get_usage_percent(self) -> float:
        """Return the account's current monthly usage percentage."""
        self._ensure_access_jwt()
        resp = self._request(
            "GET",
            f"{self.server_url}/account/usage",
            timeout=10,
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Usage")
        resp.raise_for_status()
        try:
            payload = resp.json()
            value = float(
                payload.get("usage_percent", 0) if isinstance(payload, dict) else 0
            )
        except (TypeError, ValueError):
            value = 0
        return max(0.0, min(100.0, value))

    def get_history(self, session_id: str) -> dict:
        """Load one account-owned persisted session for display."""
        session_id = _require_protocol_id(session_id, "session ID")
        self._ensure_access_jwt()
        resp = self._request(
            "GET",
            f"{self.server_url}/session/{session_id}/history",
            timeout=30,
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        self._check_authenticated_response(resp, "Session history")
        resp.raise_for_status()
        payload = resp.json()
        return payload if isinstance(payload, dict) else {}

    # ── Wizard helpers ───────────────────────────────────────────────────────

    def get_me_settings(self) -> dict:
        """GET /me/settings. Used by the wizard's verify page.

        Note: /me/* endpoints require RequireDashboardAuth (a Supabase JWT),
        NOT the IDA-client access JWT. We send the access JWT anyway because
        a server gateway may be configured to translate; the v1 plan calls
        this out and a follow-up may add a dedicated /me-shaped endpoint
        usable with the client JWT. For now we read what we can; the wizard
        falls back to a happier "connected" message if the call 401s.
        """
        self._ensure_access_jwt()
        resp = self._request(
            "GET",
            f"{self.server_url}/me/settings",
            timeout=10,
            headers=self._auth_headers(),
            allow_redirects=False,
        )
        resp.raise_for_status()
        return resp.json()

    def test_connection(self) -> dict[str, Any]:
        """Do a full refresh-exchange + best-effort /me/settings read.

        Returns:
          {ok: bool, email?: str, tier?: str, error?: str}
        """
        try:
            self._ensure_access_jwt()
        except AuthError as e:
            return {"ok": False, "error": str(e)}
        except Exception as e:
            return {"ok": False, "error": f"Connect failed: {e}"}

        out: dict[str, Any] = {"ok": True}
        try:
            settings = self.get_me_settings()
            email = settings.get("email", "")
            tier = settings.get("tier") or settings.get("default_model_tier", "")
            if email:
                out["email"] = email
            if tier:
                out["tier"] = tier
        except requests.exceptions.HTTPError as e:
            # Refresh exchange succeeded -> auth works end-to-end.
            # /me/settings may require a dashboard JWT in v1; not a failure.
            if e.response is not None and e.response.status_code in (401, 403):
                pass
            else:
                out["ok"] = False
                out["error"] = f"/me/settings: {e}"
        except Exception as e:
            out["ok"] = False
            out["error"] = f"/me/settings: {e}"
        return out

    def verify_auth(self) -> dict[str, Any]:
        """Verify the saved refresh token by performing the normal exchange."""
        self._ensure_access_jwt()
        with self._auth_lock:
            return dict(self._last_auth_info)
