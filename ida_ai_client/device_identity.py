"""Per-install device identity used to sender-constrain refresh credentials."""

from __future__ import annotations

import base64
import hashlib
import secrets
import time

from . import secret_store

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover - depends on the embedded IDA Python
    Ed25519PrivateKey = None  # type: ignore[assignment]
    serialization = None  # type: ignore[assignment]


class DeviceIdentityUnavailable(RuntimeError):
    pass


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _private_key(server_url: str):
    if Ed25519PrivateKey is None or serialization is None:
        raise DeviceIdentityUnavailable(
            "Secure device identity support is unavailable. Install the 'cryptography' package for IDA's Python."
        )
    encoded = secret_store.load_device_private_key(server_url)
    if encoded:
        try:
            return Ed25519PrivateKey.from_private_bytes(_b64decode(encoded))
        except Exception as exc:
            raise DeviceIdentityUnavailable("Stored device identity key is invalid.") from exc

    private_key = Ed25519PrivateKey.generate()
    raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    secret_store.save_device_private_key(_b64encode(raw), server_url)
    return private_key


def public_key(server_url: str) -> str:
    key = _private_key(server_url)
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _b64encode(raw)


def _proof(server_url: str, purpose: str, fields: list[str]) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    message = "\n".join([purpose, *fields, timestamp, nonce]).encode("utf-8")
    signature = _private_key(server_url).sign(message)
    return {
        "device_public_key": public_key(server_url),
        "device_proof_timestamp": timestamp,
        "device_proof_nonce": nonce,
        "device_proof": _b64encode(signature),
    }


def code_exchange_proof(
    server_url: str,
    auth_code: str,
    state: str,
    code_verifier: str,
) -> dict[str, str]:
    return _proof(
        server_url,
        "decompile-code-exchange-v1",
        [auth_code, state, code_verifier],
    )


def refresh_rotation_request_id(server_url: str, refresh_token: str) -> str:
    material = "\n".join([
        "decompile-refresh-rotation-request-v1",
        refresh_token,
        public_key(server_url),
    ]).encode("utf-8")
    return _b64encode(hashlib.sha256(material).digest())


def refresh_exchange_proof(
    server_url: str,
    refresh_token: str,
    rotation_request_id: str,
) -> dict[str, str]:
    return _proof(
        server_url,
        "decompile-refresh-exchange-v1",
        [refresh_token, rotation_request_id],
    )
