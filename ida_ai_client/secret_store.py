"""
secret_store.py - Refresh-token persistence using the OS credential store.

The refresh token is the long-lived credential used only for
POST /auth/refresh/exchange. It must never be logged or written to the JSON
settings file. Persistence is handled by the `keyring` package, which maps to
Windows Credential Manager, macOS Keychain, or Linux Secret Service/KWallet.
"""

from __future__ import annotations

import hashlib

from .config import (
    KEYRING_AVAILABLE,
    PRODUCTION_API_URL,
    g_settings,
    validate_server_url,
)
from .settings import save_settings

try:
    import keyring  # type: ignore
except ImportError:
    keyring = None  # type: ignore

_SERVICE = "decompile-ida-client"
_LEGACY_USER = "refresh_token"
_USER_PREFIX = "refresh_token:"
_DEVICE_KEY_PREFIX = "device_key:"


class CredentialStoreUnavailable(RuntimeError):
    """Raised when the OS credential store cannot persist the refresh token."""


def _backend_is_secure(backend) -> bool:
    module = type(backend).__module__
    if module.startswith("keyrings.alt") or module in {
        "keyring.backends.fail",
        "keyring.backends.null",
    }:
        return False
    children = getattr(backend, "backends", None)
    if children:
        return bool(children) and all(_backend_is_secure(child) for child in children)
    return module.startswith(
        (
            "keyring.backends.Windows",
            "keyring.backends.macOS",
            "keyring.backends.SecretService",
            "keyring.backends.libsecret",
            "keyring.backends.kwallet",
        )
    )


def _keyring_usable() -> bool:
    if not (KEYRING_AVAILABLE and keyring is not None):
        return False
    get_backend = getattr(keyring, "get_keyring", None)
    if get_backend is None:
        return True  # Test doubles provide only the credential operations.
    try:
        return _backend_is_secure(get_backend())
    except Exception:
        return False


def _clear_legacy_json_token() -> None:
    if g_settings.pop("refresh_token", None):
        save_settings()


def _account_id(account_id: str | None = None) -> str:
    account_id = (account_id or str(g_settings.get("active_account_id", "") or "")).strip()
    return account_id or "default"


def _server_origin(server_url: str | None = None) -> str:
    value = server_url or str(g_settings.get("server_url", "") or "") or PRODUCTION_API_URL
    return validate_server_url(value)


def _origin_id(server_url: str | None = None) -> str:
    origin = _server_origin(server_url).lower()
    return hashlib.sha256(origin.encode("utf-8")).hexdigest()[:16]


def _keyring_user(account_id: str | None = None, server_url: str | None = None) -> str:
    return f"{_USER_PREFIX}{_origin_id(server_url)}:{_account_id(account_id)}"


def _legacy_account_user(account_id: str | None = None) -> str:
    return _USER_PREFIX + _account_id(account_id)


def _device_key_user(server_url: str | None = None) -> str:
    return _DEVICE_KEY_PREFIX + _origin_id(server_url)


def load_refresh_token(account_id: str | None = None, server_url: str | None = None) -> str:
    """Return the OS-stored refresh token, or "" if none is available."""
    _clear_legacy_json_token()
    if _keyring_usable():
        try:
            tok = keyring.get_password(_SERVICE, _keyring_user(account_id, server_url))
            if tok:
                return tok
            # Existing installs used an account-only key. Migrate it only for
            # the production issuer; never import a production token into a
            # local or self-hosted credential namespace.
            if _server_origin(server_url) == PRODUCTION_API_URL:
                legacy = keyring.get_password(_SERVICE, _legacy_account_user(account_id))
                if not legacy and _account_id(account_id) == "default":
                    legacy = keyring.get_password(_SERVICE, _LEGACY_USER)
                if legacy:
                    keyring.set_password(_SERVICE, _keyring_user(account_id, server_url), legacy)
                    try:
                        keyring.delete_password(_SERVICE, _legacy_account_user(account_id))
                        if _account_id(account_id) == "default":
                            keyring.delete_password(_SERVICE, _LEGACY_USER)
                    except Exception:
                        pass
                    return legacy
        except Exception:
            pass
    return ""


def save_refresh_token(
    token: str,
    account_id: str | None = None,
    server_url: str | None = None,
) -> None:
    """Persist a refresh token in the OS credential store."""
    _clear_legacy_json_token()
    if not token:
        clear_refresh_token(account_id, server_url)
        return
    if not _keyring_usable():
        raise CredentialStoreUnavailable(
            "Secure credential storage is unavailable in this IDA Python environment. "
            "Install 'keyring' with a native OS credential backend for IDA's Python, then sign in again."
        )
    try:
        keyring.set_password(_SERVICE, _keyring_user(account_id, server_url), token)
    except Exception as e:
        raise CredentialStoreUnavailable(
            "Secure credential storage rejected the sign-in token. "
            "Check that your OS keychain/credential manager is available, then sign in again."
        ) from e


def clear_refresh_token(account_id: str | None = None, server_url: str | None = None) -> None:
    """Remove the refresh token from the OS credential store and old JSON copies."""
    if _keyring_usable():
        try:
            keyring.delete_password(_SERVICE, _keyring_user(account_id, server_url))
        except Exception:
            pass
        if _server_origin(server_url) == PRODUCTION_API_URL:
            try:
                keyring.delete_password(_SERVICE, _legacy_account_user(account_id))
            except Exception:
                pass
            if _account_id(account_id) == "default":
                try:
                    keyring.delete_password(_SERVICE, _LEGACY_USER)
                except Exception:
                    pass
    _clear_legacy_json_token()


def load_device_private_key(server_url: str | None = None) -> str:
    if not _keyring_usable():
        return ""
    try:
        return keyring.get_password(_SERVICE, _device_key_user(server_url)) or ""
    except Exception:
        return ""


def save_device_private_key(value: str, server_url: str | None = None) -> None:
    if not value:
        raise ValueError("device private key must not be empty")
    if not _keyring_usable():
        raise CredentialStoreUnavailable(
            "Secure device identity storage is unavailable. Install 'keyring' with a native OS backend."
        )
    try:
        keyring.set_password(_SERVICE, _device_key_user(server_url), value)
    except Exception as e:
        raise CredentialStoreUnavailable(
            "The OS credential store rejected the device identity key."
        ) from e
