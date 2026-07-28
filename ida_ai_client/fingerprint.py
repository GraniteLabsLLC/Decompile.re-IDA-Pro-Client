"""Device identity presented with client access credentials."""

from __future__ import annotations

from . import device_identity
from .config import g_settings


def device_fingerprint() -> str:
    """Return the per-install public key for the active API origin."""
    server_url = str(g_settings.get("server_url", "https://api.decompile.re") or "")
    return device_identity.public_key(server_url)
