"""
config.py — Client-side constants and capability detection.
The LLM backend and analysis settings live on the server (.config).
"""

import os
from urllib.parse import urlparse

PLUGIN_NAME    = "Decompile.re"
PLUGIN_VERSION = "1.1.0"
PLUGIN_HOTKEY  = "Ctrl-Shift-A"
CLIENT_USER_AGENT = f"decompile-re-ida/{PLUGIN_VERSION}"

PRODUCTION_API_URL = "https://api.decompile.re"
PRODUCTION_DASHBOARD_URL = "https://decompile.re"
SETUP_WIZARD_RELEASE_URL = (
    "https://github.com/GraniteLabsLLC/"
    "Decompile.re-Setup-Wizard/releases/latest"
)
LOCAL_API_URL = "http://127.0.0.1:8080"
LOCAL_DASHBOARD_URL = "http://127.0.0.1:3000"

# Release builds always default to production. Local IDA launches can opt in
# explicitly without editing distributable source files.
LOCAL_DEVELOPMENT = os.environ.get(
    "DECOMPILE_RE_LOCAL_DEVELOPMENT", ""
).strip().lower() in {"1", "true", "yes", "on"}
ACTIVE_API_URL = LOCAL_API_URL if LOCAL_DEVELOPMENT else PRODUCTION_API_URL
ACTIVE_DASHBOARD_URL = (
    LOCAL_DASHBOARD_URL if LOCAL_DEVELOPMENT else PRODUCTION_DASHBOARD_URL
)


def is_loopback_server_url(url: str) -> bool:
    """Whether a configured API URL resolves only to this machine."""
    try:
        return urlparse(url).hostname in {"127.0.0.1", "::1"}
    except ValueError:
        return False


def validate_server_url(url: str) -> str:
    """Return a normalized API origin or raise for an unsafe credential target."""
    try:
        parsed = urlparse(str(url or "").strip())
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid Decompile API URL") from exc
    host = (parsed.hostname or "").lower()
    is_loopback = host in {"127.0.0.1", "::1"}
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Decompile API URL must not include credentials, query, or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("Decompile API URL must be an origin without a path")
    if parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback):
        raise ValueError("Decompile API must use HTTPS unless it is a loopback development server")
    if not host:
        raise ValueError("Invalid Decompile API URL")
    return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")

# ── Capability flags ─────────────────────────────────────────────────────────

try:
    import ida_hexrays
    # IDA 9.x: init_hexrays_plugin() was removed; the decompiler initialises
    # automatically when the plugin is loaded.  IDA 8.x still has it, so call
    # it only when present to stay forward-compatible.
    if hasattr(ida_hexrays, 'init_hexrays_plugin'):
        ida_hexrays.init_hexrays_plugin()
    HEXRAYS_AVAILABLE = True
except Exception:
    HEXRAYS_AVAILABLE = False

try:
    import requests          # noqa: F401
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from .compat.qt import (  # noqa: F401
    QT_AVAILABLE,
    Qt,
    QtCore,
    QtGui,
    QtWidgets,
    QThread,
    Signal,
)

try:
    import keyring          # noqa: F401
    KEYRING_AVAILABLE = True
except ImportError:
    KEYRING_AVAILABLE = False

# ── Settings persistence path ────────────────────────────────────────────────

def _settings_dir() -> str:
    appdata = os.environ.get("APPDATA") or os.environ.get("XDG_CONFIG_HOME")
    if appdata:
        folder = os.path.join(appdata, "IDA Pro", "ida_ai_client")
    else:
        folder = os.path.join(os.path.expanduser("~"), ".config", "ida_ai_client")
    os.makedirs(folder, exist_ok=True)
    return folder

SETTINGS_DIR = _settings_dir()
SETTINGS_FILE = os.path.join(SETTINGS_DIR, "decompile_re_settings.json")

# ── Default client settings ──────────────────────────────────────────────────

DEFAULT_SETTINGS: dict = {
    "server_url":           ACTIVE_API_URL,
    "auto_renames":         True,
    "auto_types":           True,
    "auto_structs":         True,
    "rename_style":         "snake_case",
    "struct_member_style":  "default",
    "max_call_depth":       0,
    # Auth + user preferences. The refresh token is stored only in the OS
    # credential store via secret_store.py, never in this JSON settings file.
    "user_email":           "",
    "user_name":            "",
    "user_avatar_url":      "",
    "auth_verified":        False,
    "active_account_id":    "",
    "accounts":             {},
    "model_tier":           "fast",
    "device_id":            "",
    # UI colour theme — one of styles.PALETTES (see ui/styles.py).
    "theme":                "Nord",
}

g_settings: dict = dict(DEFAULT_SETTINGS)
