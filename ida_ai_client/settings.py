"""
settings.py — Load and save client settings to/from JSON.
"""

import json
import os
import tempfile

from .config import (
    ACTIVE_API_URL,
    DEFAULT_SETTINGS,
    SETTINGS_FILE,
    g_settings,
)

_MODEL_TIERS = {"fast", "dynamic", "smart"}
_RENAME_STYLES = {"snake_case", "camelCase", "PascalCase"}
_STRUCT_MEMBER_STYLES = {"default", "m_prefix", "typed_m_prefix"}
_SECRET_KEYS = {"refresh_token"}


def _validated_settings(saved: object) -> dict:
    """Return supported, type-safe values from an untrusted settings file."""
    if not isinstance(saved, dict):
        return {}

    validated: dict = {}
    for key, default in DEFAULT_SETTINGS.items():
        if key in _SECRET_KEYS or key not in saved:
            continue
        value = saved[key]
        if isinstance(default, bool):
            if isinstance(value, bool):
                validated[key] = value
        elif isinstance(default, int):
            if isinstance(value, int) and not isinstance(value, bool):
                validated[key] = value
        elif isinstance(default, str):
            if isinstance(value, str):
                validated[key] = value
        elif isinstance(default, dict):
            if isinstance(value, dict):
                validated[key] = value

    if validated.get("model_tier", DEFAULT_SETTINGS["model_tier"]) not in _MODEL_TIERS:
        validated["model_tier"] = DEFAULT_SETTINGS["model_tier"]
    if validated.get("rename_style", DEFAULT_SETTINGS["rename_style"]) not in _RENAME_STYLES:
        validated["rename_style"] = DEFAULT_SETTINGS["rename_style"]
    if (
        validated.get("struct_member_style", DEFAULT_SETTINGS["struct_member_style"])
        not in _STRUCT_MEMBER_STYLES
    ):
        validated["struct_member_style"] = DEFAULT_SETTINGS["struct_member_style"]

    validated["max_call_depth"] = max(
        0,
        min(10, validated.get("max_call_depth", DEFAULT_SETTINGS["max_call_depth"])),
    )
    return validated


def load_settings() -> None:
    """Merge saved settings into g_settings, then apply the chosen UI theme."""
    g_settings.clear()
    g_settings.update(DEFAULT_SETTINGS)
    rewrite = False
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            saved = json.load(f)
        validated = _validated_settings(saved)
        g_settings.update(validated)
        rewrite = not isinstance(saved, dict) or any(
            key in _SECRET_KEYS or key not in DEFAULT_SETTINGS
            for key in saved
        )
        rewrite = rewrite or (
            isinstance(saved, dict)
            and any(saved.get(key) != value for key, value in validated.items())
        )
    except (FileNotFoundError, json.JSONDecodeError, OSError, TypeError):
        pass

    # The selected build mode owns the credential endpoint. This prevents a
    # stale development setting from redirecting a public build to localhost.
    if g_settings.get("server_url") != ACTIVE_API_URL:
        rewrite = True
    g_settings["server_url"] = ACTIVE_API_URL

    if rewrite:
        save_settings()

    # Apply the selected colour theme so dialogs open already themed.
    try:
        from .ui.styles import apply_theme
        if not apply_theme(g_settings.get("theme", "Nord")):
            g_settings["theme"] = DEFAULT_SETTINGS["theme"]
            save_settings()
    except Exception:
        pass


def save_settings() -> None:
    """Atomically persist non-secret settings to disk."""
    folder = os.path.dirname(SETTINGS_FILE) or "."
    temp_path = ""
    try:
        os.makedirs(folder, exist_ok=True)
        persisted = {
            key: value
            for key, value in _validated_settings(g_settings).items()
            if key not in _SECRET_KEYS
        }
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=folder,
            prefix=".decompile_re_settings.",
            suffix=".tmp",
            delete=False,
        ) as temp_file:
            temp_path = temp_file.name
            json.dump(persisted, temp_file, indent=2)
            temp_file.write("\n")
            temp_file.flush()
            os.fsync(temp_file.fileno())
        os.replace(temp_path, SETTINGS_FILE)
    except (OSError, TypeError, ValueError) as e:
        print(f"[IDA AI Client] Could not save settings: {e}")
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except FileNotFoundError:
                pass
            except OSError:
                pass
