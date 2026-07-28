"""
auth_state.py - Saved account profile and startup verification.
"""

from __future__ import annotations

from .config import g_settings
from .settings import save_settings
from . import secret_store
from . import fingerprint


def _accounts() -> dict:
    accounts = g_settings.get("accounts")
    if not isinstance(accounts, dict):
        accounts = {}
        g_settings["accounts"] = accounts
    return accounts


def account_id_for_data(data: dict, fallback: str = "") -> str:
    for key in ("user_id", "account_id", "id", "sub", "email"):
        value = str(data.get(key, "") or "").strip()
        if value:
            return value
    return fallback.strip() or "default"


def active_account_id() -> str:
    active = str(g_settings.get("active_account_id", "") or "").strip()
    if active:
        return active
    accounts = _accounts()
    if accounts:
        active = sorted(accounts.keys())[0]
        g_settings["active_account_id"] = active
        _sync_legacy_profile(accounts.get(active, {}))
        save_settings()
        return active
    return ""


def display_name() -> str:
    return profile().get("name", "")


def profile() -> dict:
    account_id = active_account_id()
    account = _accounts().get(account_id, {}) if account_id else {}
    if account:
        name = str(account.get("name", "") or account.get("email", "") or "")
        # Preserve the legacy profile during migration from the pre-multi-account
        # settings format.  _sync_legacy_profile only mirrors the active account,
        # so this cannot leak an avatar from another saved account.
        avatar_url = str(account.get("avatar_url", "") or "")
        if account_id == str(g_settings.get("active_account_id", "") or ""):
            avatar_url = avatar_url or str(
                g_settings.get("user_avatar_url", "") or ""
            )
        return {
            "account_id": account_id,
            "email": str(account.get("email", "") or ""),
            "name": name,
            "avatar_url": avatar_url,
            "verified": bool(account.get("verified", False)),
        }
    return {
        "account_id": "",
        "email": str(g_settings.get("user_email", "") or ""),
        "name": str(g_settings.get("user_name", "") or g_settings.get("user_email", "") or ""),
        "avatar_url": str(g_settings.get("user_avatar_url", "") or ""),
        "verified": bool(g_settings.get("auth_verified", False)),
    }


def saved_accounts() -> list[dict]:
    out = []
    for account_id, account in sorted(_accounts().items(), key=lambda item: str(item[1].get("email") or item[1].get("name") or item[0]).lower()):
        item = dict(account)
        item["account_id"] = account_id
        item["name"] = str(item.get("name", "") or item.get("email", "") or account_id)
        item["email"] = str(item.get("email", "") or "")
        item["avatar_url"] = str(item.get("avatar_url", "") or "")
        item["verified"] = bool(item.get("verified", False))
        out.append(item)
    return out


def set_active_account(account_id: str) -> None:
    account_id = str(account_id or "").strip()
    if not account_id or account_id not in _accounts():
        return
    g_settings["active_account_id"] = account_id
    _sync_legacy_profile(_accounts()[account_id])
    save_settings()


def save_signed_in_profile(data: dict, verified: bool = True, account_id: str = "") -> str:
    account_id = account_id_for_data(data, fallback=account_id or active_account_id())
    accounts = _accounts()
    previous = dict(accounts.get(account_id, {}))
    email = str(data.get("email", "") or "")
    name = str(data.get("name", "") or data.get("profile_name", "") or email)
    avatar_url = str(data.get("avatar_url", "") or "")
    device_fingerprint = str(data.get("device_fingerprint", "") or "")
    server_url = str(data.get("server_url", "") or previous.get("server_url", "") or g_settings.get("server_url", ""))

    account = {
        "user_id": str(data.get("user_id", "") or previous.get("user_id", "") or account_id),
        "email": email or str(previous.get("email", "") or ""),
        "name": name or str(previous.get("name", "") or ""),
        "avatar_url": avatar_url or str(previous.get("avatar_url", "") or ""),
        "device_fingerprint": device_fingerprint or str(previous.get("device_fingerprint", "") or ""),
        "server_url": server_url,
        "verified": verified,
    }
    accounts[account_id] = account
    g_settings["active_account_id"] = account_id
    _sync_legacy_profile(account)
    save_settings()
    return account_id


def mark_unverified() -> None:
    account_id = active_account_id()
    if account_id and account_id in _accounts():
        _accounts()[account_id]["verified"] = False
    g_settings["auth_verified"] = False
    save_settings()


def clear_signed_in_profile(clear_token: bool = False) -> None:
    account_id = active_account_id()
    if account_id and clear_token:
        account = _accounts().get(account_id, {})
        server_url = str(
            account.get("server_url", "") or g_settings.get("server_url", "") or ""
        )
        from .session import reset_shared_auth_context

        reset_shared_auth_context(account_id, server_url)
        secret_store.clear_refresh_token(account_id, server_url)
        _accounts().pop(account_id, None)
        remaining = saved_accounts()
        g_settings["active_account_id"] = remaining[0]["account_id"] if remaining else ""
    elif account_id and account_id in _accounts():
        _accounts()[account_id]["verified"] = False

    active = active_account_id()
    if active and active in _accounts():
        _sync_legacy_profile(_accounts()[active])
    else:
        _sync_legacy_profile({})
    save_settings()


def verify_saved_sign_in() -> dict:
    account_id = active_account_id()
    server_url = str(g_settings.get("server_url", "https://api.decompile.re") or "")
    token = secret_store.load_refresh_token(account_id, server_url)
    if not token:
        clear_signed_in_profile()
        return profile()

    from .session import AuthError, ServerSession, get_shared_auth_context

    srv = None
    try:
        fp = fingerprint.device_fingerprint()
        auth_context = get_shared_auth_context(
            server_url,
            token,
            fp,
            account_id=account_id,
        )
        srv = ServerSession(
            server_url,
            token,
            fp,
            account_id=account_id,
            auth_context=auth_context,
        )
        info = srv.verify_auth()
        merged = dict(_accounts().get(account_id, {}))
        merged.update({k: v for k, v in info.items() if v})
        save_signed_in_profile(merged, verified=True, account_id=account_id)
    except AuthError as e:
        if e.rejected:
            clear_signed_in_profile(clear_token=True)
        else:
            mark_unverified()
    except Exception:
        mark_unverified()
    finally:
        if srv is not None:
            srv.close()
    return profile()


def _sync_legacy_profile(account: dict) -> None:
    g_settings["user_email"] = str(account.get("email", "") or "")
    g_settings["user_name"] = str(account.get("name", "") or account.get("email", "") or "")
    g_settings["user_avatar_url"] = str(account.get("avatar_url", "") or "")
    g_settings["auth_verified"] = bool(account.get("verified", False))
