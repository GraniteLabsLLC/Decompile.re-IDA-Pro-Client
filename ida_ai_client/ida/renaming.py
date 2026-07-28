"""
renaming.py — Helpers for renaming functions and local variables in IDA Pro.
"""

import re

import idc
import ida_hexrays
import ida_typeinf

from ..config import PLUGIN_NAME, HEXRAYS_AVAILABLE


def _sanitise_name(name: str) -> str:
    name = re.sub(r"[^a-zA-Z0-9_]", "_", name).strip("_")
    if name and name[0].isdigit():
        name = "n_" + name
    return name or "unknown"


def safe_rename_function(ea: int, new_name: str) -> bool:
    try:
        new_name = _sanitise_name(new_name)
        return idc.set_name(ea, new_name, idc.SN_NOWARN | idc.SN_NOCHECK) != 0
    except Exception as e:
        print(f"[{PLUGIN_NAME}] Rename func {ea:#x}: {e}")
        return False


def rename_global(current_name: str, new_name: str, ea_text: str = "") -> bool:
    """Rename a global data symbol (byte_XXXX, dword_XXXX, off_XXXX, …).

    Resolves current_name to its address and applies new_name there. Returns
    False if the name does not resolve or the rename is rejected (e.g. the new
    name collides with an existing symbol).
    """
    try:
        ea = idc.BADADDR
        if ea_text:
            try:
                ea = int(ea_text, 16)
            except ValueError:
                ea = idc.BADADDR
        if ea == idc.BADADDR and current_name:
            ea = idc.get_name_ea_simple(current_name)
        if ea == idc.BADADDR:
            return False
        new_name = _sanitise_name(new_name)
        return idc.set_name(ea, new_name, idc.SN_NOWARN | idc.SN_NOCHECK) != 0
    except Exception as e:
        print(f"[{PLUGIN_NAME}] rename_global {current_name}: {e}")
        return False


def _make_lvar_info(lvar, new_name: str, type_str: str):
    lsi      = ida_hexrays.lvar_saved_info_t()
    lsi.ll   = lvar
    lsi.name = new_name

    if type_str:
        tif = ida_typeinf.tinfo_t()
        # IDA 9.3: parse_decl is still 4-arg (tif, til, decl, flags);
        # pass None for til to use the current IDB's local TIL.
        if ida_typeinf.parse_decl(tif, None, type_str.rstrip(";") + ";",
                                  ida_typeinf.PT_SIL):
            lsi.type = tif

    return lsi


def _apply_lvar_info(func_ea: int, lvar, new_name: str, type_str: str) -> bool:
    lsi = _make_lvar_info(lvar, new_name, type_str)
    uvec = ida_hexrays.lvar_uservec_t()
    uvec.lvvec.push_back(lsi)
    ida_hexrays.save_user_lvar_settings(func_ea, uvec)
    return True


def rename_lvar(func_ea: int, current_name: str, new_name: str, type_str: str = "") -> bool:
    return rename_lvars(func_ea, [{
        "current_name": current_name,
        "new_name": new_name,
        "type": type_str,
    }]) > 0


def rename_lvars_detailed(func_ea: int, renames: list) -> list[dict]:
    if not HEXRAYS_AVAILABLE:
        return []
    renames = renames or []
    wanted = [
        r for r in renames
        if r.get("current_name") and r.get("new_name") and r.get("current_name") != r.get("new_name")
    ]
    if not wanted:
        return []
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return []

        by_name = {lv.name: lv for lv in cfunc.get_lvars()}
        uvec = ida_hexrays.lvar_uservec_t()
        applied = []
        seen = set()

        for item in wanted:
            current_name = item.get("current_name", "")
            if current_name in seen:
                continue
            seen.add(current_name)
            target = by_name.get(current_name)
            if target is None:
                continue

            new_name = _sanitise_name(item.get("new_name", ""))
            type_str = item.get("type") or item.get("type_str") or ""
            uvec.lvvec.push_back(_make_lvar_info(target, new_name, type_str))
            applied.append({
                "current_name": current_name,
                "new_name": new_name,
                "type": type_str,
            })

        if applied:
            ida_hexrays.save_user_lvar_settings(func_ea, uvec)
            ida_hexrays.mark_cfunc_dirty(func_ea)
        return applied
    except Exception as e:
        print(f"[{PLUGIN_NAME}] rename_lvars {func_ea:#x}: {e}")
        return []


def rename_lvars(func_ea: int, renames: list) -> int:
    return len(rename_lvars_detailed(func_ea, renames))


def rename_function_parameters_detailed(func_ea: int, params: list) -> list[dict]:
    if not HEXRAYS_AVAILABLE or not params:
        return []
    applied = []
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        if not cfunc:
            return []

        args = [lv for lv in cfunc.get_lvars() if lv.is_arg_var]

        for i, param in enumerate(params):
            if i >= len(args):
                break
            current_name = args[i].name
            new_name = _sanitise_name(param.get("name", ""))
            type_str = (param.get("type") or "").strip()
            if not new_name:
                continue

            if _apply_lvar_info(func_ea, args[i], new_name, type_str):
                applied.append({
                    "current_name": current_name,
                    "new_name": new_name,
                    "type": type_str,
                })

        if applied:
            ida_hexrays.mark_cfunc_dirty(func_ea)

    except Exception as e:
        print(f"[{PLUGIN_NAME}] rename_params {func_ea:#x}: {e}")
    return applied


def rename_function_parameters(func_ea: int, params: list) -> int:
    return len(rename_function_parameters_detailed(func_ea, params))
