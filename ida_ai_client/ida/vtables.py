"""
vtables.py — VTable discovery and caching for the IDA client.

The client discovers vtables using IDA APIs and caches them.
VTable RANKING (choosing between candidates) is performed by the Go server.
Discovery happens lazily on the first scan_vtables command from the server.

All IDA database operations must be called on the main thread.
"""

import re
import threading

import idc
import idaapi
import ida_funcs
import ida_bytes
import ida_segment
import idautils

from ..config import PLUGIN_NAME, HEXRAYS_AVAILABLE
from .version_api import version_api

# ── Pointer size ──────────────────────────────────────────────────────────────

PTR_SIZE = version_api.pointer_size()
_MIN_ENTRIES = 2

_VTABLE_SECTIONS = {'.rdata', '.rodata', '.data.rel.ro', '__const', '__data_const'}

_MSVC_VTABLE_RE  = re.compile(r'^\?\?_7')
_GCC_VTABLE_RE   = re.compile(r'^_ZTV')
_DEMANGLE_PREFIX = "vtable for'"

# ── Module-level cache ────────────────────────────────────────────────────────

_cache: dict[int, dict] = {}
_cache_lock             = threading.Lock()
_scan_done              = False
_scan_lock              = threading.Lock()

# ── IDA helpers (main thread only) ───────────────────────────────────────────

def _is_func_ptr(ea: int) -> bool:
    try:
        fn = ida_funcs.get_func(ea)
        return fn is not None and fn.start_ea == ea
    except Exception:
        return False


def _read_ptr(ea: int) -> int | None:
    try:
        val = ida_bytes.get_qword(ea)
        return val if val not in (idaapi.BADADDR, 0) else None
    except Exception:
        return None


def _read_vtable_entries(ea: int, seg_end: int = 0) -> list[dict]:
    entries = []
    cur = ea
    while True:
        if seg_end and cur + PTR_SIZE > seg_end:
            break
        val = _read_ptr(cur)
        if val is None or not _is_func_ptr(val):
            break
        entries.append({
            "slot":      len(entries),
            "offset":    len(entries) * PTR_SIZE,
            "func_ea":   val,
            "func_name": idc.get_func_name(val) or f"sub_{val:X}",
        })
        cur += PTR_SIZE
    return entries


def _vtable_dict(ea: int, name: str, entries: list[dict], from_rtti: bool) -> dict:
    return {
        "ea":          ea,
        "name":        name,
        "entries":     entries,
        "num_methods": len(entries),
        "from_rtti":   from_rtti,
    }

# ── Pass 1: RTTI-based discovery (main thread only) ───────────────────────────

def _find_vtables_rtti() -> list[dict]:
    found = []
    seen_eas: set[int] = set()
    for ea, name in idautils.Names():
        is_vtable = (
            _MSVC_VTABLE_RE.match(name)
            or _GCC_VTABLE_RE.match(name)
            or name.startswith(_DEMANGLE_PREFIX)
        )
        if not is_vtable or ea in seen_eas:
            continue
        entries = _read_vtable_entries(ea)
        if len(entries) >= _MIN_ENTRIES:
            demangled = idaapi.demangle_name(name, idaapi.MNG_SHORT_FORM) or name
            found.append(_vtable_dict(ea, demangled, entries, from_rtti=True))
            seen_eas.add(ea)
    return found

# ── Pass 2: Brute-force segment scan (main thread only) ───────────────────────

def _find_vtables_brute(skip_eas: set[int]) -> list[dict]:
    found = []
    for seg_ea in idautils.Segments():
        seg = ida_segment.getseg(seg_ea)
        if seg is None:
            continue
        if idc.get_segm_name(seg_ea) not in _VTABLE_SECTIONS:
            continue
        ea  = seg.start_ea
        end = seg.end_ea
        while ea + PTR_SIZE <= end:
            if ea in skip_eas:
                ea += PTR_SIZE
                continue
            entries = _read_vtable_entries(ea, end)
            if len(entries) >= _MIN_ENTRIES:
                name = idc.get_name(ea) or f"vtable_{ea:016X}"
                found.append(_vtable_dict(ea, name, entries, from_rtti=False))
                ea += len(entries) * PTR_SIZE
            else:
                ea += PTR_SIZE
    return found

# ── Public: ensure cache is populated (main thread only) ─────────────────────

def ensure_vtables_cached() -> None:
    global _scan_done
    with _scan_lock:
        if _scan_done:
            return
        _scan_done = True

    rtti_vtables  = _find_vtables_rtti()
    rtti_eas      = {vt["ea"] for vt in rtti_vtables}
    brute_vtables = [] if rtti_vtables else _find_vtables_brute(skip_eas=rtti_eas)
    all_vtables   = rtti_vtables + brute_vtables

    with _cache_lock:
        for vt in all_vtables:
            _cache[vt["ea"]] = vt

    print(
        f"[{PLUGIN_NAME}] VTable cache: {len(all_vtables)} total "
        f"({len(rtti_vtables)} RTTI, {len(brute_vtables)} brute-force)"
    )


def get_cached_vtables() -> list[dict]:
    with _cache_lock:
        return list(_cache.values())

# ── Public: find virtual call sites (main thread only) ───────────────────────

def find_vcall_sites(func_ea: int, target_offset: int) -> list[int]:
    """Return EAs of cot_call nodes in func_ea that dispatch at target_offset.

    Works by walking the Hex-Rays ctree and matching the double-deref pattern:
        (*(*obj + target_offset))(...)
    Falls back to an empty list when Hex-Rays is unavailable or decompilation fails.
    """
    if not HEXRAYS_AVAILABLE:
        return []

    try:
        import ida_hexrays

        cfunc = ida_hexrays.decompile(func_ea)
        if cfunc is None:
            return []

        def _num_value(expr) -> int | None:
            """Extract the integer value from a cot_num expression."""
            if expr.op == ida_hexrays.cot_num:
                try:
                    return expr.n._value
                except Exception:
                    pass
            return None

        def _contains_offset(expr) -> bool:
            """True if expr contains a cot_num leaf equal to target_offset."""
            if expr is None:
                return False
            v = _num_value(expr)
            if v is not None:
                return (v & 0xFFFFFFFFFFFFFFFF) == (target_offset & 0xFFFFFFFFFFFFFFFF)
            try:
                if expr.x is not None and _contains_offset(expr.x):
                    return True
                if expr.y is not None and _contains_offset(expr.y):
                    return True
            except Exception:
                pass
            return False

        class _VCallFinder(ida_hexrays.ctree_visitor_t):
            def __init__(self):
                super().__init__(ida_hexrays.CV_FAST)
                self.sites: list[int] = []

            def visit_expr(self, e):
                # We want: cot_call { x: cot_ptr { x: <expr containing target_offset> } }
                if e.op == ida_hexrays.cot_call:
                    fn = e.x
                    if fn is not None and fn.op == ida_hexrays.cot_ptr:
                        if _contains_offset(fn.x):
                            if e.ea != idaapi.BADADDR:
                                self.sites.append(e.ea)
                return 0

        finder = _VCallFinder()
        finder.apply_to(cfunc.body, None)
        return finder.sites

    except Exception as exc:
        print(f"[{PLUGIN_NAME}] find_vcall_sites({func_ea:#x}, {target_offset}): {exc}")
        return []


# ── Public: rename anonymous vtable (main thread only) ───────────────────────

def rename_vtable_if_anonymous(vtable_ea: int, winner_func_name: str) -> None:
    with _cache_lock:
        vt = _cache.get(vtable_ea)
        if vt is None or vt.get("from_rtti"):
            return

    base = winner_func_name
    if "::" in base:
        class_part = base.split("::")[0].strip()
        new_name = f"vtable_{class_part}"
    else:
        new_name = f"vtable_winner_{base}"

    new_name = re.sub(r"[^A-Za-z0-9_]", "_", new_name)
    ok = idc.set_name(vtable_ea, new_name, idc.SN_NOWARN | idc.SN_NOCHECK)
    if ok:
        with _cache_lock:
            if vtable_ea in _cache:
                _cache[vtable_ea]["name"] = new_name
        print(f"[{PLUGIN_NAME}] Renamed anonymous vtable {vtable_ea:#x} → {new_name}")
