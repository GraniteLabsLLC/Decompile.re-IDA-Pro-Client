"""
types.py — Helpers for creating/modifying IDA structures and applying C type declarations.

IDA 9.x notes:
  - ida_struct was removed; all struct access uses ida_typeinf.
  - parse_decl() is now 3-arg: (tif, decl, flags) — no til argument.
  - idc.parse_decls() and idc.PT_FILE/PT_SIL removed; use ida_typeinf.parse_decls().
"""

import re as _re
import idc
import idautils
import ida_funcs
import ida_hexrays
import ida_typeinf

from ..config import PLUGIN_NAME, HEXRAYS_AVAILABLE
from .version_api import version_api

# ── Typedef sanitisation ──────────────────────────────────────────────────────

_COMMENT_RE = _re.compile(r'/\*.*?\*/|//[^\n]*', _re.DOTALL)

# Matches function-pointer members: RetType (__convention *name)(args)
_FUNCPTR_RE = _re.compile(
    r'\b[\w\s*]+\s*\(\s*[_a-zA-Z]+\s*\*+\s*\w*\s*\)\s*\([^)]*\)',
    _re.DOTALL,
)

_C99_MAP = [
    (r'\buint8_t\b',   'unsigned char'),
    (r'\buint16_t\b',  'unsigned short'),
    (r'\buint32_t\b',  'unsigned int'),
    (r'\buint64_t\b',  'unsigned __int64'),
    (r'\bint8_t\b',    '__int8'),
    (r'\bint16_t\b',   '__int16'),
    (r'\bint32_t\b',   '__int32'),
    (r'\bint64_t\b',   '__int64'),
    (r'\bsize_t\b',    'unsigned __int64'),
    (r'\buintptr_t\b', 'unsigned __int64'),
    (r'\bintptr_t\b',  '__int64'),
    (r'\bptrdiff_t\b', '__int64'),
    (r'\bbool\b',      'unsigned char'),
    (r'\bBYTE\b',      'unsigned char'),
    (r'\bWORD\b',      'unsigned short'),
    (r'\bDWORD\b',     'unsigned int'),
    (r'\bQWORD\b',     'unsigned __int64'),
    (r'\b_BYTE\b',     'unsigned char'),
    (r'\b_WORD\b',     'unsigned short'),
    (r'\b_DWORD\b',    'unsigned int'),
    (r'\b_QWORD\b',    'unsigned __int64'),
]

# Types that IDA's standalone TIL parser always knows.
_IDA_KNOWN = frozenset({
    'BYTE', 'WORD', 'DWORD', 'QWORD', 'OWORD', 'TBYTE',
    '_BYTE', '_WORD', '_DWORD', '_QWORD',
    'char', 'short', 'int', 'long', 'float', 'double', 'void',
    'unsigned', 'signed',
    '__int8', '__int16', '__int32', '__int64',
    'INT8', 'INT16', 'INT32', 'INT64',
    'UINT8', 'UINT16', 'UINT32', 'UINT64',
    'BOOL', 'HANDLE', 'HMODULE', 'PVOID', 'LPVOID',
    'LPCSTR', 'LPSTR', 'LPCWSTR', 'LPWSTR',
    'struct', 'union', 'enum', 'typedef', 'const',
    '__cdecl', '__stdcall', '__fastcall', '__thiscall', '__usercall',
})

# Matches a single struct member line: [type] [*] name [array] ;
_MEMBER_RE = _re.compile(
    r'(?P<type>[A-Za-z_]\w*)'      # type name
    r'(?P<ptr>\s*\*+)?'             # optional pointer stars
    r'\s+(?P<name>[A-Za-z_]\w*)'   # member name
    r'(?P<arr>\s*\[\s*\d+\s*\])*'  # optional array dimensions
    r'\s*;',
)


def _sanitize_c_decl(decl: str) -> str:
    """Strip comments, replace function pointers, normalise C99 type names."""
    decl = _COMMENT_RE.sub('', decl)
    decl = _FUNCPTR_RE.sub('void *', decl)
    for pattern, replacement in _C99_MAP:
        decl = _re.sub(pattern, replacement, decl)
    return decl.strip()


def _packed_decl(decl: str) -> str:
    """Wrap a declaration in 1-byte packing pragmas for exact IDA offsets."""
    return "#pragma pack(push, 1)\n" + decl.strip() + "\n#pragma pack(pop)\n"


def _safe_type_name(name: str) -> str:
    """Return a valid C type identifier for IDA's parser."""
    name = (name or "").strip()
    name = _re.sub(r"^(struct|union|enum)\s+", "", name)
    name = _re.sub(r"\W+", "_", name)
    name = name.strip("_")
    if not name:
        name = "RecoveredStruct"
    if _re.match(r"^\d", name):
        name = "_" + name
    return name


def _sanitize_member_type(type_str: str) -> str:
    """Normalize one member type into something IDA's C parser accepts."""
    typ = _sanitize_c_decl(type_str or "")
    typ = typ.strip().rstrip(";").strip()
    if not typ:
        return "unsigned __int64"
    # C++ references/classes/templates are not C local-type declarations. Keep
    # pointer semantics where visible; otherwise use an opaque machine word.
    if "&" in typ or "<" in typ or ">" in typ or "::" in typ:
        return "void *" if "*" in typ or "&" in typ else "unsigned __int64"
    if "(" in typ and ")" in typ:
        return "void *"
    return typ


def _split_array_type(type_str: str) -> tuple[str, str]:
    """Move array suffixes from the type position to the declarator position."""
    typ = _sanitize_member_type(type_str)
    suffixes = []
    while True:
        m = _re.search(r"\[\s*(\d*)\s*\]\s*$", typ)
        if not m:
            break
        n = m.group(1).strip()
        suffixes.insert(0, f"[{n if n else '1'}]")
        typ = typ[:m.start()].rstrip()
    if not typ:
        typ = "unsigned char"
    return typ, "".join(suffixes)


def _strip_unknown_types(decl: str) -> str:
    """Replace unrecognised member type names with void* (pointers) or QWORD.

    This is a last-resort pass: it fixes forward-references to custom types
    that haven't been defined in IDA's TIL yet.
    """
    def _replace(m: _re.Match) -> str:
        tname = m.group('type')
        if tname in _IDA_KNOWN:
            return m.group(0)
        ptr  = m.group('ptr') or ''
        name = m.group('name')
        arr  = m.group('arr') or ''
        if ptr.strip():
            # Was a pointer — keep pointer semantics with void*
            return f'void *{name}{arr};'
        # Was a value type — treat as opaque 8-byte slot
        return f'unsigned __int64 {name}{arr};'

    # Only apply inside the struct body (between the outer braces)
    body_match = _re.search(r'\{(.*)\}', decl, _re.DOTALL)
    if not body_match:
        return decl
    body    = body_match.group(1)
    new_body = _MEMBER_RE.sub(_replace, body)
    return decl[:body_match.start(1)] + new_body + decl[body_match.end(1):]


def apply_c_type_declaration(c_decl: str) -> bool:
    """Try multiple passes to register a C typedef in IDA's local TIL.

    IDA 9.x: idc.parse_decls() and idc.PT_FILE/PT_SIL were removed.
    We use ida_typeinf.parse_decls() directly with PT_TYP | PT_SIL | PT_REPLACE.
    """
    c_decl = c_decl.strip()
    if not c_decl.endswith(';'):
        c_decl += ';'

    sanitized   = _sanitize_c_decl(c_decl)
    type_stripped = _strip_unknown_types(sanitized)
    if not sanitized.endswith(';'):
        sanitized += ';'
    if not type_stripped.endswith(';'):
        type_stripped += ';'

    # Order: packed sanitized → packed type-stripped → normal fallbacks → raw.
    # The packed forms are important for reverse-engineered layouts such as IDTR
    # where a QWORD sits at offset 2 and normal C alignment would shift it.
    attempts = [_packed_decl(sanitized), _packed_decl(type_stripped), sanitized, type_stripped]
    if c_decl not in attempts:
        attempts.append(c_decl)

    til = ida_typeinf.get_idati()
    for attempt in attempts:
        for flags in (
            ida_typeinf.PT_TYP | ida_typeinf.PT_SIL | ida_typeinf.PT_REPLACE,
            ida_typeinf.PT_SIL | ida_typeinf.PT_REPLACE,
        ):
            try:
                errors = ida_typeinf.parse_decls(til, attempt, None, flags)
                if errors == 0:
                    return True
            except Exception as exc:
                print(f'[{PLUGIN_NAME}] parse_decls raised: {exc}')

    # All attempts failed — log the final form so the user can diagnose.
    print(f'[{PLUGIN_NAME}] Struct parse failed. Sanitized decl:\n{sanitized}')
    return False


def create_or_update_struct(name: str, c_typedef: str) -> bool:
    print(f"[{PLUGIN_NAME}]   → Applying struct '{name}'")
    ok = apply_c_type_declaration(c_typedef)
    if not ok:
        print(f"[{PLUGIN_NAME}]   ✗ Failed to apply struct '{name}'")
    return ok


def modify_struct_members(struct_name: str, modified_members: list) -> int:
    """Update member types and names through the active IDA implementation."""
    return version_api.modify_struct_members(
        struct_name, modified_members, PLUGIN_NAME
    )


def _member_size(type_str: str) -> int:
    """Byte size of a C type as IDA's local TIL parses it; 0 if unknown.

    Uses parse_decl with til=None (the current IDB's TIL), so custom struct types
    already defined in the database resolve to their real size.
    """
    try:
        tif = ida_typeinf.tinfo_t()
        decl, arr = _split_array_type(type_str)
        if ida_typeinf.parse_decl(tif, None, f"{decl} __member{arr};", ida_typeinf.PT_SIL):
            sz = tif.get_size()
            if isinstance(sz, int) and 0 < sz < (1 << 31):
                return sz
    except Exception:
        pass
    return 0


def _safe_member_name(name: str, off: int, used: set) -> str:
    """Return a valid, unique C identifier for a member at the given offset."""
    if name and _re.match(r"^[A-Za-z_]\w*$", name) and name not in used:
        return name
    base = f"field_{off:X}"
    candidate = base
    k = 1
    while candidate in used:
        candidate = f"{base}_{k}"
        k += 1
    return candidate


def _build_struct_typedef(struct_name: str, norm: list, typed: bool = True) -> str:
    """Build a packed typedef from sorted (offset, name, type) tuples."""
    lines: list = []
    cursor = 0
    used: set = set()
    n = len(norm)
    for i, (off, name, typ) in enumerate(norm):
        if off < cursor:
            continue  # overlaps an earlier, enlarged member — absorb it
        if off > cursor:
            lines.append(f"    char gap_{cursor:X}[{off - cursor}];")
        name = _safe_member_name(name, off, used)
        used.add(name)

        clean_typ, arr = _split_array_type(typ)
        size = _member_size(clean_typ + arr)
        nxt = norm[i + 1][0] if i + 1 < n else None
        if size <= 0:
            if nxt is not None and nxt > off:
                size = nxt - off
            else:
                size = 8

        if typed:
            if nxt is not None and off + size > nxt:
                # The requested type is larger than the gap to the next
                # explicit field. Preserve exact offsets by making this slot
                # opaque instead of letting it overlap.
                lines.append(f"    char {name}[{nxt - off}];")
                cursor = nxt
                continue
            lines.append(f"    {clean_typ} {name}{arr};")
        else:
            lines.append(f"    char {name}[{size}];")
        cursor = off + size

    return "typedef struct {\n%s\n} %s;" % ("\n".join(lines), struct_name)


def replace_struct_from_layout(struct_name: str, members: list) -> bool:
    """Rebuild a struct from an offset-keyed member list, replacing the existing one.

    members: [{"offset": int, "name": str, "type": str}, ...] using BYTE offsets.

    The server sends only offsets/names/types; THIS side computes the padding
    between members (so a field discovered in what IDA currently treats as
    padding can be added) and emits a typedef whose member offsets are exact.
    Members are placed at their declared offsets; gaps become char arrays. A
    member that overlaps an earlier (enlarged) one is absorbed.
    """
    if not struct_name or not members:
        return False
    struct_name = _safe_type_name(struct_name)

    norm = []
    for m in members:
        try:
            raw_off = m.get("offset")
            off = int(raw_off, 0) if isinstance(raw_off, str) else int(raw_off)
        except (TypeError, ValueError):
            continue
        typ = _sanitize_member_type(m.get("type") or "")
        if off < 0 or not typ:
            continue
        norm.append((off, (m.get("name") or "").strip(), typ))
    if not norm:
        return False
    norm.sort(key=lambda t: t[0])

    typedef = _build_struct_typedef(struct_name, norm, typed=True)
    if apply_c_type_declaration(typedef):
        return True

    # Last-resort fallback: keep exact discovered offsets with opaque byte
    # fields. This is better than failing the whole structure and still gives
    # Hex-Rays a real named layout to attach to variables.
    fallback = _build_struct_typedef(struct_name, norm, typed=False)
    ok = apply_c_type_declaration(fallback)
    if not ok:
        print(f"[{PLUGIN_NAME}] replace_struct_from_layout failed for {struct_name} with {len(norm)} member(s)")
    return ok


def get_all_structs() -> list:
    """Enumerate all struct definitions from IDA's Local Type Library.

    Reads from Local Types (not the Structures window) because the Hex-Rays
    decompiler resolves type names from Local Types — this matches where
    create_or_update_struct() writes via parse_decls/apply_c_type_declaration.

    Returns a list of dicts:
        {"name": str, "size": int, "members": [{"name": str, "type": str, "offset": int}, ...]}
    Returns an empty list if IDA modules are unavailable or if no structs exist.
    """
    return version_api.get_all_structs(PLUGIN_NAME)


_FUNCTION_STRUCT_LIMIT = 8
_FUNCTION_STRUCT_MEMBER_LIMIT = 64

_TYPE_TOKEN_RE = _re.compile(r'\b[A-Za-z_][A-Za-z0-9_]*\b')
_TYPE_TOKEN_SKIP = {
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "int",
    "long", "register", "return", "short", "signed", "sizeof", "static",
    "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
    "while", "class", "public", "private", "protected", "virtual", "this",
    "__int8", "__int16", "__int32", "__int64", "__fastcall", "__stdcall",
    "__cdecl", "__thiscall", "__usercall", "__spoils", "_BYTE", "_WORD",
    "_DWORD", "_QWORD", "BYTE", "WORD", "DWORD", "QWORD", "LOBYTE",
    "HIBYTE", "LOWORD", "HIWORD", "LODWORD", "HIDWORD", "NULL", "true",
    "false", "bool", "size_t", "uint8_t", "uint16_t", "uint32_t",
    "uint64_t", "int8_t", "int16_t", "int32_t", "int64_t",
}


def _normalise_type_name(name: str) -> str:
    name = (name or "").strip()
    name = _re.sub(r"^(struct|union|enum|class)\s+", "", name)
    return name.strip()


def _extract_type_tokens(text: str) -> list:
    if not text:
        return []
    out = []
    seen = set()
    for token in _TYPE_TOKEN_RE.findall(text):
        if token in seen or token in _TYPE_TOKEN_SKIP:
            continue
        if token.startswith(("sub_", "loc_", "off_", "byte_", "word_", "dword_", "qword_", "xmmword_")):
            continue
        seen.add(token)
        out.append(token)
    return out


def _lookup_struct(name: str) -> dict | None:
    name = _normalise_type_name(name)
    if not name or name in _TYPE_TOKEN_SKIP:
        return None
    try:
        return version_api.lookup_struct(name, _FUNCTION_STRUCT_MEMBER_LIMIT)
    except Exception:
        return None


def _add_struct_candidate(out: list, seen: set, name: str) -> None:
    if len(out) >= _FUNCTION_STRUCT_LIMIT:
        return
    name = _normalise_type_name(name)
    key = name.lower()
    if not name or key in seen:
        return
    st = _lookup_struct(name)
    if not st:
        return
    seen.add(key)
    out.append(st)


def _collect_lvar_type_text(ea: int) -> str:
    if not HEXRAYS_AVAILABLE:
        return ""
    try:
        cfunc = ida_hexrays.decompile(ea)
        if not cfunc:
            return ""
        parts = []
        for lv in cfunc.get_lvars():
            try:
                tif = lv.type()
            except Exception:
                tif = getattr(lv, "tif", None)
            if tif:
                parts.append(str(tif))
        return "\n".join(parts)
    except Exception:
        return ""


def get_function_structs(ea: int, code: str = "") -> list:
    """Return only structures that appear relevant to one function.

    This intentionally does not enumerate the IDB's full Local Types database.
    It gathers candidate type names from the function prototype, Hex-Rays local
    variable types, pseudocode/disassembly text, and instruction annotations,
    then resolves only those names against IDA's type system.
    """
    structs = []
    seen = set()
    text_parts = []

    try:
        proto = idc.get_type(ea) or ""
        text_parts.append(proto)
    except Exception:
        pass

    text_parts.append(_collect_lvar_type_text(ea))
    if code:
        text_parts.append(code)

    try:
        fn = ida_funcs.get_func(ea)
        if fn:
            for item_ea in idautils.FuncItems(fn.start_ea):
                try:
                    text_parts.append(idc.generate_disasm_line(item_ea, 0) or "")
                except Exception:
                    pass
    except Exception:
        pass

    for token in _extract_type_tokens("\n".join(text_parts)):
        _add_struct_candidate(structs, seen, token)
        if len(structs) >= _FUNCTION_STRUCT_LIMIT:
            break
    return structs


def set_function_comment(ea: int, comment: str) -> None:
    """Set a repeatable comment on the function that contains ea."""
    try:
        idc.set_func_cmt(ea, comment[:1024], 1)
    except Exception:
        pass


def set_address_comment(ea: int, comment: str) -> None:
    """Set a repeatable comment at a specific address (e.g. a call site)."""
    try:
        idc.set_cmt(ea, comment[:1024], 1)
    except Exception:
        pass
