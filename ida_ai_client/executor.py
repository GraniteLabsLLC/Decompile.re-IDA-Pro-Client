"""
executor.py — Maps server IDA commands to actual IDA Pro API calls.

Every public method here is called on IDA's main thread (via run_on_main in worker.py).
Return values are dicts ready to POST back to the server as IDAResult objects.
"""

import hashlib
import os
import re
import shutil
import subprocess
import tempfile

import idc
import ida_hexrays
import ida_lines

from .ida.navigation import get_function_code, get_pseudocode, get_disassembly, get_function_name, find_function_by_name, get_bytes, get_function_global_references, build_call_tree, scan_exports, find_string_xrefs, pdb_symbols_loaded
from .ida.renaming   import (
    safe_rename_function,
    rename_lvar,
    rename_lvars_detailed,
    rename_function_parameters_detailed,
    rename_global,
)
from .ida.types      import create_or_update_struct, modify_struct_members, replace_struct_from_layout, set_function_comment, set_address_comment, get_all_structs, get_function_structs
from .ida.vtables    import ensure_vtables_cached, get_cached_vtables, rename_vtable_if_anonymous, find_vcall_sites
from .config         import HEXRAYS_AVAILABLE


# ─── Source-reconstruction state ────────────────────────────────────────────
#
# When the server invokes request_output_directory and we return a path, we
# remember it module-level. All subsequent write_file / compile_project
# commands resolve their paths relative to this directory. The server is never
# trusted to send absolute paths — that would let a malicious server write
# anywhere on the user's disk.

_OUTPUT_DIR: str = ""
_BUILD_APPROVED_FINGERPRINT: str = ""
_BUILD_DENIED_FINGERPRINT: str = ""
_MAX_SOURCE_FILE_BYTES = 4 * 1024 * 1024
_MAX_BUILD_CONFIG_BYTES = 8 * 1024 * 1024
_MAX_BUILD_OUTPUT_CHARS = 2 * 1024 * 1024
_MAX_LISTED_FILES = 10_000


def _set_output_directory(path: str) -> None:
    """Record the user-approved output directory for source reconstruction."""
    global _OUTPUT_DIR, _BUILD_APPROVED_FINGERPRINT, _BUILD_DENIED_FINGERPRINT
    _OUTPUT_DIR = os.path.realpath(os.path.abspath(path)) if path else ""
    _BUILD_APPROVED_FINGERPRINT = ""
    _BUILD_DENIED_FINGERPRINT = ""


def _resolve_under_outdir(rel_path: str) -> str | None:
    """Join rel_path with the output directory and reject path traversal.

    Returns the absolute target path, or None if the path is invalid (no
    output directory set, escapes the sandbox, or is otherwise unsafe).
    """
    if not _OUTPUT_DIR:
        return None
    if not rel_path or os.path.isabs(rel_path) or os.path.splitdrive(rel_path)[0]:
        return None
    # Resolve symlinks/junctions as well as '..'. Prefix checks alone can be
    # bypassed by a link inside the approved directory that targets elsewhere.
    base = os.path.realpath(_OUTPUT_DIR)
    candidate = os.path.realpath(os.path.join(base, rel_path))
    try:
        contained = os.path.normcase(os.path.commonpath((base, candidate))) == os.path.normcase(base)
    except ValueError:
        contained = False
    if not contained:
        return None
    return candidate


def execute(cmd: dict) -> dict:
    """Dispatch a command dict to the appropriate IDA operation.

    Returns a result dict (without command_id — the caller fills that in).
    """
    t = cmd.get("type", "")
    try:
        return _DISPATCH.get(t, _unknown)(cmd)
    except Exception as e:
        return {"type": "error_result", "error": str(e)}


# ─── Command handlers ─────────────────────────────────────────────────────────

def _function_global_values(ea: int) -> list:
    global_values = []
    for reference in get_function_global_references(ea):
        name = reference.get("name", "")
        global_values.append({
            "name": name,
            "address": reference.get("address", ""),
            "value": _value_from_name(name),
        })
    return global_values


def _get_function_code(cmd: dict) -> dict:
    ea = int(cmd["ea"], 16)
    code = get_function_code(ea) or ""
    result = {
        "type": "string_result",
        "value": code,
        "structs": get_function_structs(ea, code),
    }
    return result


def _get_function_global_values(cmd: dict) -> dict:
    ea = int(cmd["ea"], 16)
    return {
        "type": "global_values_result",
        "global_values": _function_global_values(ea),
    }


def _get_function_pseudocode(cmd: dict) -> dict:
    ea = int(cmd["ea"], 16)
    code = get_pseudocode(ea) or ""
    return {"type": "string_result", "value": code}


def _get_function_disassembly(cmd: dict) -> dict:
    ea = int(cmd["ea"], 16)
    code = get_disassembly(ea) or ""
    return {"type": "string_result", "value": code}


def _get_function_name(cmd: dict) -> dict:
    ea = int(cmd["ea"], 16)
    name = get_function_name(ea) or ""
    return {"type": "string_result", "value": name}


def _find_function_by_name(cmd: dict) -> dict:
    ea = find_function_by_name(cmd["name"])
    return {"type": "string_result", "value": hex(ea) if ea is not None else ""}


def _get_bytes(cmd: dict) -> dict:
    ea   = int(cmd["ea"], 16)
    size = int(cmd.get("size", 0))
    raw  = get_bytes(ea, size)
    return {"type": "bytes_result", "hex": raw.hex() if raw else ""}


def _value_from_name(name: str) -> str:
    name = name or ""
    ea   = idc.get_name_ea_simple(name)
    if ea == idc.BADADDR:
        return ""
    raw_line = idc.generate_disasm_line(ea, 0) or ""
    line     = ida_lines.tag_remove(raw_line)
    if "db " in line:
        return line.split("db ", 1)[-1].strip()
    return line


def _get_value_from_name(cmd: dict) -> dict:
    name = cmd.get("name", "")
    return {"type": "string_result", "value": _value_from_name(name)}


def _parse_ea(text: str):
    text = (text or "").strip()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def _get_data_batch(cmd: dict) -> dict:
    """Return ordered memory/value reads in one client round-trip."""
    results = []
    for read in cmd.get("data_reads", []) or []:
        target = (read.get("target") or read.get("ea") or read.get("name") or "").strip()
        ea_text = (read.get("ea") or "").strip()
        name = (read.get("name") or "").strip()
        try:
            size = int(read.get("size") or 0)
        except (TypeError, ValueError):
            size = 0

        result = {
            "target": target,
            "size": size,
        }

        ea = _parse_ea(ea_text)
        if ea is None and target.lower().startswith("0x"):
            ea = _parse_ea(target)
        if ea is None and size > 0:
            lookup_name = name or target
            if lookup_name:
                named_ea = idc.get_name_ea_simple(lookup_name)
                if named_ea != idc.BADADDR:
                    ea = named_ea

        if size > 0 and ea is not None:
            result["kind"] = "memory"
            result["address"] = hex(ea)
            raw = get_bytes(ea, size)
            if raw:
                result["hex"] = raw.hex()
            elif name:
                value = _value_from_name(name)
                if value:
                    result["kind"] = "value"
                    result["value"] = value
                else:
                    result["error"] = "no bytes available"
            else:
                result["error"] = "no bytes available"
            results.append(result)
            continue

        if target.lower().startswith("0x"):
            result["kind"] = "memory"
            result["address"] = target
            result["error"] = "hex-address reads require a positive size"
            results.append(result)
            continue

        result["kind"] = "value"
        value = _value_from_name(name or target)
        if value:
            result["value"] = value
        else:
            result["error"] = "no value available"
        results.append(result)

    return {"type": "data_batch_result", "data_results": results}


def _rename_function(cmd: dict) -> dict:
    ea   = int(cmd["ea"], 16)
    name = cmd.get("name", "")
    ok   = safe_rename_function(ea, name)
    return {"type": "bool_result", "success": bool(ok)}


def _rename_global(cmd: dict) -> dict:
    ok = rename_global(cmd.get("current_name", ""), cmd.get("new_name", ""), cmd.get("ea", ""))
    return {"type": "bool_result", "success": bool(ok)}


def _find_string_xrefs(cmd: dict) -> dict:
    refs = find_string_xrefs(cmd.get("query", ""), int(cmd.get("limit", 5) or 5))
    return {"type": "string_refs_result", "string_refs": refs}


def _rename_lvar(cmd: dict) -> dict:
    func_ea = int(cmd["func_ea"], 16)
    ok = rename_lvar(
        func_ea,
        cmd.get("current_name", ""),
        cmd.get("new_name", ""),
        cmd.get("type_str", ""),
    )
    return {"type": "bool_result", "success": bool(ok)}


def _rename_lvars(cmd: dict) -> dict:
    func_ea = int(cmd["func_ea"], 16)
    applied = rename_lvars_detailed(func_ea, cmd.get("local_vars") or [])
    return {
        "type": "int_result",
        "count": len(applied),
        "applied_renames": applied,
    }


def _rename_params(cmd: dict) -> dict:
    func_ea = int(cmd["func_ea"], 16)
    params  = cmd.get("params") or []
    applied = rename_function_parameters_detailed(func_ea, params)
    return {
        "type": "int_result",
        "count": len(applied),
        "applied_renames": applied,
    }


def _get_all_structs(_cmd: dict) -> dict:
    structs = get_all_structs()
    return {"type": "structs_result", "structs": structs}


def _create_struct(cmd: dict) -> dict:
    ok = create_or_update_struct(cmd.get("name", ""), cmd.get("typedef", ""))
    return {"type": "bool_result", "success": bool(ok)}


def _modify_struct(cmd: dict) -> dict:
    cnt = modify_struct_members(cmd.get("name", ""), cmd.get("members") or [])
    return {"type": "int_result", "count": cnt}


def _replace_struct(cmd: dict) -> dict:
    ok = replace_struct_from_layout(cmd.get("name", ""), cmd.get("struct_layout") or cmd.get("members") or [])
    return {"type": "bool_result", "success": bool(ok)}


def _set_comment(cmd: dict) -> dict:
    set_function_comment(int(cmd["ea"], 16), cmd.get("comment", ""))
    return {"type": "ack"}


def _set_address_comment(cmd: dict) -> dict:
    set_address_comment(int(cmd["ea"], 16), cmd.get("comment", ""))
    return {"type": "ack"}


def _find_vcall_sites(cmd: dict) -> dict:
    func_ea = int(cmd["func_ea"], 16)
    offset  = int(cmd.get("offset", 0))
    sites   = find_vcall_sites(func_ea, offset)
    return {"type": "eas_result", "eas": [hex(ea) for ea in sites]}


def _mark_cfunc_dirty(cmd: dict) -> dict:
    if HEXRAYS_AVAILABLE:
        try:
            ida_hexrays.mark_cfunc_dirty(int(cmd["ea"], 16))
        except Exception:
            pass
    return {"type": "ack"}


def _get_call_tree(cmd: dict) -> dict:
    """Build the full static call graph reachable from root_ea.

    Used by the source-reconstruction fork's bottom-up engine. No LLM
    involvement — just IDA's xref data plus a virtual-call heuristic.
    """
    root_ea = int(cmd["ea"], 16)
    tree = build_call_tree(root_ea)
    return {
        "type": "call_tree_result",
        "call_tree": tree,
        "pdb_loaded": pdb_symbols_loaded(),
    }


def _scan_exports(cmd: dict) -> dict:
    """Enumerate exported functions from the current module."""
    return {"type": "exports_result", "exports": scan_exports()}


def _scan_vtables(cmd: dict) -> dict:
    ensure_vtables_cached()
    raw = get_cached_vtables()
    vtable_list = []
    for vt in raw:
        entries = [
            {
                "slot":      e["slot"],
                "offset":    e["offset"],
                "func_ea":   hex(e["func_ea"]),
                "func_name": e["func_name"],
            }
            for e in vt.get("entries", [])
        ]
        vtable_list.append({
            "ea":          hex(vt["ea"]),
            "name":        vt["name"],
            "entries":     entries,
            "num_methods": vt["num_methods"],
            "from_rtti":   vt.get("from_rtti", False),
        })
    return {"type": "vtables_result", "vtables": vtable_list}


def _rename_vtable(cmd: dict) -> dict:
    ea   = int(cmd["ea"], 16)
    name = cmd.get("winner_name", "")
    rename_vtable_if_anonymous(ea, name)
    return {"type": "ack"}


def _request_output_directory(cmd: dict) -> dict:
    """Pop a directory chooser dialog and return the chosen path.

    Sent by the source-reconstruction engine between planning and
    implementation. Returns {"type": "string_result", "value": <path or "">}.
    Empty value indicates the user cancelled.

    The chosen directory is also remembered on the client side as the sandbox
    base for subsequent write_file / compile_project commands.
    """
    from .compat.qt import QtWidgets, QtCore

    # Each request establishes a new filesystem capability. Cancelling must
    # revoke any directory retained from an earlier reconstruction.
    _set_output_directory("")
    project_name = cmd.get("message", "reconstructed_project")

    dlg = QtWidgets.QFileDialog(
        None,
        f"Choose output directory for reconstructed source ({project_name})",
    )
    dlg.setFileMode(QtWidgets.QFileDialog.Directory)
    dlg.setOption(QtWidgets.QFileDialog.ShowDirsOnly, True)
    dlg.setWindowFlags(dlg.windowFlags() | QtCore.Qt.WindowStaysOnTopHint)

    if dlg.exec() == QtWidgets.QDialog.Accepted:
        selected = dlg.selectedFiles()
        path = selected[0] if selected else ""
    else:
        path = ""

    if path:
        _set_output_directory(path)

    return {"type": "string_result", "value": path}


# ─── Source-reconstruction: file shipping + local build ─────────────────────

def _read_file(cmd: dict) -> dict:
    """Read a file from the output directory and return its content.

    Used by the project implementation agent to inspect a file it wrote
    earlier so it can revise it (read → modify → write_file).
    """
    rel = cmd.get("path", "")

    target = _resolve_under_outdir(rel)
    if target is None:
        if not _OUTPUT_DIR:
            return {"type": "error_result", "error": "no output directory selected"}
        return {"type": "error_result", "error": f"refusing unsafe path: {rel!r}"}

    try:
        if os.path.getsize(target) > _MAX_SOURCE_FILE_BYTES:
            return {
                "type": "error_result",
                "error": f"file exceeds {_MAX_SOURCE_FILE_BYTES} byte read limit",
            }
        with open(target, "r", encoding="utf-8") as f:
            content = f.read(_MAX_SOURCE_FILE_BYTES + 1)
        if len(content.encode("utf-8")) > _MAX_SOURCE_FILE_BYTES:
            return {
                "type": "error_result",
                "error": f"file exceeds {_MAX_SOURCE_FILE_BYTES} byte read limit",
            }
    except FileNotFoundError:
        return {"type": "error_result", "error": f"file not found: {rel!r}"}
    except Exception as e:
        return {"type": "error_result", "error": f"read failed: {e}"}

    return {"type": "string_result", "value": content}


def _list_files(_cmd: dict) -> dict:
    """List all files in the output directory (recursive, build/ excluded).

    Returns relative paths sorted alphabetically. Used by the project agent
    to survey which files have been written so far.
    """
    if not _OUTPUT_DIR:
        return {"type": "error_result", "error": "no output directory selected"}

    base = os.path.normpath(_OUTPUT_DIR)
    files: list[str] = []
    try:
        for root, dirs, filenames in os.walk(base):
            # Skip cmake build artefact directory.
            dirs[:] = [d for d in dirs if d != "build"]
            for filename in filenames:
                if len(files) >= _MAX_LISTED_FILES:
                    return {
                        "type": "error_result",
                        "error": f"project exceeds {_MAX_LISTED_FILES} file listing limit",
                    }
                abs_path = os.path.join(root, filename)
                rel = os.path.relpath(abs_path, base).replace(os.sep, "/")
                files.append(rel)
    except Exception as e:
        return {"type": "error_result", "error": f"list failed: {e}"}

    return {"type": "files_result", "files": sorted(files)}


def _write_file(cmd: dict) -> dict:
    """Write a source file (or CMakeLists.txt) under the output directory.

    All paths are sandboxed via _resolve_under_outdir to prevent the server
    from writing outside the user-approved directory.
    """
    rel = cmd.get("path", "")
    content = cmd.get("content", "")
    if not isinstance(content, str):
        return {"type": "error_result", "error": "file content must be text"}
    if len(content.encode("utf-8")) > _MAX_SOURCE_FILE_BYTES:
        return {
            "type": "error_result",
            "error": f"file exceeds {_MAX_SOURCE_FILE_BYTES} byte write limit",
        }

    target = _resolve_under_outdir(rel)
    if target is None:
        if not _OUTPUT_DIR:
            return {"type": "error_result", "error": "no output directory selected"}
        return {"type": "error_result", "error": f"refusing unsafe path: {rel!r}"}

    temp_path = ""
    try:
        parent = os.path.dirname(target) or _OUTPUT_DIR
        os.makedirs(parent, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", delete=False,
            dir=parent, prefix=".decompile-write-", suffix=".tmp",
        ) as f:
            temp_path = f.name
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, target)
        temp_path = ""
    except Exception as e:
        return {"type": "error_result", "error": f"write failed: {e}"}
    finally:
        if temp_path:
            try:
                os.unlink(temp_path)
            except OSError:
                pass

    return {"type": "ack"}


# Standard headers always prepended to the syntax-check temp file. The shim
# (which comes from the server) builds on top of these.
_SYNTAX_CHECK_PREAMBLE = (
    "#include <cstdint>\n"
    "#include <cstddef>\n"
    "#include <cstring>\n"
    "#include <cstdio>\n"
    "#include <cstdlib>\n"
    "#include <string>\n"
    "#include <vector>\n"
    "#include <memory>\n"
    "#include <utility>\n"
)


def _find_clang() -> str | None:
    """Look up a clang++ executable on PATH. Returns None if not present."""
    for name in ("clang++", "clang++-18", "clang++-17", "clang++-16", "clang++-15"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _filter_clang_errors(raw: str, src_path: str) -> str:
    """Trim clang output to lines for the user's body, anonymising the temp path."""
    keep = []
    for line in raw.splitlines():
        if (
            ": error:" in line
            or ": fatal error:" in line
            or ": warning:" in line
            or line.startswith(" ")
            or line.startswith("\t")
        ):
            keep.append(line.replace(src_path, "<your-output>"))
    if not keep:
        return raw.strip()
    return "\n".join(keep)


def _syntax_check(cmd: dict) -> dict:
    """Run `clang++ -fsyntax-only` against a single function body + shim.

    Used by the per-function REPL in the server's implementer. Returns
    {"type": "string_result", "output": <errors or "">}.

    If clang isn't installed, returns empty output (fail-open). The
    project-level compile pass will surface the issue later if needed.
    """
    shim = cmd.get("shim", "")
    body = cmd.get("body", "")

    clang = _find_clang()
    if not clang:
        return {"type": "string_result", "output": ""}

    src = _SYNTAX_CHECK_PREAMBLE + shim + "\n\n" + body + "\n"

    tmp = tempfile.NamedTemporaryFile(
        prefix="ida-syntax-", suffix=".cpp",
        mode="w", encoding="utf-8", delete=False,
    )
    try:
        tmp.write(src)
        tmp.close()
        result = subprocess.run(
            [clang, "-fsyntax-only", "-std=c++17",
             "-Wno-everything", "-fno-color-diagnostics", tmp.name],
            capture_output=True, text=True, timeout=30,
        )
    except subprocess.TimeoutExpired:
        return {"type": "string_result", "output": ""}
    except Exception as e:
        return {"type": "string_result", "output": f"syntax_check infra error: {e}"}
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

    if result.returncode == 0:
        return {"type": "string_result", "output": ""}
    errors = _filter_clang_errors((result.stdout or "") + (result.stderr or ""), tmp.name)
    return {"type": "string_result", "output": errors}


def _compile_project(_cmd: dict) -> dict:
    """Run `cmake` configure + build inside <output_dir>/build.

    On failure, scans the output for file paths and reads the current content
    of every file the compiler complained about — server uses these directly
    in FixCompilationErrors without another round-trip.
    """
    if not _OUTPUT_DIR:
        return {
            "type":    "compile_result",
            "success": False,
            "output":  "no output directory selected on client",
        }

    cmake = shutil.which("cmake")
    if not cmake:
        return {
            "type":    "compile_result",
            "success": False,
            "output":  "cmake not found on client PATH",
        }

    approved, approval_message = _approve_project_build()
    if not approved:
        return {
            "type": "compile_result",
            "success": False,
            "output": approval_message,
        }

    build_dir = os.path.join(_OUTPUT_DIR, "build")
    try:
        os.makedirs(build_dir, exist_ok=True)
    except Exception as e:
        return {
            "type":    "compile_result",
            "success": False,
            "output":  f"could not create build dir: {e}",
        }

    config_args = [cmake, "..", "-DCMAKE_BUILD_TYPE=Debug"]
    clang = _find_clang()
    if clang:
        config_args.append(f"-DCMAKE_CXX_COMPILER={clang}")

    def _run(args: list[str]) -> tuple[int, str]:
        try:
            r = subprocess.run(
                args, cwd=build_dir,
                capture_output=True, text=True, timeout=300,
            )
            output = (r.stdout or "") + (r.stderr or "")
            if len(output) > _MAX_BUILD_OUTPUT_CHARS:
                output = (
                    output[:_MAX_BUILD_OUTPUT_CHARS]
                    + "\n[build output truncated by client]"
                )
            return r.returncode, output
        except subprocess.TimeoutExpired:
            return 124, "timeout"
        except Exception as e:
            return 1, f"subprocess error: {e}"

    cfg_rc, cfg_out = _run(config_args)
    if cfg_rc != 0:
        return {"type": "compile_result", "success": False, "output": cfg_out}

    build_rc, build_out = _run([cmake, "--build", ".", "--parallel"])
    combined = cfg_out + "\n" + build_out
    if build_rc == 0:
        return {"type": "compile_result", "success": True, "output": combined}

    # Collect current content of every file mentioned in error lines.
    error_files: dict[str, str] = {}
    base = os.path.realpath(_OUTPUT_DIR)
    for line in combined.splitlines():
        if ": error:" not in line and ": fatal error:" not in line:
            continue
        match = re.match(
            r"^(.*?):\d+(?::\d+)?:\s+(?:fatal\s+)?error:",
            line,
        )
        if not match:
            continue
        reported_path = match.group(1)
        if not os.path.isabs(reported_path):
            reported_path = os.path.join(build_dir, reported_path)
        rel = os.path.relpath(
            os.path.realpath(reported_path),
            base,
        ).replace(os.sep, "/")
        abs_path = _resolve_under_outdir(rel)
        if abs_path is None:
            continue
        if rel in error_files:
            continue
        try:
            if os.path.getsize(abs_path) > _MAX_SOURCE_FILE_BYTES:
                continue
            with open(abs_path, "r", encoding="utf-8") as f:
                error_files[rel] = f.read(_MAX_SOURCE_FILE_BYTES + 1)
        except (OSError, UnicodeError):
            pass

    return {
        "type":        "compile_result",
        "success":     False,
        "output":      combined,
        "error_files": error_files,
    }


def _chat_suggest_deeper(cmd: dict) -> dict:
    """Show a dialog asking the user which functions to re-analyse.

    `cmd["functions"]` is a list of {ea, name, reason} objects sent by the
    server.  Returns {"type": "ack", "approved": [ea, ...]} containing the
    EAs the user approved (empty list means "skip re-analysis").
    """
    from .compat.qt import QtWidgets, QtCore

    functions = cmd.get("functions") or []
    if not functions:
        return {"type": "ack", "approved": []}

    dlg = QtWidgets.QDialog()
    dlg.setWindowTitle("Deeper Analysis Suggested")
    dlg.setWindowFlags(QtCore.Qt.Dialog | QtCore.Qt.WindowStaysOnTopHint)
    dlg.setMinimumWidth(480)

    lay = QtWidgets.QVBoxLayout(dlg)
    lay.setSpacing(10)

    intro = QtWidgets.QLabel(
        "The AI suggests re-analysing the following functions to give a more "
        "precise answer to your question.\n\n"
        "Select which to include (this may take a moment):"
    )
    intro.setWordWrap(True)
    lay.addWidget(intro)

    checkboxes: list = []
    for fn in functions:
        name   = fn.get("name", "") or fn.get("ea", "")
        reason = fn.get("reason", "")
        label  = f"{name}  —  {reason}" if reason else name
        chk    = QtWidgets.QCheckBox(label)
        chk.setChecked(True)
        chk.setProperty("ea", fn.get("ea", ""))
        lay.addWidget(chk)
        checkboxes.append(chk)

    btn_row = QtWidgets.QHBoxLayout()
    btn_row.addStretch(1)
    btn_skip = QtWidgets.QPushButton("Skip re-analysis")
    btn_ok   = QtWidgets.QPushButton("Re-analyse selected")
    btn_ok.setDefault(True)
    btn_ok.setStyleSheet("font-weight: bold;")
    btn_row.addWidget(btn_skip)
    btn_row.addWidget(btn_ok)
    lay.addLayout(btn_row)

    btn_skip.clicked.connect(dlg.reject)
    btn_ok.clicked.connect(dlg.accept)

    if dlg.exec() == QtWidgets.QDialog.Accepted:
        approved = [chk.property("ea") for chk in checkboxes if chk.isChecked()]
    else:
        approved = []

    return {"type": "ack", "approved": approved}


def _ack(_cmd: dict) -> dict:
    return {"type": "ack"}


def _unknown(cmd: dict) -> dict:
    command_type = str(cmd.get("type", "") or "<missing>")
    return {
        "type": "error_result",
        "error": f"Unsupported client command: {command_type[:128]}",
    }


def _build_configuration_fingerprint() -> str | None:
    """Hash executable CMake configuration under the approved output folder."""
    if not _OUTPUT_DIR:
        return None
    base = os.path.realpath(_OUTPUT_DIR)
    files: list[tuple[str, str]] = []
    for root, dirs, filenames in os.walk(base):
        dirs[:] = [name for name in dirs if name != "build"]
        for filename in filenames:
            if filename != "CMakeLists.txt" and not filename.endswith(".cmake"):
                continue
            absolute = os.path.join(root, filename)
            relative = os.path.relpath(absolute, base).replace(os.sep, "/")
            resolved = _resolve_under_outdir(relative)
            if resolved is None:
                return None
            files.append((relative, resolved))

    digest = hashlib.sha256()
    total_bytes = 0
    for relative, absolute in sorted(files):
        try:
            size = os.path.getsize(absolute)
        except OSError:
            return None
        total_bytes += size
        if total_bytes > _MAX_BUILD_CONFIG_BYTES:
            return None
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        try:
            with open(absolute, "rb") as source:
                while chunk := source.read(64 * 1024):
                    digest.update(chunk)
        except OSError:
            return None
        digest.update(b"\0")
    return digest.hexdigest()


def _approve_project_build() -> tuple[bool, str]:
    """Require consent whenever executable CMake configuration changes."""
    global _BUILD_APPROVED_FINGERPRINT, _BUILD_DENIED_FINGERPRINT

    fingerprint = _build_configuration_fingerprint()
    if fingerprint is None:
        return False, "could not safely inspect the generated CMake configuration"
    if fingerprint == _BUILD_APPROVED_FINGERPRINT:
        return True, ""
    if fingerprint == _BUILD_DENIED_FINGERPRINT:
        return False, "build was declined by the user"

    from .compat.qt import QtWidgets

    message = (
        "The generated CMake configuration can execute commands on this computer.\n\n"
        f"Review the generated files in:\n{_OUTPUT_DIR}\n\n"
        "Run CMake configure and build now?"
    )
    answer = QtWidgets.QMessageBox.question(
        None,
        "Run generated build configuration?",
        message,
        QtWidgets.QMessageBox.StandardButton.Yes
        | QtWidgets.QMessageBox.StandardButton.No,
        QtWidgets.QMessageBox.StandardButton.No,
    )
    if answer == QtWidgets.QMessageBox.StandardButton.Yes:
        _BUILD_APPROVED_FINGERPRINT = fingerprint
        _BUILD_DENIED_FINGERPRINT = ""
        return True, ""

    _BUILD_DENIED_FINGERPRINT = fingerprint
    return False, "build was declined by the user"


_DISPATCH = {
    "get_function_code":        _get_function_code,
    "get_function_global_values": _get_function_global_values,
    "get_function_pseudocode":  _get_function_pseudocode,
    "get_function_disassembly": _get_function_disassembly,
    "get_function_name":        _get_function_name,
    "find_function_by_name":    _find_function_by_name,
    "get_bytes":                _get_bytes,
    "get_value_from_name":      _get_value_from_name,
    "get_data_batch":           _get_data_batch,
    "rename_function":          _rename_function,
    "rename_lvar":              _rename_lvar,
    "rename_lvars":             _rename_lvars,
    "rename_params":            _rename_params,
    "rename_global":            _rename_global,
    "find_string_xrefs":        _find_string_xrefs,
    "get_all_structs":          _get_all_structs,
    "create_struct":            _create_struct,
    "modify_struct":            _modify_struct,
    "replace_struct":           _replace_struct,
    "set_comment":              _set_comment,
    "set_address_comment":      _set_address_comment,
    "find_vcall_sites":         _find_vcall_sites,
    "mark_cfunc_dirty":         _mark_cfunc_dirty,
    "scan_vtables":             _scan_vtables,
    "scan_exports":             _scan_exports,
    "rename_vtable":            _rename_vtable,
    "chat_suggest_deeper":      _chat_suggest_deeper,
    "get_call_tree":            _get_call_tree,
    "request_output_directory": _request_output_directory,
    # Source-reconstruction: client-side filesystem + build
    "write_file":               _write_file,
    "read_file":                _read_file,
    "list_files":               _list_files,
    "syntax_check":             _syntax_check,
    "compile_project":          _compile_project,
}
