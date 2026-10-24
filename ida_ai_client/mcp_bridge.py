"""Private loopback bridge used when Granite launches this IDA instance."""

from __future__ import annotations

import json
import os
import threading
import time
from urllib.parse import quote, urlsplit

import requests

from .executor import execute
from .ida.sync import run_on_main
from .mcp_activity import ActivitySender, install_native_hooks, run_native

_ENDPOINT_ENV = "GRANITE_MCP_ENDPOINT"
_TOKEN_ENV = "GRANITE_MCP_TOKEN"
_TARGET_ENV = "GRANITE_TARGET_ID"
_BINARY_ENV = "GRANITE_BINARY_PATH"


class GraniteBridge:
    def __init__(
        self,
        endpoint: str,
        token: str,
        target_id: str,
        binary_path: str = "",
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.token = token
        self.target_id = target_id
        self.binary_path = binary_path
        self._stop = threading.Event()
        self._shutdown_lock = threading.Lock()
        self._stopped = False
        self._commands_lock = threading.Lock()
        self._commands = {}
        self._activity_sender = None
        self._startup_lock = threading.Lock()
        self._startup_sequence = 0
        self._startup_enabled = threading.Event()
        self._startup_latest = ""
        self._startup_hooks = []
        self._startup_cleanup_scheduled = False
        self._thread = threading.Thread(
            target=self._run,
            name=f"granite-mcp-{target_id}",
            daemon=True,
        )
        self._http = self._new_http_session()

    def _new_http_session(self) -> requests.Session:
        session = requests.Session()
        session.trust_env = False
        session.headers.update(
            {
                "Authorization": f"Bearer {self.token}",
                "User-Agent": "granite-ida-bridge/1",
                "Cache-Control": "no-store",
            }
        )
        return session

    def start(self) -> None:
        # Plugin initialization is already on IDA's main thread. Install before
        # execute_sync(MFF_WRITE) can queue behind the initial autoanalysis.
        self._startup_hooks = install_native_hooks(self._record_startup_activity)
        self._thread.start()

    def _record_startup_activity(self, message):
        if self._startup_enabled.is_set():
            self._startup_activity(message)
        else:
            self._startup_latest = message

    def _finish_startup_hooks(self, _command):
        with self._startup_lock:
            hooks, self._startup_hooks = self._startup_hooks, []
        for hook in hooks:
            hook.unhook()

    def _schedule_startup_cleanup(self):
        with self._startup_lock:
            if not self._startup_hooks or self._startup_cleanup_scheduled:
                return
            self._startup_cleanup_scheduled = True
        # Never wait here: plugin stop can itself run on the main thread and
        # join this worker before execute_sync is admitted.
        threading.Thread(target=lambda: run_on_main(self._finish_startup_hooks, {}),
                         daemon=True, name="granite-startup-hooks-cleanup").start()

    def stop(self) -> None:
        with self._shutdown_lock:
            if self._stopped:
                return
            self._stop.set()
            if threading.current_thread() is threading.main_thread():
                self._finish_startup_hooks({})
            else:
                self._schedule_startup_cleanup()
            with self._commands_lock:
                for handle in self._commands.values():
                    handle["cancel"].set()
            self._notify_disconnect()
            if threading.current_thread() is not self._thread:
                self._thread.join()
            self._stopped = True

    def _notify_disconnect(self) -> None:
        session = requests.Session()
        session.trust_env = False
        try:
            session.post(
                self._target_url("disconnect"),
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "User-Agent": "granite-ida-bridge/1",
                    "Cache-Control": "no-store",
                },
                timeout=(1, 2),
                allow_redirects=False,
            )
        except requests.RequestException:
            pass
        finally:
            session.close()

    def _target_url(self, suffix: str) -> str:
        target = quote(self.target_id, safe="")
        return f"{self.endpoint}/bridge/v1/targets/{target}/{suffix}"

    def _run(self) -> None:
        try:
            startup_supported = self._begin_startup()
            if startup_supported:
                self._startup_enabled.set()
                if self._startup_latest:
                    self._startup_activity(self._startup_latest)
                threading.Thread(target=self._startup_control, daemon=True, name="granite-startup-control").start()
                def report_startup(payload):
                    self._startup_activity(str(payload.get("detail") or "Autoanalysis progress"), state=payload.get("state", ""))
                registration = run_native(_prepare_registration, {"id": "startup", "operation_id": self.target_id},
                                          self._stop, report_startup, threading.Event())
                self._startup_activity("Validating target metadata")
            else:
                registration = run_on_main(_prepare_registration, {})
            launch_path = (
                os.path.realpath(self.binary_path) if self.binary_path else ""
            )
            if launch_path:
                registration["binary_path"] = launch_path
            registration["binary_sha256"] = _sha256_file(
                str(registration.get("binary_path") or ""),
                (lambda count: self._startup_activity(f"Validated {count} binary bytes")) if startup_supported else None,
            )
            registration["adapter"] = "ida"
            registration["pid"] = os.getpid()
            self._register(registration)
            if self._activity_sender is not None:
                self._activity_sender.retire("startup")
            if self._startup_hooks:
                run_on_main(self._finish_startup_hooks, {})
            self._command_loop()
        except Exception as exc:
            if not self._stop.is_set():
                self._notify_disconnect()
                print(f"[Granite] MCP bridge stopped: {exc}")
        finally:
            self._schedule_startup_cleanup()
            if self._activity_sender is not None:
                self._activity_sender.close()
            self._http.close()

    def _begin_startup(self):
        payload = {"sequence": 1, "operation_id": self.target_id, "pid": os.getpid(),
                   "phase": "plugin_connected", "message": "Granite plugin connected"}
        try:
            response = self._http.post(self._target_url("startup"), json=payload,
                                       timeout=(2, 3), allow_redirects=False)
            if response.status_code == 404:
                return False
            response.raise_for_status()
            capabilities = response.json().get("capabilities") or []
            self._startup_sequence = 1
            return "startup_progress_v1" in capabilities
        except requests.RequestException:
            # Registration retains its bounded retry policy for older/offline Managers.
            return False

    def _startup_activity(self, message, state=""):
        with self._startup_lock:
            self._startup_sequence += 1
            payload = {"sequence": self._startup_sequence, "operation_id": self.target_id,
                       "pid": os.getpid(), "phase": "autoanalysis", "message": message,
                       "state": state}
        self._sender().submit("startup", self._send_startup, payload)

    def _send_startup(self, payload):
        http = self._new_http_session()
        try:
            response = http.post(self._target_url("startup"), json=payload,
                                 timeout=(2, 3), allow_redirects=False)
            if response.status_code not in (200, 404, 410):
                response.raise_for_status()
        finally:
            http.close()

    def _startup_control(self):
        http = self._new_http_session()
        try:
            while not self._stop.is_set():
                try:
                    response = http.get(self._target_url("startup/control"), timeout=(3, 25), allow_redirects=False)
                    if response.status_code in (404, 410):
                        return
                    if response.status_code == 204:
                        continue
                    response.raise_for_status()
                    payload = response.json()
                    if payload.get("status") == "ready":
                        return
                    if payload.get("action") == "close":
                        self._stop.set()
                        run_on_main(_close_unfinished_target, {})
                        return
                except requests.RequestException:
                    self._stop.wait(0.5)
        finally:
            http.close()

    def _register(self, registration: dict) -> None:
        deadline = time.monotonic() + 60
        while not self._stop.is_set():
            try:
                response = self._http.post(
                    self._target_url("register"),
                    json=registration,
                    timeout=(3, 10),
                    allow_redirects=False,
                )
                if response.status_code == 200:
                    return
                if response.status_code in (401, 404, 409, 410):
                    reason = response.text.strip()
                    detail = f": {reason}" if reason else ""
                    raise RuntimeError(
                        "registration rejected with HTTP "
                        f"{response.status_code}{detail}"
                    )
            except requests.RequestException:
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("manager did not accept target registration")
            self._stop.wait(0.5)
        raise RuntimeError("bridge stopped before registration")

    def _command_loop(self) -> None:
        while not self._stop.is_set():
            try:
                response = self._http.get(
                    self._target_url("next"),
                    timeout=(3, 25),
                    allow_redirects=False,
                )
            except requests.RequestException:
                self._stop.wait(0.5)
                continue
            if self._stop.is_set():
                return
            if response.status_code == 204:
                continue
            if response.status_code in (404, 410):
                return
            response.raise_for_status()
            command = response.json()
            if not isinstance(command, dict):
                raise RuntimeError("manager returned an invalid command")
            command_id = str(command.get("id") or "")
            if not command_id:
                raise RuntimeError("manager command omitted its ID")
            if command.get("type") == "granite_cancel_command":
                result = self._cancel_command(str(command.get("operation_command_id") or ""))
                result["command_id"] = command_id
                self._post_result(self._http, command_id, result)
                continue
            self._start_reverse_command(command, command_id)

    def _start_reverse_command(
        self,
        command: dict,
        command_id: str,
    ) -> None:
        handle = {"cancel": threading.Event(), "done": threading.Event(),
                  "native_active": threading.Event(), "session": None,
                  "progress_sequence": 0, "last_backend_sequence": 0, "operation_id": "",
                  "session_start_pending": command.get("type") == "granite_reverse_functions"}
        with self._commands_lock:
            if command_id in self._commands:
                return
            self._commands[command_id] = handle
        command = dict(command, _handle=handle)
        threading.Thread(
            target=self._run_reverse_command,
            args=(command, command_id),
            name=f"granite-reverse-{command_id}",
            daemon=True,
        ).start()

    def _run_reverse_command(self, command: dict, command_id: str) -> None:
        try:
            result = dict(self._execute(command))
        except Exception as exc:
            result = {"type": "error_result", "error": str(exc)}
        result.setdefault("command_id", command_id)
        http = self._new_http_session()
        try:
            self._post_result(http, command_id, result)
        except Exception as exc:
            if not self._stop.is_set():
                print(
                    "[Granite] Failed to return concurrent reversal "
                    f"{command_id}: {exc}"
                )
        finally:
            http.close()
            handle = command.get("_handle")
            if handle:
                handle["done"].set()
            with self._commands_lock:
                self._commands.pop(command_id, None)
            if self._activity_sender is not None:
                self._activity_sender.retire("manager:" + command_id)

    def _post_result(
        self,
        http: requests.Session,
        command_id: str,
        result: dict,
    ) -> None:
        posted = http.post(
            self._target_url(f"results/{quote(command_id, safe='')}"),
            json=result,
            timeout=(3, 30),
            allow_redirects=False,
        )
        if posted.status_code not in (200, 404):
            posted.raise_for_status()

    def _execute(self, command: dict) -> dict:
        command_type = str(command.get("type") or "")
        handle = command.get("_handle")
        if command_type == "granite_reverse_functions":
            return self._reverse_functions(command.get("targets") or [], handle, str(command.get("id") or ""))
        function = {"granite_resolve_memory_region": _resolve_memory_region,
                    "granite_read_memory": _read_memory,
                    "granite_search_byte_pattern": _search_byte_pattern,
                    "granite_resolve_pseudocode_location": _resolve_pseudocode_location,
                    "granite_close_target": _close_target}.get(command_type, execute)
        if command.get("progress") and handle:
            command_id = str(command.get("id") or "")
            def report(activity):
                payload = dict(activity, message=activity.pop("detail", ""))
                self._enqueue_activity(command_id, payload)
            return run_native(function, command, handle["cancel"], report, handle["native_active"])
        return run_on_main(function, command)

    def _sender(self):
        with self._commands_lock:
            if self._activity_sender is None:
                self._activity_sender = ActivitySender()
            return self._activity_sender

    def _enqueue_activity(self, command_id, payload):
        self._sender().submit("manager:" + command_id,
                              lambda value: self._post_activity(command_id, value), payload)

    def _post_activity(self, command_id, payload):
        http = self._new_http_session()
        try:
            response = http.post(self._target_url("activity/" + quote(command_id, safe="")),
                                 json=payload, timeout=(2, 3), allow_redirects=False)
            if response.status_code not in (200, 404):
                response.raise_for_status()
        finally:
            http.close()

    def _cancel_command(self, command_id):
        with self._commands_lock:
            handle = self._commands.get(command_id)
            if handle:
                handle["cancel"].set()
                session = handle["session"]
                creation_pending = bool(handle.get("session_start_pending"))
        if not handle:
            return {"accepted": False, "backend_stopped": False, "native_running": None, "unknown_command": True}
        outcome = {"accepted": True, "stopped": session is None and not creation_pending}
        if session is not None and not creation_pending:
            try:
                outcome = session.cancel_operation_with_outcome()
            except Exception as error:
                outcome = {"accepted": False, "stopped": False, "error": str(error)}
        return {"accepted": bool(outcome.get("accepted")),
                "backend_stopped": bool(outcome.get("stopped")) and not creation_pending,
                "creation_pending": creation_pending,
                "native_running": handle["native_active"].is_set(),
                "cancellation_error": outcome.get("error", ""),
                "limited_progress_support": bool(outcome.get("limited")) or (session is not None and "native_command_activity_v1" not in getattr(session, "capabilities", set()))}

    def _reverse_functions(self, targets: list[dict], handle=None, command_id="") -> dict:
        from .config import g_settings
        from .ui.worker import create_authenticated_server_session

        if handle is not None and handle["cancel"].is_set():
            raise RuntimeError("Recursive reversal canceled before backend session creation")
        session = create_authenticated_server_session()
        if handle is None:
            handle = {"cancel": self._stop, "native_active": threading.Event(), "session": session,
                      "progress_sequence": 0, "last_backend_sequence": 0, "operation_id": ""}
        else:
            with self._commands_lock:
                handle["session"] = session
        completed = False
        try:
            session.start_reverse_functions(
                targets=targets,
                model_tier=g_settings.get("model_tier", "fast"),
                agent_reasoning_level=g_settings.get(
                    "agent_reasoning_level", "high"
                ),
                auto_renames=bool(g_settings.get("auto_renames", True)),
                auto_types=bool(g_settings.get("auto_types", True)),
                auto_structs=bool(g_settings.get("auto_structs", True)),
                rename_style=g_settings.get("rename_style", "snake_case"),
                struct_member_style=g_settings.get(
                    "struct_member_style", "default"
                ),
                max_call_depth=int(g_settings.get("max_call_depth", 0)),
                guess_virtual_function_calls=bool(
                    g_settings.get("guess_virtual_function_calls", False)
                ),
                decompiler="ida",
            )
            with self._commands_lock:
                handle["session_start_pending"] = False
            while not self._stop.is_set() and not handle["cancel"].is_set():
                for server_command in session.next_command():
                    sequence = int(server_command.get("sequence") or 0)
                    if sequence and sequence <= handle["last_backend_sequence"]:
                        continue
                    handle["last_backend_sequence"] = sequence
                    if server_command.get("type") == "reversal_activity":
                        activity = server_command.get("reversal_activity") or {}
                        operation_id = str(activity.get("operation_id") or "")
                        if operation_id and (not handle["operation_id"] or handle["operation_id"] == operation_id):
                            handle["operation_id"] = operation_id
                            handle["progress_sequence"] += 1
                            self._enqueue_activity(command_id, {"sequence": handle["progress_sequence"], "operation_id": operation_id,
                                "phase": activity.get("phase", ""), "message": str(activity.get("label") or "Analysis progress") + (": " + str(activity["detail"]) if activity.get("detail") else ""), "counts": activity.get("counts") or {}})
                    if server_command.get("needs_result") is True:
                        native_id = str(server_command.get("id") or "")
                        try:
                            def report_native(payload, native_id=native_id):
                                if "native_command_activity_v1" in getattr(session, "capabilities", set()):
                                    self._sender().submit("backend:" + native_id, lambda value: session.post_command_activity(native_id, value), payload)
                            result = run_native(execute, server_command, handle["cancel"], report_native, handle["native_active"])
                            result = dict(result)
                        except Exception as error:
                            result = {"type": "error_result", "error": str(error)}
                        if handle["cancel"].is_set():
                            raise RuntimeError("Recursive reversal canceled")
                        result.setdefault("command_id", native_id)
                        session.post_result(native_id, result)
                        if self._activity_sender is not None:
                            self._activity_sender.retire("backend:" + native_id)
                    session.commit_sequence(sequence)
                    command_type = str(server_command.get("type") or "")
                    if command_type == "done":
                        report = server_command.get("report") or "{}"
                        parsed = json.loads(report)
                        if not isinstance(parsed, dict):
                            raise RuntimeError(
                                "reverse_functions returned an invalid result"
                            )
                        completed = True
                        return {
                            "type": "granite_reverse_functions_result",
                            "result": parsed,
                        }
                    if command_type in {"error", "operation_interrupted"}:
                        raise RuntimeError(
                            str(
                                server_command.get("message")
                                or server_command.get("report")
                                or "recursive reversal failed"
                            )
                        )
            raise RuntimeError("Granite bridge stopped during recursive reversal")
        finally:
            if not completed:
                try:
                    session.cancel_operation_with_outcome()
                except Exception:
                    pass
                session.cancel()
            session.close()


def _close_unfinished_target(_command):
    # Readiness was never committed. Avoid initiating a potentially long save
    # before Manager's bounded launch-cleanup termination window.
    import ida_pro
    ida_pro.qexit(0)


def _prepare_registration(_command: dict) -> dict:
    import ida_auto
    import ida_ida
    import ida_nalt

    try:
        ida_auto.auto_wait()
    finally:
        _restore_interactive_mode()
    processor = ""
    try:
        processor = str(ida_ida.inf_get_procname() or "")
    except Exception:
        pass
    input_path = str(ida_nalt.get_input_file_path() or "")
    image_base = None
    minimum = 0
    maximum = 0
    try:
        image_base = int(ida_nalt.get_imagebase())
        minimum = int(ida_ida.inf_get_min_ea())
        maximum = int(ida_ida.inf_get_max_ea())
    except Exception:
        pass
    return {
        "binary_path": os.path.realpath(input_path) if input_path else "",
        "display_name": ida_nalt.get_root_filename() or "IDA database",
        "architecture": processor,
        "idb_image_base": hex(image_base) if image_base is not None else "",
        "idb_min_address": hex(minimum) if minimum else "",
        "idb_max_address": hex(maximum) if maximum else "",
        "capabilities": [
            "analysis",
            "memory",
            "recursive_reversal",
            "byte_pattern_search",
            "pseudocode_location_resolution",
            "command_progress_v1",
            "command_cancellation_v1",
        ],
    }


def _restore_interactive_mode() -> None:
    import idc

    idc.batch(0)


def _sha256_file(path: str, on_chunk=None) -> str:
    import hashlib

    if not path:
        return ""
    try:
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            count = 0
            for chunk in iter(lambda: source.read(1 << 20), b""):
                digest.update(chunk)
                count += len(chunk)
                if on_chunk is not None:
                    on_chunk(count)
        return digest.hexdigest()
    except OSError:
        return ""


def _resolve_pseudocode_location(command: dict) -> dict:
    import ida_bytes
    import ida_funcs
    import ida_hexrays
    import ida_lines
    import idaapi
    import idc

    function_text = str(command.get("function") or "").strip()
    fragment = str(command.get("text") or "")
    if not function_text or not fragment:
        raise ValueError("function and exact text are required")
    if len(fragment) > 1 << 16:
        raise ValueError("pseudocode fragment cannot exceed 65536 characters")

    try:
        function_ea = int(function_text, 16)
    except ValueError:
        function_ea = int(idc.get_name_ea_simple(function_text))
        if function_ea == idc.BADADDR:
            lower = function_text.lower()
            for prefix in ("sub_", "loc_", "nullsub_", "j_sub_"):
                if lower.startswith(prefix):
                    try:
                        function_ea = int(function_text[len(prefix) :], 16)
                    except ValueError:
                        pass
                    break
    function = ida_funcs.get_func(function_ea)
    if function is None:
        raise ValueError(f"unknown function: {function_text}")
    function_ea = int(function.start_ea)
    cfunc = ida_hexrays.decompile(function_ea)
    if cfunc is None:
        raise RuntimeError("Hex-Rays pseudocode is unavailable for this function")

    tagged_lines = [str(line.line) for line in cfunc.get_pseudocode()]
    clean_lines = [str(ida_lines.tag_remove(line)) for line in tagged_lines]
    pseudocode = "\n".join(clean_lines)
    if len(pseudocode) > 16 << 20:
        raise RuntimeError("pseudocode exceeds Granite's 16 MiB resolver limit")

    line_starts: list[int] = []
    cursor = 0
    for line in clean_lines:
        line_starts.append(cursor)
        cursor += len(line) + 1

    def position(offset: int) -> tuple[int, int]:
        import bisect

        line_index = max(0, bisect.bisect_right(line_starts, offset) - 1)
        return line_index, offset - line_starts[line_index]

    def addresses_for_span(start: int, end: int) -> list[int]:
        addresses: set[int] = set()

        def add_function_address(address: int) -> None:
            if address == idaapi.BADADDR:
                return
            containing_function = ida_funcs.get_func(address)
            if (
                containing_function is not None
                and int(containing_function.start_ea) == function_ea
            ):
                addresses.add(int(ida_bytes.get_item_head(address)))

        def add_anchor_address(tagged_line: str, clean_column: int) -> None:
            try:
                raw_end = int(ida_lines.tag_advance(tagged_line, clean_column + 1))
                marker = ida_lines.SCOLOR_ON + ida_lines.SCOLOR_ADDR
                marker_at = tagged_line.rfind(marker, 0, raw_end)
                if marker_at < 0:
                    return
                value_at = marker_at + len(marker)
                value_end = value_at + int(ida_lines.COLOR_ADDR_SIZE)
                anchor = ida_hexrays.ctree_anchor_t()
                anchor.value = int(tagged_line[value_at:value_end], 16)
                if not anchor.is_citem_anchor():
                    return
                item_index = int(anchor.get_index())
                if item_index < 0 or item_index >= len(cfunc.treeitems):
                    return
                add_function_address(int(cfunc.treeitems[item_index].ea))
            except Exception:
                return

        start_line, _ = position(start)
        end_line, _ = position(max(start, end - 1))
        for line_index in range(start_line, end_line + 1):
            line_start = line_starts[line_index]
            clean_start = max(0, start - line_start)
            clean_end = min(len(clean_lines[line_index]), end - line_start)
            if clean_end <= clean_start:
                continue
            # get_line_item() expects a visible screen coordinate, not an
            # offset into the color-tagged string. Multiple ctree items can
            # contribute to one source fragment after optimisation.
            for clean_column in range(clean_start, clean_end):
                add_anchor_address(tagged_lines[line_index], clean_column)
                try:
                    for is_ctree_line in (True, False):
                        head = ida_hexrays.ctree_item_t()
                        item = ida_hexrays.ctree_item_t()
                        tail = ida_hexrays.ctree_item_t()
                        if not cfunc.get_line_item(
                            tagged_lines[line_index],
                            clean_column,
                            is_ctree_line,
                            head,
                            item,
                            tail,
                        ):
                            continue
                        for candidate in (item, head, tail):
                            add_function_address(int(candidate.get_ea()))
                        break
                except Exception:
                    continue
        return sorted(addresses)

    def instruction_ranges(addresses: list[int]) -> list[dict[str, str]]:
        ranges: list[dict[str, int]] = []
        for address in addresses:
            try:
                end = int(ida_bytes.get_item_end(address))
            except Exception:
                end = address + 1
            if end <= address:
                end = address + 1
            if ranges and address <= ranges[-1]["end"]:
                ranges[-1]["end"] = max(ranges[-1]["end"], end)
            else:
                ranges.append({"start": address, "end": end})
        return [
            {
                "start_address": hex(item["start"]),
                "end_address": hex(item["end"]),
            }
            for item in ranges
        ]

    matches: list[dict] = []
    search_from = 0
    while True:
        match_start = pseudocode.find(fragment, search_from)
        if match_start < 0:
            break
        match_end = match_start + len(fragment)
        start_line, start_column = position(match_start)
        end_line, end_column = position(max(match_start, match_end - 1))
        end_column += 1
        addresses = addresses_for_span(match_start, match_end)
        matches.append(
            {
                "start_line": start_line + 1,
                "start_column": start_column,
                "end_line": end_line + 1,
                "end_column": end_column,
                "idb_addresses": [hex(address) for address in addresses],
                "instruction_ranges": instruction_ranges(addresses),
            }
        )
        search_from = match_start + 1

    return {
        "type": "pseudocode_location_result",
        "function": {
            "name": str(idc.get_func_name(function_ea) or function_text),
            "address": hex(function_ea),
        },
        "matches": matches,
    }


def _resolve_memory_region(command: dict) -> dict:
    import ida_bytes
    import ida_funcs
    import idc

    name = str(command.get("name") or "").strip()
    address = idc.get_name_ea_simple(name)
    if address == idc.BADADDR:
        return {"type": "error_result", "error": f"unknown name: {name}"}
    function = ida_funcs.get_func(address)
    if function is not None and int(function.start_ea) == int(address):
        size = int(function.end_ea) - int(function.start_ea)
    else:
        size = int(ida_bytes.get_item_size(address) or 0)
    if size <= 0:
        return {
            "type": "error_result",
            "error": f"could not determine the size of {name}",
        }
    return {
        "type": "memory_region_result",
        "address": hex(int(address)),
        "size": size,
    }


def _read_memory(command: dict) -> dict:
    import ida_bytes

    address = int(str(command.get("ea") or ""), 16)
    size = int(command.get("size") or 0)
    if not 1 <= size <= 1 << 20:
        raise ValueError("memory chunk size must be between 1 and 1048576 bytes")
    data = ida_bytes.get_bytes(address, size)
    return {"type": "bytes_result", "hex": bytes(data or b"").hex()}


def _compile_byte_pattern(pattern: str) -> tuple[list[int | None], int, bytes]:
    fields = str(pattern or "").split()
    if not 1 <= len(fields) <= 4096:
        raise ValueError("pattern must contain between 1 and 4096 bytes")
    tokens: list[int | None] = []
    for index, field in enumerate(fields):
        if field in {"?", "??"}:
            tokens.append(None)
            continue
        if len(field) != 2 or any(
            character not in "0123456789abcdefABCDEF" for character in field
        ):
            raise ValueError(f"invalid byte token at position {index + 1}")
        try:
            tokens.append(int(field, 16))
        except ValueError as exc:
            raise ValueError(
                f"invalid byte token at position {index + 1}"
            ) from exc

    best_start = -1
    best_length = 0
    run_start = 0
    run_length = 0
    for index, token in enumerate(tokens + [None]):
        if token is not None:
            if run_length == 0:
                run_start = index
            run_length += 1
        else:
            if run_length > best_length:
                best_start = run_start
                best_length = run_length
            run_length = 0
    if best_start < 0:
        raise ValueError("pattern must contain at least one concrete byte")
    anchor = bytes(tokens[best_start : best_start + best_length])
    return tokens, best_start, anchor


def _find_pattern_offsets(
    data: bytes,
    primary_size: int,
    tokens: list[int | None],
    anchor_offset: int,
    anchor: bytes,
):
    search_from = 0
    while True:
        anchor_match = data.find(anchor, search_from)
        if anchor_match < 0:
            return
        search_from = anchor_match + 1
        candidate = anchor_match - anchor_offset
        if candidate < 0 or candidate >= primary_size:
            continue
        if candidate + len(tokens) > len(data):
            continue
        if all(
            expected is None or data[candidate + index] == expected
            for index, expected in enumerate(tokens)
        ):
            yield candidate


def _describe_byte_pattern_match(address: int) -> dict[str, str]:
    import ida_funcs
    import idc

    result = {"address": hex(address)}
    function = ida_funcs.get_func(address)
    if function is not None:
        function_address = int(function.start_ea)
        result["function_name"] = str(
            idc.get_func_name(function_address) or f"sub_{function_address:X}"
        )
        result["function_address"] = hex(function_address)
    return result


def _search_byte_pattern(command: dict) -> dict:
    import ida_bytes
    import ida_segment
    import idc

    tokens, anchor_offset, anchor = _compile_byte_pattern(
        str(command.get("pattern") or "")
    )
    limit = int(command.get("limit") or 50)
    if not 1 <= limit <= 50:
        raise ValueError("limit must be between 1 and 50")
    start_text = str(command.get("start_address") or "").strip()
    start_address = int(start_text, 16) if start_text else None
    if start_address is not None and start_address < 0:
        raise ValueError("start_address must be a non-negative hexadecimal address")

    matches: list[dict[str, str]] = []
    segment = ida_segment.get_first_seg()

    # IDA's native compiled-pattern search is substantially faster and avoids
    # copying whole segments into Python. Keep the chunked matcher below as a
    # compatibility fallback for older IDAPython releases.
    if hasattr(ida_bytes, "find_bytes"):
        native_pattern = " ".join(
            "?" if token is None else f"{token:02X}" for token in tokens
        )
        flags = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW
        while segment is not None:
            segment_start = int(segment.start_ea)
            segment_end = int(segment.end_ea)
            cursor = max(segment_start, start_address or 0)
            while cursor < segment_end:
                match = int(
                    ida_bytes.find_bytes(
                        native_pattern,
                        cursor,
                        range_end=segment_end,
                        flags=flags,
                        radix=16,
                    )
                )
                if match == idc.BADADDR:
                    break
                matches.append(_describe_byte_pattern_match(match))
                if len(matches) > limit:
                    return {
                        "type": "byte_pattern_search_result",
                        "matches": matches[:limit],
                        "truncated": True,
                    }
                cursor = match + 1
            segment = ida_segment.get_next_seg(segment_start)
        return {
            "type": "byte_pattern_search_result",
            "matches": matches,
            "truncated": False,
        }

    chunk_size = 1 << 20
    overlap = len(tokens) - 1
    while segment is not None:
        segment_start = int(segment.start_ea)
        segment_end = int(segment.end_ea)
        cursor = max(segment_start, start_address or 0)
        while cursor < segment_end:
            primary_size = min(chunk_size, segment_end - cursor)
            read_size = min(primary_size + overlap, segment_end - cursor)
            data = ida_bytes.get_bytes(cursor, read_size)
            if data:
                raw = bytes(data)
                for offset in _find_pattern_offsets(
                    raw, primary_size, tokens, anchor_offset, anchor
                ):
                    matches.append(
                        _describe_byte_pattern_match(cursor + offset)
                    )
                    if len(matches) > limit:
                        return {
                            "type": "byte_pattern_search_result",
                            "matches": matches[:limit],
                            "truncated": True,
                        }
            cursor += primary_size
        segment = ida_segment.get_next_seg(segment_start)
    return {
        "type": "byte_pattern_search_result",
        "matches": matches,
        "truncated": False,
    }


def _close_target(_command: dict) -> dict:
    import ida_loader
    import ida_pro

    from .compat.qt import QtCore

    raw_database_path = str(
        ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or ""
    ).strip()
    if not raw_database_path:
        raise RuntimeError("IDA did not provide a database path")
    database_path = os.path.realpath(raw_database_path)
    if not ida_loader.save_database(None, 0):
        raise RuntimeError(f"failed to save IDA database: {database_path}")

    QtCore.QTimer.singleShot(250, lambda: ida_pro.qexit(0))
    return {
        "type": "close_target_result",
        "database_path": database_path,
    }


def start_bridge_if_requested() -> GraniteBridge | None:
    endpoint = os.environ.get(_ENDPOINT_ENV, "").strip()
    token = os.environ.get(_TOKEN_ENV, "").strip()
    target_id = os.environ.get(_TARGET_ENV, "").strip()
    binary_path = os.environ.get(_BINARY_ENV, "")
    for variable in (_ENDPOINT_ENV, _TOKEN_ENV, _TARGET_ENV, _BINARY_ENV):
        os.environ.pop(variable, None)
    if not endpoint and not token and not target_id:
        return None
    if not endpoint or not token or not target_id:
        print("[Granite] Incomplete MCP launch environment; bridge disabled.")
        return None
    try:
        parsed = urlsplit(endpoint)
        valid_endpoint = (
            parsed.scheme == "http"
            and parsed.hostname == "127.0.0.1"
            and parsed.port is not None
            and parsed.username is None
            and parsed.password is None
            and parsed.path in ("", "/")
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        valid_endpoint = False
    if not valid_endpoint:
        print("[Granite] Refusing non-loopback MCP bridge endpoint.")
        return None
    bridge = GraniteBridge(endpoint, token, target_id, binary_path)
    bridge.start()
    return bridge
