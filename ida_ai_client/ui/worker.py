"""
worker.py - QThread worker that runs the server polling loop.

Flow:
  1. POST /session                  -> get session_id
  2. Loop:
     a. GET  /session/{id}/next     -> receive a command
     b. If UI command (log/tree/progress/wait): emit Qt signal or skip
     c. If IDA command: run_on_main(executor.execute, cmd) -> result
     d. POST /session/{id}/result   -> send result back
     e. If done/error: emit final signal and exit
"""

from __future__ import annotations

import threading
import traceback

import requests
from ..compat.qt import QThread, Signal

from ..config import ACTIVE_DASHBOARD_URL, g_settings
from ..session import (
    ServerSession,
    AuthError,
    BillingError,
    ServerProtocolError,
    SessionStartError,
    find_shared_auth_context,
    get_shared_auth_context,
)
from ..executor import execute
from ..ida.sync import run_on_main
from .. import secret_store
from .. import fingerprint
from .. import auth_state


# Bounded exponential backoff for transient network errors. Long-running
# analyses keep retrying until the user cancels or the server rejects them.
_BACKOFF_SCHEDULE_S = (1, 2, 4, 8, 16, 32)
_UNKNOWN_RESULT_RETRY_LIMIT = len(_BACKOFF_SCHEDULE_S)
_MALFORMED_ACK_RETRY_LIMIT = 3


def _reauth_message(detail: str = "") -> str:
    message = "Authentication failed. Sign in with your browser, then try again."
    if detail:
        message = f"{message}\n\nServer response: {detail}"
    return f"{message}\n\nDashboard: {ACTIVE_DASHBOARD_URL.rstrip('/')}/app/account"


def create_authenticated_server_session(account_id: str | None = None) -> ServerSession:
    server_url = g_settings.get("server_url", "https://api.decompile.re")
    if account_id is None:
        account_id = auth_state.active_account_id()
    auth_context = find_shared_auth_context(server_url, account_id or "")
    if auth_context is not None:
        with auth_context.lock:
            refresh_token = auth_context.refresh_token
            device_fp = auth_context.device_fingerprint
        return ServerSession(
            server_url,
            refresh_token,
            device_fp,
            account_id=account_id or "",
            auth_context=auth_context,
        )
    refresh_token = (
        secret_store.load_refresh_token(account_id, server_url)
        if account_id
        else secret_store.load_refresh_token(server_url=server_url)
    )
    device_fp = fingerprint.device_fingerprint()
    auth_context = get_shared_auth_context(
        server_url,
        refresh_token,
        device_fp,
        account_id=account_id or "",
    )
    return ServerSession(
        server_url,
        refresh_token,
        device_fp,
        account_id=account_id or "",
        auth_context=auth_context,
    )


def load_session_names(account_id: str) -> list[dict]:
    session = create_authenticated_server_session(account_id)
    try:
        return session.list_history()
    finally:
        session.close()


def load_usage_percent(account_id: str) -> float:
    session = create_authenticated_server_session(account_id)
    try:
        return session.get_usage_percent()
    finally:
        session.close()


class NetworkHistorySession:
    """Account-bound handle for a server-backed history row."""

    def __init__(self, session_id: str, account_id: str | None = None):
        self.session_id = session_id
        self.account_id = account_id or auth_state.active_account_id()

    def isRunning(self) -> bool:
        return False

    def delete_history(self) -> None:
        session = create_authenticated_server_session(self.account_id)
        try:
            session.session_id = self.session_id
            session.delete_history()
        finally:
            session.close()

    def rename_history(self, name: str) -> str:
        session = create_authenticated_server_session(self.account_id)
        try:
            session.session_id = self.session_id
            return session.rename_history(name)
        finally:
            session.close()

    def load_history(self) -> dict:
        session = create_authenticated_server_session(self.account_id)
        try:
            return session.get_history(self.session_id)
        finally:
            session.close()


class AnalysisWorker(QThread):
    """Polls the Go server for commands and executes them in IDA."""

    sig_log      = Signal(str, str)  # presentation level, message
    sig_progress = Signal(str)
    sig_done     = Signal(str)
    sig_error    = Signal(str)

    # PySide6 Signal(int) maps to C++ 32-bit int — too small for 64-bit EAs.
    # Use object so Python ints are passed through unsized.
    sig_tree_node_added   = Signal(object, object, str, bool)     # parent_ea, ea, name, duplicate
    sig_tree_nodes_added  = Signal(object)                        # parsed node tuples
    sig_tree_node_updated = Signal(object, str, str, str, str)    # ea, name, status, notes, summary
    sig_chat_response     = Signal(str)                     # message from server chat response
    sig_operation_cancelled = Signal(str)                   # active agent/reversal operation stopped
    sig_operation_interrupted = Signal(str)                 # active operation failed but chat remains available
    sig_stream_start      = Signal()                        # response generation started
    sig_stream_chunk      = Signal(str)                     # incremental response delta
    sig_candidate_answer_replace = Signal(int, str)         # full mutable answer replacement
    sig_answer_final      = Signal(int)                     # mutable answer finalized
    sig_answer_preparing  = Signal()                        # final answer preparation began
    sig_agent_thinking_start = Signal()                     # report agent began gathering
    sig_agent_turn_start = Signal(int)                       # final-agent turn began
    sig_agent_turn_note = Signal(int, str)                    # visible note from a tool-agent turn
    sig_agent_reversal_note = Signal(int, str)                # tool-turn note moved into reversal activity
    sig_agent_turn_chunk = Signal(int, str)                   # live visible content from a tool-agent turn
    sig_agent_turn_end = Signal(int, str)                    # final-agent turn ended
    sig_agent_reading = Signal(object)                       # evidence read by final agent
    sig_answer_audit = Signal(object)                        # draft audit lifecycle update
    sig_reversal_activity = Signal(object)                   # structured reversal-stage activity

    def __init__(
        self,
        root_ea: int,
        user_prompt: str,
        model_tier: str = "fast",
        agent_reasoning_level: str = "high",
        current_view: dict | None = None,
    ):
        super().__init__()
        self.root_ea     = root_ea
        self.user_prompt = user_prompt
        self.model_tier  = model_tier or "fast"
        self.agent_reasoning_level = agent_reasoning_level or "high"
        self.current_view = dict(current_view or {})
        self._cancelled  = False
        self._srv: ServerSession | None = None
        self._result_cache: dict[str, dict] = {}
        self._skip_batch_sequence_commit = False
        self._cancel_thread: threading.Thread | None = None
        self._operation_cancel_thread: threading.Thread | None = None
        self._operation_cancel_requested = False

    # ── QThread entry point ───────────────────────────────────────────────────

    def run(self) -> None:
        try:
            self._run_session()
        finally:
            if self._cancel_thread is not None:
                self._cancel_thread.join(timeout=6)
            if self._operation_cancel_thread is not None:
                self._operation_cancel_thread.join(timeout=6)
            if self._srv is not None:
                self._srv.close()

    def _run_session(self) -> None:
        try:
            self._srv = create_authenticated_server_session()
        except Exception as e:
            self.sig_error.emit(f"Failed to initialize authenticated session: {e}")
            return
        if self._cancelled:
            return

        try:
            self._srv.start(
                root_ea              = self.root_ea,
                user_prompt          = self.user_prompt,
                model_tier           = self.model_tier,
                agent_reasoning_level = self.agent_reasoning_level,
                auto_renames         = g_settings.get("auto_renames", True),
                auto_types           = g_settings.get("auto_types", True),
                auto_structs         = g_settings.get("auto_structs", True),
                rename_style         = g_settings.get("rename_style", "snake_case"),
                struct_member_style  = g_settings.get("struct_member_style", "default"),
                skip_reversing       = False,
                max_call_depth       = g_settings.get("max_call_depth", 0),
                guess_virtual_function_calls = g_settings.get(
                    "guess_virtual_function_calls", False
                ),
                decompiler           = "ida",
                current_view         = self.current_view,
            )
        except AuthError as e:
            self.sig_error.emit(_reauth_message(str(e)))
            return
        except BillingError as e:
            tag = f"reason={e.reason}" if e.reason else "billing_error"
            self.sig_error.emit(f"Cannot start analysis ({tag}): {e}")
            return
        except SessionStartError as e:
            tag = f"reason={e.reason}" if e.reason else "session_unavailable"
            self.sig_error.emit(f"Cannot start analysis ({tag}): {e}")
            return
        except Exception as e:
            self.sig_error.emit(f"Failed to start session: {e}\n{traceback.format_exc()}")
            return

        if self._cancelled:
            self._srv.cancel()
            return
        if self._operation_cancel_requested:
            self._start_operation_cancel_request()
        self._poll_loop()

    def _poll_loop(self) -> None:
        consecutive_failures = 0
        while not self._cancelled:
            try:
                cmds = self._srv.next_command()   # list[dict]
                consecutive_failures = 0
            except AuthError as e:
                if e.rejected:
                    self.sig_error.emit(_reauth_message(str(e)))
                    return
                consecutive_failures += 1
                if self._wait_for_network(consecutive_failures, e):
                    return
                continue
            except SessionStartError as e:
                self.sig_error.emit(str(e))
                return
            except requests.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code in (404, 409):
                    try:
                        if self._srv.resume():
                            continue
                    except Exception as resume_error:
                        e = resume_error
                consecutive_failures += 1
                if self._wait_for_network(consecutive_failures, e):
                    return
                continue
            except requests.exceptions.RequestException as e:
                consecutive_failures += 1
                if self._wait_for_network(consecutive_failures, e):
                    return
                continue
            except Exception as e:
                self.sig_error.emit(f"Error polling server: {e}")
                return

            if not self._dispatch_command_batch(cmds):
                return

    def _dispatch_command_batch(self, cmds: list[dict]) -> bool:
        """Execute one polled batch and acknowledge its IDA results together."""
        self._skip_batch_sequence_commit = False
        result_batch: list[tuple[str, dict]] = []
        completed_sequences: list[int] = []
        keep_running = True

        for cmd in cmds:
            if self._cancelled:
                return False
            try:
                if cmd.get("needs_result") is True:
                    result_batch.append(self._prepare_command_result(cmd))
                else:
                    keep_running = self._dispatch_command(cmd)
                completed_sequences.append(int(cmd.get("sequence", 0) or 0))
            except Exception as e:
                self.sig_error.emit(f"Invalid server command: {e}")
                return False
            if not keep_running:
                break

        if result_batch and not self._post_command_results(result_batch):
            return False
        if not self._skip_batch_sequence_commit:
            for sequence in completed_sequences:
                self._srv.commit_sequence(sequence)
        return keep_running

    def _dispatch_command(self, cmd: dict) -> bool:
        """Process one command. Returns False if the worker should stop."""
        cmd_type = cmd.get("type", "")

        # ── Terminal ───────────────────────────────────────────────────────
        if cmd_type == "done":
            self.sig_done.emit(cmd.get("report", ""))
            return True   # stay alive for chat

        if cmd_type == "error":
            self.sig_error.emit(cmd.get("message", "Unknown server error"))
            return False

        if cmd_type == "operation_cancelled":
            self._operation_cancel_requested = False
            self.sig_operation_cancelled.emit(
                cmd.get("message", "Generation stopped.")
            )
            return True

        if cmd_type == "operation_interrupted":
            self._operation_cancel_requested = False
            self.sig_operation_interrupted.emit(
                cmd.get(
                    "message",
                    "Generation was interrupted. You can send another message to continue.",
                )
            )
            return True

        # ── UI notifications (no result needed) ───────────────────────────
        if cmd_type == "wait":
            return True

        if cmd_type == "log":
            self.sig_log.emit(cmd.get("level", "info"), cmd.get("message", ""))
            return True

        if cmd_type == "progress":
            self.sig_progress.emit(cmd.get("message", ""))
            return True

        if cmd_type == "tree_node_added":
            self.sig_tree_node_added.emit(
                self._parse_ea(cmd.get("parent_ea", "0x0")),
                self._parse_ea(cmd.get("ea", "0x0")),
                cmd.get("name", ""),
                bool(cmd.get("duplicate", False)),
            )
            return True

        if cmd_type == "tree_nodes_added":
            raw_nodes = cmd.get("tree_nodes", [])
            if not isinstance(raw_nodes, list):
                raise ValueError("tree_nodes_added requires a node list")
            nodes = []
            for node in raw_nodes:
                if not isinstance(node, dict):
                    raise ValueError("tree_nodes_added contains an invalid node")
                parent_ea = self._parse_ea(node.get("parent_ea", "0x0"))
                ea = self._parse_ea(node.get("ea", "0x0"))
                name = node.get("name", "")
                if not ea or not isinstance(name, str):
                    raise ValueError("tree_nodes_added contains an invalid node")
                nodes.append(
                    (parent_ea, ea, name, bool(node.get("duplicate", False)))
                )
            if nodes:
                self.sig_tree_nodes_added.emit(nodes)
            return True

        if cmd_type == "tree_node_updated":
            self.sig_tree_node_updated.emit(
                self._parse_ea(cmd.get("ea", "0x0")),
                cmd.get("name", ""),
                cmd.get("status", ""),
                cmd.get("notes", ""),
                cmd.get("summary", ""),
            )
            return True

        if cmd_type == "reversal_activity":
            activity = cmd.get("reversal_activity", {})
            if not isinstance(activity, dict):
                return True
            safe_activity = {
                "function_ea": str(activity.get("function_ea", "") or "").strip()[:48],
                "function_name": str(activity.get("function_name", "") or "").strip()[:160],
                "parent_ea": str(activity.get("parent_ea", "") or "").strip()[:48],
                "parent_name": str(activity.get("parent_name", "") or "").strip()[:160],
                "action": str(activity.get("action", "") or "").strip()[:64],
                "label": str(activity.get("label", "") or "").strip()[:160],
                "detail": str(activity.get("detail", "") or "").strip()[:1200],
                "status": str(activity.get("status", "") or "").strip()[:32],
                "items": [
                    str(item).strip()[:300]
                    for item in (
                        activity.get("items", [])
                        if isinstance(activity.get("items", []), list)
                        else []
                    )[:100]
                    if str(item).strip()
                ],
            }
            if safe_activity["action"] and safe_activity["label"]:
                self.sig_reversal_activity.emit(safe_activity)
            return True

        if cmd_type == "chat_response":
            self.sig_chat_response.emit(cmd.get("message", ""))
            return True

        if cmd_type == "stream_start":
            self.sig_stream_start.emit()
            return True

        if cmd_type == "stream_chunk":
            self.sig_stream_chunk.emit(cmd.get("delta", ""))
            return True

        if cmd_type == "candidate_answer_replace":
            self.sig_candidate_answer_replace.emit(
                int(cmd.get("revision", 0) or 0),
                cmd.get("report", ""),
            )
            return True

        if cmd_type == "answer_final":
            self.sig_answer_final.emit(int(cmd.get("revision", 0) or 0))
            return True

        if cmd_type == "agent_thinking_start":
            self.sig_agent_thinking_start.emit()
            return True

        if cmd_type == "answer_preparing":
            self.sig_answer_preparing.emit()
            return True

        if cmd_type in {
            "answer_audit_start",
            "answer_audit_running",
            "answer_audit_skipped",
            "answer_audit_complete",
            "answer_audit_failed",
        }:
            self.sig_answer_audit.emit({
                "type": cmd_type,
                "status": str(cmd.get("status", "") or "")[:64],
                "report": str(cmd.get("report", "") or ""),
                "edit_count": max(0, int(cmd.get("edit_count", 0) or 0)),
            })
            return True

        if cmd_type == "agent_turn_start":
            self.sig_agent_turn_start.emit(int(cmd.get("turn", 0) or 0))
            return True

        if cmd_type == "agent_turn_note":
            self.sig_agent_turn_note.emit(
                int(cmd.get("turn", 0) or 0),
                cmd.get("agent_note", ""),
            )
            return True

        if cmd_type == "agent_reversal_note":
            self.sig_agent_reversal_note.emit(
                int(cmd.get("turn", 0) or 0),
                cmd.get("agent_note", ""),
            )
            return True

        if cmd_type == "agent_turn_chunk":
            self.sig_agent_turn_chunk.emit(
                int(cmd.get("turn", 0) or 0),
                str(cmd.get("delta", "") or ""),
            )
            return True

        if cmd_type == "agent_turn_end":
            self.sig_agent_turn_end.emit(
                int(cmd.get("turn", 0) or 0),
                cmd.get("status", ""),
            )
            return True

        if cmd_type == "agent_reading":
            reads = cmd.get("agent_reads", [])
            safe_reads = []
            for read in reads if isinstance(reads, list) else []:
                if not isinstance(read, dict):
                    continue
                safe_reads.append({
                    key: value
                    for key, value in read.items()
                    if key != "content"
                })
            actions = cmd.get("agent_actions", [])
            safe_actions = []
            for action in actions if isinstance(actions, list) else []:
                if not isinstance(action, dict):
                    continue
                tool = str(action.get("tool", "") or "").strip()[:80]
                label = str(action.get("label", "") or "").strip()[:200]
                detail = str(action.get("detail", "") or "").strip()[:300]
                if not label:
                    continue
                safe_actions.append({
                    "tool": tool,
                    "label": label,
                    "detail": detail,
                })
            self.sig_agent_reading.emit({
                "turn": int(cmd.get("turn", 0) or 0),
                "reads": safe_reads,
                "actions": safe_actions,
            })
            return True

        # ── IDA commands — execute on main thread, post result ────────────
        return self._post_command_results([self._prepare_command_result(cmd)])

    def _prepare_command_result(self, cmd: dict) -> tuple[str, dict]:
        cmd_id = cmd.get("id", "")
        if not isinstance(cmd_id, str) or not cmd_id:
            raise ValueError("executable command has no command ID.")
        if cmd_id in self._result_cache:
            result = self._result_cache[cmd_id]
        else:
            try:
                result = run_on_main(execute, cmd)
            except Exception as e:
                result = {"type": "error_result", "error": str(e)}
            self._result_cache[cmd_id] = result
        return cmd_id, result

    def _post_command_results(self, results: list[tuple[str, dict]]) -> bool:
        pending = list(results)
        failures = 0
        malformed_ack_failures = 0
        while pending and not self._cancelled:
            try:
                statuses = self._srv.post_results(pending)
                malformed_ack_failures = 0
                retry = []
                for cmd_id, result in pending:
                    status = statuses.get(cmd_id)
                    if status in ("accepted", "duplicate"):
                        self._result_cache.pop(cmd_id, None)
                    elif status == "pending":
                        retry.append((cmd_id, result))
                    elif status == "unknown":
                        self.sig_error.emit(
                            "The server did not recognize the pending command result."
                        )
                        return False
                    else:
                        raise RuntimeError(
                            f"Unexpected result acknowledgement for {cmd_id}."
                        )
                if retry:
                    pending = retry
                    failures += 1
                    if failures >= _UNKNOWN_RESULT_RETRY_LIMIT:
                        self.sig_error.emit(
                            "The server did not recognize the pending command result."
                        )
                        return False
                    if self._wait_for_network(
                        failures,
                        RuntimeError("command persistence has not completed"),
                    ):
                        return False
                    continue
                return True
            except AuthError as e:
                if e.rejected:
                    self.sig_error.emit(_reauth_message(str(e)))
                    return False
                failures += 1
                if self._wait_for_network(failures, e):
                    return False
            except requests.exceptions.HTTPError as e:
                if (
                    e.response is not None
                    and e.response.status_code in (404, 409)
                ):
                    try:
                        if self._srv.resume():
                            self._result_cache.clear()
                            self._skip_batch_sequence_commit = True
                            return True
                    except Exception as resume_error:
                        e = resume_error
                failures += 1
                if self._wait_for_network(failures, e):
                    return False
            except requests.exceptions.RequestException as e:
                failures += 1
                if self._wait_for_network(failures, e):
                    return False
            except ServerProtocolError as e:
                malformed_ack_failures += 1
                if malformed_ack_failures >= _MALFORMED_ACK_RETRY_LIMIT:
                    self.sig_error.emit(
                        "The server repeatedly returned an invalid command acknowledgement."
                    )
                    return False
                if self._wait_for_network(malformed_ack_failures, e):
                    return False
            except Exception as e:
                self.sig_error.emit(f"Failed to return command result: {e}")
                return False

        return False

    def send_chat(
        self,
        message: str,
        current_view: dict | None = None,
        model_tier: str = "fast",
        agent_reasoning_level: str = "high",
    ) -> None:
        """Forward a follow-up chat message to the server.

        Called from a dedicated chat worker while this QThread runs the poll
        loop. ServerSession uses a separate polling connection and serializes
        other requests.
        """
        if self._srv:
            self._srv.send_chat(
                message,
                current_view=current_view,
                model_tier=model_tier,
                agent_reasoning_level=agent_reasoning_level,
            )

    def _sleep_interruptible(self, seconds: int) -> bool:
        """Sleep for up to `seconds`, in 0.25s ticks, honouring cancellation.

        Returns True if cancellation was observed (caller should bail).
        """
        ticks = max(1, int(seconds * 4))
        for _ in range(ticks):
            if self._cancelled:
                return True
            self.msleep(250)
        return False

    def _wait_for_network(self, failures: int, error: Exception) -> bool:
        wait_s = _BACKOFF_SCHEDULE_S[
            min(failures - 1, len(_BACKOFF_SCHEDULE_S) - 1)
        ]
        self.sig_progress.emit(
            f"Network error, retrying in {wait_s}s "
            f"(attempt {failures}): {error}"
        )
        return self._sleep_interruptible(wait_s)

    @staticmethod
    def _parse_ea(s: str) -> int:
        try:
            return int(s, 16)
        except (ValueError, TypeError):
            return 0

    # ── Control ───────────────────────────────────────────────────────────────

    def cancel(self) -> None:
        if self._cancelled:
            return
        self._cancelled = True
        session = self._srv
        if session is not None:
            self._cancel_thread = threading.Thread(
                target=session.cancel,
                name="ida-ai-cancel",
                daemon=True,
            )
            self._cancel_thread.start()

    def cancel_operation(self) -> None:
        """Stop current server work while keeping this session's poller alive."""
        self._operation_cancel_requested = True
        self._start_operation_cancel_request()

    def _start_operation_cancel_request(self) -> None:
        session = self._srv
        if session is None:
            return
        thread = self._operation_cancel_thread
        if thread is not None and thread.is_alive():
            return
        self._operation_cancel_thread = threading.Thread(
            target=session.cancel_operation,
            name="ida-ai-cancel-operation",
            daemon=True,
        )
        self._operation_cancel_thread.start()

    def delete_history(self) -> None:
        if self._srv:
            self._srv.delete_history()
        self._cancelled = True
