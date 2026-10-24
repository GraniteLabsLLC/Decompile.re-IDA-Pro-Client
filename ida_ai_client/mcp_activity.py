"""Scoped native observations; IDA callbacks only enqueue, never perform I/O."""

from __future__ import annotations

import threading
import time

from .ida.sync import run_on_main

NATIVE_IDLE_SECONDS = 600


class ActivitySender:
    """One latest observation per source, with a bounded number of sources."""

    def __init__(self):
        self._condition = threading.Condition()
        self._pending = {}
        self._admissions = {}
        self._closed = False
        self._next_due = {}
        self._retired = {}
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="granite-activity-sender")
        self._thread.start()

    def submit(self, source, send, payload):
        with self._condition:
            if self._closed:
                return
            if source in self._retired:
                return
            sources = set(self._pending) | set(self._admissions)
            if source not in sources and len(sources) >= 256:
                removed = next(iter(self._pending or self._admissions))
                self._pending.pop(removed, None)
                self._admissions.pop(removed, None)
                self._next_due.pop(removed, None)
                self._retired[removed] = True
                if len(self._retired) > 512:
                    self._retired.pop(next(iter(self._retired)))
            if source not in self._next_due and len(self._next_due) >= 256:
                self._next_due.pop(next(iter(self._next_due)))
            if payload.get("state") == "running":
                self._admissions[source] = (send, payload)
            else:
                self._pending[source] = (send, payload)
            self._condition.notify()

    def _run(self):
        while True:
            with self._condition:
                while True:
                    self._condition.wait_for(lambda: self._closed or self._admissions or self._pending)
                    if self._closed:
                        return
                    now = time.monotonic()
                    source = next((key for key in self._admissions if self._next_due.get(key, 0) <= now), None)
                    if source is not None:
                        send, payload = self._admissions.pop(source)
                        break
                    source = next((key for key in self._pending if key not in self._admissions and self._next_due.get(key, 0) <= now), None)
                    if source is not None:
                        send, payload = self._pending.pop(source)
                        break
                    self._condition.wait(timeout=max(0.001, min(self._next_due.get(key, now) for key in (set(self._pending) | set(self._admissions))) - now))
                self._next_due[source] = time.monotonic() + 1.0
            try:
                send(payload)
            except Exception:
                # Retry the original admission identity/sequence. A duplicate
                # receipt cannot renew a remote clock; routine activity remains
                # pending until the admission is delivered successfully.
                if payload.get("state") == "running":
                    with self._condition:
                        if not self._closed and source not in self._retired:
                            self._admissions[source] = (send, payload)
                            self._condition.notify()

    def retire(self, source):
        with self._condition:
            self._pending.pop(source, None)
            self._admissions.pop(source, None)
            self._next_due.pop(source, None)
            self._retired[source] = True
            if len(self._retired) > 512:
                self._retired.pop(next(iter(self._retired)))
            self._condition.notify_all()

    def close(self):
        with self._condition:
            self._closed = True
            self._pending.clear()
            self._admissions.clear()
            self._condition.notify_all()
        if threading.current_thread() is not self._thread:
            self._thread.join(timeout=4)


def install_native_hooks(observe):
    """Install available documented hooks; callers must unhook on the main thread."""
    hooks = []
    try:
        import ida_idp

        class DatabaseHooks(ida_idp.IDB_Hooks):
            def make_code(self, insn):
                observe("Created code at " + hex(insn.ea))

            def make_data(self, ea, *_args):
                observe("Created data at " + hex(ea))

            def func_added(self, function):
                observe("Created function at " + hex(function.start_ea))

            def auto_empty(self):
                observe("Autoanalysis queue completed")

            def auto_empty_finally(self):
                observe("Autoanalysis completed")

        hook = DatabaseHooks()
        if hook.hook():
            hooks.append(hook)
    except (ImportError, AttributeError, RuntimeError):
        pass
    try:
        import ida_hexrays

        class DecompilerHooks(ida_hexrays.Hexrays_Hooks):
            def flowchart(self, *_args):
                observe("Decompiler flowchart built")
                return 0

            def microcode(self, *_args):
                observe("Decompiler microcode built")
                return 0

            def preoptimized(self, *_args):
                observe("Decompiler preoptimization completed")
                return 0

            def locopt(self, *_args):
                observe("Decompiler local optimization completed")
                return 0

            def prealloc(self, *_args):
                observe("Decompiler allocation stage")
                return 0

            def glbopt(self, *_args):
                observe("Decompiler global optimization completed")
                return 0

            def maturity(self, _function, maturity):
                observe("Decompiler maturity " + str(maturity))
                return 0

        hook = DecompilerHooks()
        if hook.hook():
            hooks.append(hook)
    except (ImportError, AttributeError, RuntimeError):
        pass
    return hooks


def run_native(function, command, cancel, report, native_active, *,
               idle_seconds=NATIVE_IDLE_SECONDS):
    """Abandon a canceled/stalled wait; an entered IDA call may finish later.

    A retained daemon owns execute_sync until it returns. The wrapper checks
    cancellation again at admission, so canceled queued work never executes.
    """
    done = threading.Event()
    lock = threading.Lock()
    state = {"admitted": False, "last": 0.0, "sequence": 0,
             "result": None, "error": None, "abandoned": False}

    def observe(detail, admission=False):
        with lock:
            if state["abandoned"] or cancel.is_set():
                return
            state["last"] = time.monotonic()
            state["sequence"] += 1
            payload = {"sequence": state["sequence"],
                       "operation_id": str(command.get("operation_id") or command.get("id") or ""),
                       "state": "running" if admission else "progress",
                       "detail": detail}
        report(payload)

    def execute(_command):
        with lock:
            if state["abandoned"] or cancel.is_set():
                return None
            state["admitted"] = True
        native_active.set()
        observe("Main-thread admission", True)
        hooks = install_native_hooks(observe)
        try:
            return function(command)
        finally:
            for hook in hooks:
                hook.unhook()
            native_active.clear()

    def dispatch():
        try:
            result = run_on_main(execute, command)
            with lock:
                if not state["abandoned"]:
                    state["result"] = result
        except Exception as error:
            with lock:
                state["error"] = error
        finally:
            done.set()

    threading.Thread(target=dispatch, daemon=True, name="granite-native-command").start()
    while not done.wait(0.1):
        with lock:
            if cancel.is_set():
                state["abandoned"] = True
                raise RuntimeError("Granite command canceled; an entered native call may still be running")
            if state["admitted"] and time.monotonic() - state["last"] >= idle_seconds:
                state["abandoned"] = True
                raise TimeoutError("IDA native command made no progress for ten minutes")
    with lock:
        if cancel.is_set():
            raise RuntimeError("Granite command canceled")
        if state["error"] is not None:
            raise state["error"]
        return state["result"]
