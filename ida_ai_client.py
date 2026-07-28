"""
ida_ai_client.py — IDA Pro plugin entry point for the server-backed AI analyser.

Drop this file and the ida_ai_client/ package into IDA's plugins directory.
The analysis logic runs entirely on the Go server; this plugin handles only
IDA Pro API calls and forwards results back over HTTP.
"""

import json
import os
from pathlib import Path
import re
import shutil

import idaapi
import ida_kernwin

PLUGIN_NAME    = "Decompile.re"
PLUGIN_HOTKEY  = "Ctrl-Shift-A"
PLUGIN_COMMENT = "AI-powered reverse engineering assistant (server-backed)"
PLUGIN_HELP    = "Analyse the current function with an AI backend."
PLUGIN_WANTED_NAME = PLUGIN_NAME

_dialog = None    # keep reference so Qt doesn't GC it
_ACTION_DISASSEMBLY = "decompile_re:analyse_disassembly"
_ACTION_PSEUDOCODE = "decompile_re:analyse_pseudocode"


def _recover_interrupted_update() -> None:
    """Restore the previous client before importing a partially updated package."""
    root = Path(__file__).resolve().parent
    journal_path = root / ".decompile-re-update-journal.json"
    try:
        if not journal_path.is_file():
            return
        if journal_path.stat().st_size > 64 * 1024:
            raise ValueError("journal is too large")
        journal = json.loads(journal_path.read_text("utf-8"))
        if not isinstance(journal, dict) or journal.get("schema_version") != 1:
            raise ValueError("journal schema is invalid")
        operation_id = str(journal.get("operation_id") or "")
        if not re.fullmatch(r"[0-9a-f]{32}", operation_id):
            raise ValueError("operation identifier is invalid")

        target_module = root / "ida_ai_client"
        target_entry = root / "ida_ai_client.py"
        target_marker = root / "decompile-re-install.json"
        staging = root / f".decompile-re-staging-{operation_id}"
        backup = root / ".decompile-re-backups" / operation_id

        if journal.get("state") == "activated":
            if (
                target_entry.is_file()
                and (target_module / "__init__.py").is_file()
                and journal.get("health_check_started") is not True
            ):
                journal["health_check_started"] = True
                temporary = journal_path.with_name(
                    f".{journal_path.name}.{operation_id}.tmp"
                )
                temporary.write_text(
                    json.dumps(journal, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                os.replace(temporary, journal_path)
                shutil.rmtree(staging, ignore_errors=True)
                return

        backup_module = backup / "ida_ai_client"
        backup_entry = backup / "ida_ai_client.py"
        backup_marker = backup / "decompile-re-install.json"
        if backup_module.is_dir():
            if target_module.exists():
                shutil.rmtree(target_module)
            os.replace(backup_module, target_module)
        if backup_entry.is_file():
            os.replace(backup_entry, target_entry)
        if backup_marker.is_file():
            os.replace(backup_marker, target_marker)
        elif journal.get("had_marker") is False:
            target_marker.unlink(missing_ok=True)
        shutil.rmtree(staging, ignore_errors=True)
        journal_path.unlink(missing_ok=True)
    except Exception as exc:
        print(f"[Decompile.re] Could not recover interrupted update: {exc}")


def _mark_update_healthy() -> None:
    root = Path(__file__).resolve().parent
    journal_path = root / ".decompile-re-update-journal.json"
    try:
        if not journal_path.is_file() or journal_path.stat().st_size > 64 * 1024:
            return
        journal = json.loads(journal_path.read_text("utf-8"))
        if (
            isinstance(journal, dict)
            and journal.get("schema_version") == 1
            and journal.get("state") == "activated"
            and journal.get("health_check_started") is True
        ):
            journal_path.unlink()
    except Exception as exc:
        print(f"[Decompile.re] Could not finalize client update: {exc}")


_recover_interrupted_update()


def _dialog_shutdown_complete(dialog) -> None:
    global _dialog
    reopen = dialog.take_reopen_request()
    if _dialog is dialog:
        _dialog = None
    dialog.deleteLater()
    if reopen:
        from ida_ai_client.compat.qt import QtCore
        QtCore.QTimer.singleShot(0, AIAnalyzerPlugin._show_dialog)


def _get_main_window():
    """Return IDA's main QWidget. Tries ida_kernwin first (IDA 7+),
    then falls back to None so dialogs still open without a parent."""
    try:
        import ida_kernwin
        return ida_kernwin.get_main_window()
    except (ImportError, AttributeError):
        return None


def PLUGIN_ENTRY():
    return AIAnalyzerPlugin()


class AIAnalyzerPlugin(idaapi.plugin_t):
    flags         = idaapi.PLUGIN_KEEP
    comment       = PLUGIN_COMMENT
    help          = PLUGIN_HELP
    wanted_name   = PLUGIN_WANTED_NAME
    wanted_hotkey = PLUGIN_HOTKEY

    def init(self) -> int:
        try:
            from ida_ai_client.config   import QT_AVAILABLE, REQUESTS_AVAILABLE
            from ida_ai_client.compat.runtime import is_supported_ida, IDA_VERSION
            from ida_ai_client.settings import load_settings
        except ImportError as e:
            print(f"[{PLUGIN_NAME}] Import error: {e}")
            return idaapi.PLUGIN_SKIP

        if not is_supported_ida():
            print(f"[{PLUGIN_NAME}] IDA {IDA_VERSION} is not supported.")
            return idaapi.PLUGIN_SKIP

        if not QT_AVAILABLE:
            print(f"[{PLUGIN_NAME}] No supported Qt binding is available - GUI disabled.")
            return idaapi.PLUGIN_SKIP

        if not REQUESTS_AVAILABLE:
            print(
                f"[{PLUGIN_NAME}] Missing dependency: requests. "
                "Install the plugin through HCLI or install its Python dependencies."
            )
            return idaapi.PLUGIN_SKIP

        load_settings()

        # Register and attach right-click menu actions.
        self._actions = []
        for action_name, label in (
            (_ACTION_DISASSEMBLY, "Disassembly"),
            (_ACTION_PSEUDOCODE, "Pseudocode"),
        ):
            desc = idaapi.action_desc_t(
                action_name,
                f"AI Analyse Function ({label})",
                _AnalyseActionHandler(),
                "",
                "Analyse this function with the AI server",
                -1
            )
            if idaapi.register_action(desc):
                self._actions.append(action_name)
            else:
                print(f"[{PLUGIN_NAME}] Could not register action: {action_name}")

        self._ui_hooks = _PopupHooks()
        if not self._ui_hooks.hook():
            print(f"[{PLUGIN_NAME}] Could not attach context-menu hooks.")

        _mark_update_healthy()
        print(f"[{PLUGIN_NAME}] Loaded. Press {PLUGIN_HOTKEY} or Edit -> Plugins -> Decompile.re.")
        return idaapi.PLUGIN_KEEP

    def run(self, _arg) -> None:
        self._show_dialog()

    def term(self) -> None:
        if _dialog is not None:
            _dialog.take_reopen_request()
            _dialog.close()
        hooks = getattr(self, "_ui_hooks", None)
        if hooks is not None:
            hooks.unhook()
            self._ui_hooks = None
        for name in getattr(self, "_actions", []):
            idaapi.unregister_action(name)

    @staticmethod
    def _show_dialog():
        global _dialog

        try:
            from ida_ai_client.ui.dialogs import AnalysisDialog
        except ImportError as e:
            print(f"[{PLUGIN_NAME}] Cannot open dialog: {e}")
            return

        if _dialog is not None and _dialog.is_shutting_down():
            _dialog.request_reopen_after_shutdown()
            return

        if _dialog is None:
            _dialog = AnalysisDialog(_get_main_window())
            dialog = _dialog
            dialog.sig_shutdown_complete.connect(
                lambda: _dialog_shutdown_complete(dialog)
            )

        _dialog.show()
        _dialog.raise_()
        _dialog.activateWindow()


class _AnalyseActionHandler(idaapi.action_handler_t):
    def activate(self, _ctx):
        AIAnalyzerPlugin._show_dialog()
        return 1

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class _PopupHooks(ida_kernwin.UI_Hooks):
    """Attach analysis actions only to supported function views."""

    def finish_populating_widget_popup(self, widget, popup_handle) -> None:
        widget_type = ida_kernwin.get_widget_type(widget)
        if widget_type == ida_kernwin.BWN_DISASM:
            action_name = _ACTION_DISASSEMBLY
        elif widget_type == ida_kernwin.BWN_PSEUDOCODE:
            action_name = _ACTION_PSEUDOCODE
        else:
            return
        ida_kernwin.attach_action_to_popup(
            widget,
            popup_handle,
            action_name,
            None,
        )
