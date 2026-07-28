"""
viewer.py — Opens the final AI analysis report as a dockable tab in IDA's main window.

Uses simplecustviewer_t so the report appears alongside IDA's built-in
output/disassembly panels. A viewer is reused (contents replaced) when the
same function is analysed more than once.
"""

from ..config import PLUGIN_NAME

try:
    import ida_kernwin
    import ida_lines

    class _ReportViewer(ida_kernwin.simplecustviewer_t):
        """Thin subclass so each instance keeps a stable Python identity."""
        def Create(self, title: str) -> bool:
            return ida_kernwin.simplecustviewer_t.Create(self, title)

    _IDA_AVAILABLE = True

except ImportError:
    _IDA_AVAILABLE = False
    _ReportViewer  = None  # type: ignore[assignment, misc]


# Keep Python objects alive — if they go out of scope the C++ viewer is destroyed.
_open_viewers: dict[str, "_ReportViewer"] = {}


# ── Line formatting ───────────────────────────────────────────────────────────

def _fmt(line: str) -> str:
    """Apply IDA colour codes to one report line for basic readability."""
    s = line.strip()
    if not s:
        return ""

    # Long separator lines  ═══  ───  ===
    if len(s) >= 8 and all(c in "═─=-" for c in s):
        return ida_lines.COLSTR(line, ida_lines.SCOLOR_SYMBOL)

    # Markdown-style headers  #  ##  ###
    if s.startswith("#"):
        return ida_lines.COLSTR(line, ida_lines.SCOLOR_CODNAME)

    # Bullet / list items  -  •  *
    if s[:2] in ("- ", "• ", "* "):
        return ida_lines.COLSTR(line, ida_lines.SCOLOR_DSTR)

    # Bold markers  **…**  (LLM output)
    if s.startswith("**") and "**" in s[2:]:
        return ida_lines.COLSTR(line, ida_lines.SCOLOR_CODNAME)

    return line


# ── Public API ────────────────────────────────────────────────────────────────

def open_report_tab(func_name: str, report: str) -> None:
    """Open (or refresh) an IDA dockable tab showing the analysis report.

    Safe to call on IDA's main thread (e.g. from a Qt slot connected to
    AnalysisWorker.sig_done).  Does nothing gracefully when running outside IDA.

    Args:
        func_name: Root function name used as part of the tab title.
        report:    The final report text returned by the server.
    """
    if not _IDA_AVAILABLE or not report.strip():
        return

    title = f"AI Analysis · {func_name}" if func_name else "AI Analysis"

    try:
        existing = _open_viewers.get(title)
        if existing is not None:
            # Refresh in-place instead of opening a duplicate tab.
            try:
                existing.ClearLines()
                for line in report.splitlines():
                    existing.AddLine(_fmt(line))
                existing.Refresh()
                existing.Jump(0, 0)
                existing.Show()
                return
            except Exception:
                # Viewer was closed/destroyed — fall through to create a new one.
                _open_viewers.pop(title, None)

        viewer = _ReportViewer()
        if not viewer.Create(title):
            print(f"[{PLUGIN_NAME}] Could not create report viewer tab '{title}'.")
            return

        for line in report.splitlines():
            viewer.AddLine(_fmt(line))

        viewer.Refresh()
        viewer.Show()
        _open_viewers[title] = viewer

    except Exception as exc:
        print(f"[{PLUGIN_NAME}] open_report_tab: {exc}")
