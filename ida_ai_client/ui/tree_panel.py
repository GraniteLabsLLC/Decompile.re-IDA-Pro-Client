"""
tree_panel.py — Live call-tree widget (identical to the original plugin).
"""

from ..compat.qt import QtWidgets, QtGui, Qt

STATUS_LABEL = {
    "queued":     "Queued",
    "analysing":  "Analysing…",
    "refining":   "Refining...",
    "done":       "Done",
    "no_notes":   "Done",
    "analysed":   "Analysed",
    "skipped":    "Skipped",
    "failed":     "Failed",
    "duplicate":  "Duplicate",
}

STATUS_COLOR = {
    "queued":     QtGui.QColor("#888780"),
    "analysing":  QtGui.QColor("#EF9F27"),
    "refining":   QtGui.QColor("#FCE747"),
    "analysed":   QtGui.QColor("#1D9E75"),
    "done":       QtGui.QColor("#3FFC7E"),
    "no_notes":   QtGui.QColor("#3FFC7E"),
    "skipped":    QtGui.QColor("#B4B2A9"),
    "failed":     QtGui.QColor("#E24B4A"),
    "duplicate":  QtGui.QColor("#555450"),
}

STATUS_ICON = {
    "queued":     "○",
    "analysing":  "◌",
    "refining":   "◌",
    "done":       "●",
    "no_notes":   "●",
    "analysed":   "★",
    "skipped":    "–",
    "failed":     "✗",
    "duplicate":  "↩",
}


class FunctionTreeItem(QtWidgets.QTreeWidgetItem):
    def __init__(self, ea: int, name: str, parent=None):
        if parent is None:
            super().__init__()
        else:
            super().__init__(parent)
        self.ea      = ea
        self.fname   = name
        self.status  = "queued"
        self.notes   = ""
        self.summary = ""
        self._refresh()

    def update(self, name: str, status: str, notes: str, summary: str) -> None:
        self.fname   = name
        self.status  = status
        self.notes   = notes
        self.summary = summary
        self._refresh()

    def _refresh(self) -> None:
        icon  = STATUS_ICON.get(self.status, "○")
        color = STATUS_COLOR.get(self.status, QtGui.QColor("#888780"))
        self.setText(0, f"{icon}  {self.fname}")
        self.setForeground(0, QtGui.QBrush(color))
        self.setToolTip(0, self.summary[:200] if self.summary else self.fname)


class FunctionTreePanel(QtWidgets.QWidget):
    MONO = QtGui.QFont("Courier New", 9)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: dict[int, FunctionTreeItem] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        splitter = QtWidgets.QSplitter(Qt.Vertical)

        self._tree = QtWidgets.QTreeWidget()
        self._tree.setHeaderHidden(True)
        self._tree.setColumnCount(1)
        self._tree.setIndentation(16)
        self._tree.setAnimated(True)
        self._tree.setFont(self.MONO)
        self._tree.itemSelectionChanged.connect(self._on_selection)
        splitter.addWidget(self._tree)

        detail = QtWidgets.QWidget()
        detail_layout = QtWidgets.QVBoxLayout(detail)
        detail_layout.setContentsMargins(8, 6, 8, 6)
        detail_layout.setSpacing(4)

        self._lbl_name = QtWidgets.QLabel()
        self._lbl_name.setFont(QtGui.QFont("Courier New", 10))
        self._lbl_name.setWordWrap(True)
        detail_layout.addWidget(self._lbl_name)

        self._lbl_ea = QtWidgets.QLabel()
        self._lbl_ea.setStyleSheet("color: gray; font-size: 10px;")
        detail_layout.addWidget(self._lbl_ea)

        self._lbl_status = QtWidgets.QLabel()
        self._lbl_status.setStyleSheet("font-size: 11px;")
        detail_layout.addWidget(self._lbl_status)

        sep = QtWidgets.QFrame()
        sep.setFrameShape(QtWidgets.QFrame.HLine)
        sep.setStyleSheet("color: #cccccc;")
        detail_layout.addWidget(sep)

        self._txt_summary = QtWidgets.QTextEdit()
        self._txt_summary.setReadOnly(True)
        self._txt_summary.setPlaceholderText("No summary yet.")
        self._txt_summary.setFont(QtGui.QFont("Courier New", 9))
        self._txt_summary.setMaximumHeight(80)
        detail_layout.addWidget(self._txt_summary)

        self._txt_notes = QtWidgets.QTextEdit()
        self._txt_notes.setReadOnly(True)
        self._txt_notes.setPlaceholderText("No objective notes.")
        self._txt_notes.setFont(QtGui.QFont("Courier New", 9))
        self._txt_notes.setMaximumHeight(60)
        detail_layout.addWidget(self._txt_notes)

        splitter.addWidget(detail)
        splitter.setSizes([300, 180])
        layout.addWidget(splitter)

    def add_node(self, parent_ea: int, ea: int, name: str, duplicate: bool = False) -> None:
        if duplicate:
            # Node already tracked — add a read-only leaf so the caller can
            # see the cross-reference without a second subtree expanding.
            parent_item = self._items.get(parent_ea)
            if parent_item is not None:
                leaf = FunctionTreeItem(ea, f"↩  {name}", parent_item)
                leaf.update(name, "duplicate", "", "")
                # Not added to _items so it never receives status updates.
            return
        if ea in self._items:
            return
        if parent_ea == 0 or parent_ea not in self._items:
            item = FunctionTreeItem(ea, name)
            self._tree.addTopLevelItem(item)
        else:
            parent_item = self._items[parent_ea]
            item = FunctionTreeItem(ea, name, parent_item)
            parent_item.setExpanded(True)
        self._items[ea] = item

    def update_node(self, ea: int, name: str, status: str, notes: str, summary: str) -> None:
        item = self._items.get(ea)
        if item is None:
            return
        item.update(name, status, notes, summary)
        if self._tree.currentItem() is item:
            self._on_selection()

    def reset(self) -> None:
        self._tree.clear()
        self._items.clear()
        self._lbl_name.setText("")
        self._lbl_ea.setText("")
        self._lbl_status.setText("")
        self._txt_summary.clear()
        self._txt_notes.clear()

    def _on_selection(self) -> None:
        item = self._tree.currentItem()
        if not isinstance(item, FunctionTreeItem):
            return
        color = STATUS_COLOR.get(item.status, QtGui.QColor("#888780"))
        icon  = STATUS_ICON.get(item.status, "○")
        self._lbl_name.setText(item.fname)
        self._lbl_ea.setText(f"EA: {item.ea:#010x}")
        self._lbl_status.setText(f"{icon}  {STATUS_LABEL.get(item.status, item.status)}")
        self._lbl_status.setStyleSheet(f"color: {color.name()}; font-size: 11px; font-weight: bold;")
        self._txt_summary.setPlainText(item.summary or "")
        self._txt_notes.setPlainText(item.notes or "")
