"""
graph_view.py — Custom QGraphicsView call graph.

Drop-in API:
    .add_node(parent_ea, ea, name)
    .update_node(ea, name, status, notes, summary)
    .reset()

Interaction:
    - Drag:                pan
    - Ctrl + wheel:        zoom
    - F:                   fit all nodes in view
    - Ctrl+F:              open search bar
    - Click node body:     show info panel + activate focus mode
                           (second click on same node clears focus)
    - Click node chevron:  collapse / expand subtree
    - Escape:              close search → clear focus → close panel
"""

from __future__ import annotations

import math
from typing import Optional

from ..compat.qt import QtCore, QtGui, QtWidgets, Qt, QPointF, QRectF, Signal

from .styles import (
    COLORS,
    STATUS_COLOR,
    STATUS_LABEL,
    MOTION_NORMAL_MS,
)
from .scrollbars import install_scrollbars


NODE_W = 160
NODE_H = 52
H_SPACING = 36
V_SPACING = 90

_GLOW_REACH  = 28   # pixels the glow extends beyond the node rect
_GLOW_STEPS  = 14   # annular rings — more = smoother

_TOGGLE_W    = 22   # width of collapse-toggle hot-zone at right edge of node


# ═══════════════════════════════════════════════════════════════════════════
#  Edge item
# ═══════════════════════════════════════════════════════════════════════════

class EdgeItem(QtWidgets.QGraphicsPathItem):
    """Bezier edge.  Path rebuilt only on layout; pen updated every frame."""

    _SHIMMER_SPEED = 0.72       # path fraction per second
    _SHIMMER_WIDTH = 0.28       # path fraction covered by the bright band

    def __init__(self, src: "NodeItem", dst: "NodeItem"):
        super().__init__()
        self.src = src
        self.dst = dst
        self.setZValue(-1)
        self._active = False
        self._reverse = False
        self._shimmer_phase = 0.0
        self.refresh()

    def set_active(self, active: bool, reverse: bool = False) -> None:
        changed = self._active != active or self._reverse != reverse
        self._active = active
        self._reverse = reverse
        if changed:
            self._update_pen()

    def refresh(self) -> None:
        self.refresh_geometry()
        self._update_pen()

    def refresh_geometry(self) -> None:
        sp = self.src.bottom_anchor()
        dp = self.dst.top_anchor()
        path = QtGui.QPainterPath(sp)
        mid_y = (sp.y() + dp.y()) / 2
        path.cubicTo(QPointF(sp.x(), mid_y), QPointF(dp.x(), mid_y), dp)
        self.setPath(path)
        self._path_length = max(1.0, path.length())

    def _update_pen(self) -> None:
        # Keep the item bounding rect large enough for the custom shimmer stroke.
        # Active edge painting is handled in paint(); this pen is mostly geometry.
        if self._active:
            col = QtGui.QColor(COLORS["accent"])
            col.setAlpha(1)
            pen = QtGui.QPen(col)
            pen.setWidthF(4.2)
        else:
            pen = QtGui.QPen(QtGui.QColor(COLORS["border"]))
            pen.setWidthF(1.2)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        self.setPen(pen)
        self.update()

    def paint(self, painter: QtGui.QPainter,
              option: QtWidgets.QStyleOptionGraphicsItem,
              widget: Optional[QtWidgets.QWidget] = None) -> None:
        painter.save()
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.setBrush(Qt.NoBrush)

        if not self._active:
            pen = QtGui.QPen(QtGui.QColor(COLORS["border"]))
            pen.setWidthF(1.2)
            pen.setCapStyle(Qt.RoundCap)
            pen.setJoinStyle(Qt.RoundJoin)
            painter.setPen(pen)
            painter.drawPath(self.path())
            painter.restore()
            return

        accent = QtGui.QColor(COLORS["accent"])

        glow = QtGui.QColor(accent)
        glow.setAlpha(30)
        glow_pen = QtGui.QPen(glow)
        glow_pen.setWidthF(3.8)
        glow_pen.setCapStyle(Qt.RoundCap)
        glow_pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(glow_pen)
        painter.drawPath(self.path())

        base = QtGui.QColor(accent)
        base.setAlpha(95)
        base_pen = QtGui.QPen(base)
        base_pen.setWidthF(1.45)
        base_pen.setCapStyle(Qt.RoundCap)
        base_pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(base_pen)
        painter.drawPath(self.path())

        half = self._SHIMMER_WIDTH / 2.0
        phase = 1.0 - self._shimmer_phase if self._reverse else self._shimmer_phase
        self._paint_shimmer_segment(painter, phase - half, phase + half)
        painter.restore()

    def _paint_shimmer_segment(self, painter: QtGui.QPainter, start: float, end: float) -> None:
        if start < 0.0:
            self._paint_shimmer_segment(painter, start + 1.0, 1.0)
            self._paint_shimmer_segment(painter, 0.0, end)
            return
        if end > 1.0:
            self._paint_shimmer_segment(painter, start, 1.0)
            self._paint_shimmer_segment(painter, 0.0, end - 1.0)
            return
        if end <= start:
            return

        path = self.path()

        def point_at_length_fraction(fraction: float) -> QPointF:
            percent = path.percentAtLength(self._path_length * fraction)
            return path.pointAtPercent(percent)

        samples = max(
            8, min(64, int((end - start) * self._path_length / 3.0))
        )
        seg = QtGui.QPainterPath(point_at_length_fraction(start))
        for i in range(1, samples + 1):
            t = start + (end - start) * (i / samples)
            seg.lineTo(point_at_length_fraction(t))

        p0 = point_at_length_fraction(start)
        p1 = point_at_length_fraction(end)
        grad = QtGui.QLinearGradient(p0, p1)
        transparent = QtGui.QColor(COLORS["accent"])
        transparent.setAlpha(0)
        accent = QtGui.QColor(COLORS["accent"])
        accent.setAlpha(225)
        white = QtGui.QColor("#ffffff")
        white.setAlpha(235)
        grad.setColorAt(0.00, transparent)
        grad.setColorAt(0.34, accent)
        grad.setColorAt(0.50, white)
        grad.setColorAt(0.66, accent)
        grad.setColorAt(1.00, transparent)

        pen = QtGui.QPen()
        pen.setBrush(QtGui.QBrush(grad))
        pen.setWidthF(2.35)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.drawPath(seg)

    def tick_shimmer(self, dt: float) -> None:
        if not self._active:
            return
        self._shimmer_phase = (self._shimmer_phase + dt * self._SHIMMER_SPEED) % 1.0
        self.update()


# ═══════════════════════════════════════════════════════════════════════════
#  Node item
# ═══════════════════════════════════════════════════════════════════════════

class NodeItem(QtWidgets.QGraphicsObject):
    # Use object to carry 64-bit EAs — PySide6 Signal(int) is C++ 32-bit.
    sig_clicked         = Signal(object)   # main-body click — EA
    sig_activated       = Signal(object)   # main-body double-click — EA
    sig_toggle_collapse = Signal(object)   # chevron click — EA

    def __init__(self, ea: int, name: str, is_root: bool = False):
        super().__init__()
        self.ea          = ea
        self.fname       = name
        self.status      = "queued"
        self.notes       = ""
        self.summary     = ""
        self.is_root     = is_root
        self.highlighted = False
        self.collapsed   = False      # this node's subtree is folded
        self._has_children  = False
        self._hidden_count  = 0       # number of folded descendants
        self._pulse_phase   = 0.0
        self._hovered       = False
        self.setAcceptHoverEvents(True)
        self.setFlag(QtWidgets.QGraphicsItem.GraphicsItemFlag.ItemIsSelectable)
        self.setZValue(1)

    # ── geometry ────────────────────────────────────────────────────────

    def boundingRect(self) -> QRectF:
        pad = _GLOW_REACH + 4
        return QRectF(-NODE_W / 2 - pad, -NODE_H / 2 - pad,
                      NODE_W + pad * 2,  NODE_H + pad * 2)

    def _node_rect(self) -> QRectF:
        return QRectF(-NODE_W / 2, -NODE_H / 2, NODE_W, NODE_H)

    def _toggle_rect(self) -> QRectF:
        """Hot-zone for the collapse chevron — right strip of the node rect."""
        return QRectF(NODE_W / 2 - _TOGGLE_W, -NODE_H / 2, _TOGGLE_W, NODE_H)

    def top_anchor(self)    -> QPointF: return self.scenePos() + QPointF(0, -NODE_H / 2)
    def bottom_anchor(self) -> QPointF: return self.scenePos() + QPointF(0,  NODE_H / 2)

    def update_data(self, name: str, status: str, notes: str, summary: str) -> None:
        self.fname   = name
        self.status  = status
        self.notes   = notes
        self.summary = summary
        self.setToolTip(self._tooltip())
        self.update()

    def _tooltip(self) -> str:
        head = f"{self.fname}  ({self.ea:#x})"
        body = []
        if self.summary: body.append("Summary: " + self.summary[:200])
        if self.notes:   body.append("Notes: "   + self.notes[:200])
        return head if not body else head + "\n\n" + "\n\n".join(body)

    def tick_pulse(self, dt: float) -> None:
        if self.status in ("analysing", "refining"):
            self._pulse_phase = (self._pulse_phase + dt * 4.0) % (2 * math.pi)
            self.update()

    # ── painting ───────────────────────────────────────────────────────

    def paint(self, p: QtGui.QPainter, _opt, _wdg) -> None:
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        rect = self._node_rect()

        # ── Border colour (drives glow colour too) ──────────────────
        if self.is_root or self.highlighted:
            border_col = QtGui.QColor(COLORS["accent"])
            border_w   = 1.4
        elif self.status in ("analysing", "refining"):
            border_col = QtGui.QColor(COLORS["analyzing"])
            border_w   = 1.2
        elif self._hovered:
            border_col = QtGui.QColor(COLORS["border_hi"])
            border_w   = 1.2
        else:
            border_col = QtGui.QColor(COLORS["border"])
            border_w   = 1.0

        # ── Smooth glow — root and selected only ────────────────────
        if self.is_root or self.highlighted:
            max_alpha = 95 if self.is_root else 80
            p.setPen(Qt.NoPen)
            for i in range(1, _GLOW_STEPS + 1):
                outer_s = float(i)     / _GLOW_STEPS * _GLOW_REACH
                inner_s = float(i - 1) / _GLOW_STEPS * _GLOW_REACH
                alpha   = int(max_alpha * math.exp(-3.5 * outer_s / _GLOW_REACH))
                if alpha < 1:
                    continue
                gc = QtGui.QColor(border_col); gc.setAlpha(alpha)
                ring = QtGui.QPainterPath()
                ring.addRoundedRect(
                    rect.adjusted(-outer_s, -outer_s, outer_s, outer_s),
                    9.0 + outer_s, 9.0 + outer_s)
                ring.addRoundedRect(
                    rect.adjusted(-inner_s, -inner_s, inner_s, inner_s),
                    9.0 + inner_s, 9.0 + inner_s)
                ring.setFillRule(Qt.OddEvenFill)
                p.fillPath(ring, QtGui.QBrush(gc))

        # ── Background ───────────────────────────────────────────────
        p.setPen(Qt.NoPen)
        p.setBrush(QtGui.QColor(
            COLORS["bg_card_hi"] if self._hovered else COLORS["bg_card"]
        ))
        p.drawRoundedRect(rect, 9, 9)

        # ── Border ───────────────────────────────────────────────────
        pen = QtGui.QPen(border_col)
        pen.setWidthF(border_w)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(rect, 9, 9)

        # ── Collapse toggle (right strip) — only when has children ───
        right_margin = 4
        if self._has_children:
            right_margin = _TOGGLE_W + 4
            div_x = rect.right() - _TOGGLE_W + 0.5
            # Subtle vertical divider
            p.setPen(QtGui.QPen(QtGui.QColor(COLORS["border"]), 1.0))
            p.drawLine(QPointF(div_x, rect.top() + 9), QPointF(div_x, rect.bottom() - 9))
            # Chevron glyph
            chevron = "▸" if self.collapsed else "▾"
            cf = QtGui.QFont()
            cf.setPointSize(8)
            p.setFont(cf)
            p.setPen(QtGui.QColor(COLORS["text_mute"]))
            p.drawText(
                QRectF(div_x, rect.top(), _TOGGLE_W - 1, rect.height()),
                Qt.AlignCenter, chevron)

        # ── Collapsed badge — pill below node showing hidden count ───
        if self.collapsed and self._hidden_count > 0:
            badge_text = f"+{self._hidden_count}"
            bf = QtGui.QFont()
            bf.setPointSize(7); bf.setBold(True)
            p.setFont(bf)
            fm = QtGui.QFontMetrics(bf)
            badge_w = fm.horizontalAdvance(badge_text) + 12
            badge_h = 14
            badge_rect = QRectF(-badge_w / 2, rect.bottom() + 5, badge_w, badge_h)
            col = QtGui.QColor(COLORS["accent"]); col.setAlpha(200)
            p.setPen(Qt.NoPen); p.setBrush(col)
            p.drawRoundedRect(badge_rect, 7, 7)
            p.setPen(QtGui.QColor("#ffffff"))
            p.drawText(badge_rect, Qt.AlignCenter, badge_text)

        # ── Status dot ────────────────────────────────────────────────
        dot_col = QtGui.QColor(STATUS_COLOR.get(self.status, COLORS["text_mute"]))
        dot_r   = 4
        dot_pos = QPointF(rect.left() + 14, rect.top() + 16)

        if self.status == "analysing":
            alpha = int(80 + 60 * math.sin(self._pulse_phase))
            halo  = QtGui.QColor(dot_col); halo.setAlpha(alpha)
            p.setBrush(halo); p.setPen(Qt.NoPen)
            p.drawEllipse(dot_pos, dot_r + 4, dot_r + 4)

        p.setBrush(dot_col); p.setPen(Qt.NoPen)
        p.drawEllipse(dot_pos, dot_r, dot_r)

        # ── Name ─────────────────────────────────────────────────────
        name_col = QtGui.QColor(COLORS["accent"] if self.is_root else COLORS["text"])
        p.setPen(name_col)
        f_name = QtGui.QFont()
        f_name.setFamily("JetBrains Mono"); f_name.setStyleHint(QtGui.QFont.StyleHint.Monospace)
        f_name.setPointSize(9)
        p.setFont(f_name)
        name_rect = QRectF(rect.left() + 28, rect.top() + 8,
                           rect.width() - 28 - right_margin, 18)
        fm      = QtGui.QFontMetrics(f_name)
        elided  = fm.elidedText(self.fname, Qt.ElideRight, int(name_rect.width()))
        p.drawText(name_rect, Qt.AlignLeft | Qt.AlignVCenter, elided)

        # ── Meta line ────────────────────────────────────────────────
        p.setPen(QtGui.QColor(COLORS["text_mute"]))
        f_meta = QtGui.QFont()
        f_meta.setFamily("JetBrains Mono"); f_meta.setStyleHint(QtGui.QFont.StyleHint.Monospace)
        f_meta.setPointSize(8)
        p.setFont(f_meta)
        meta_rect = QRectF(rect.left() + 28, rect.top() + 27,
                           rect.width() - 28 - right_margin, 18)
        meta = STATUS_LABEL.get(self.status, self.status)
        if self.is_root: meta = "root · " + meta
        p.drawText(meta_rect, Qt.AlignLeft | Qt.AlignVCenter, meta)

    # ── interaction ─────────────────────────────────────────────────────

    def hoverEnterEvent(self, event):
        self._hovered = True
        self.setCursor(Qt.PointingHandCursor)
        self.update()
        super().hoverEnterEvent(event)

    def hoverLeaveEvent(self, event):
        self._hovered = False
        self.unsetCursor()
        self.update()
        super().hoverLeaveEvent(event)

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            if self._has_children and self._toggle_rect().contains(e.pos()):
                self.sig_toggle_collapse.emit(self.ea)
            else:
                self.sig_clicked.emit(self.ea)
        super().mousePressEvent(e)

    def mouseDoubleClickEvent(self, e):
        if (e.button() == Qt.LeftButton and
                not (self._has_children and self._toggle_rect().contains(e.pos()))):
            self.sig_activated.emit(self.ea)
            e.accept()
            return
        super().mouseDoubleClickEvent(e)


# ═══════════════════════════════════════════════════════════════════════════
#  Node info panel — floating overlay
# ═══════════════════════════════════════════════════════════════════════════

class NodeInfoPanel(QtWidgets.QFrame):
    """Floating panel showing node details on click."""

    sig_closed = Signal()

    def __init__(self, parent: QtWidgets.QWidget):
        super().__init__(parent)
        self.setObjectName("nodeInfoPanel")
        self.setFixedWidth(310)
        self.setMaximumHeight(420)
        c = COLORS
        self.setStyleSheet(f"""
            QFrame#nodeInfoPanel {{
                background: {c['bg_card']};
                border: 1px solid {c['border_hi']};
                border-radius: 10px;
            }}
            QWidget, QAbstractScrollArea, QScrollArea > QWidget > QWidget {{
                background: transparent;
            }}
        """)
        self._build()
        self.hide()

    def _build(self) -> None:
        c = COLORS
        lay = QtWidgets.QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 10)
        lay.setSpacing(6)

        # Header
        hdr = QtWidgets.QHBoxLayout(); hdr.setSpacing(8)
        self._name_lbl = QtWidgets.QLabel()
        self._name_lbl.setStyleSheet(
            f"color: {c['accent']}; font-family: 'JetBrains Mono'; "
            f"font-size: 11px; font-weight: bold;")
        self._name_lbl.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        hdr.addWidget(self._name_lbl, 1)

        self._ea_lbl = QtWidgets.QLabel()
        self._ea_lbl.setStyleSheet(
            f"color: {c['text_mute']}; font-family: 'JetBrains Mono'; font-size: 10px;")
        hdr.addWidget(self._ea_lbl)

        self._close_btn = QtWidgets.QToolButton()
        self._close_btn.setText("✕"); self._close_btn.setFixedSize(18, 18)
        self._close_btn.setCursor(Qt.PointingHandCursor)
        self._close_btn.setStyleSheet(
            f"background: transparent; border: none; "
            f"color: {c['text_mute']}; font-size: 10px;")
        self._close_btn.clicked.connect(self._close)
        hdr.addWidget(self._close_btn)
        lay.addLayout(hdr)

        self._status_lbl = QtWidgets.QLabel()
        self._status_lbl.setStyleSheet(
            "font-family: 'JetBrains Mono'; font-size: 10px;"
        )
        lay.addWidget(self._status_lbl)

        self._sep = QtWidgets.QFrame()
        self._sep.setFixedHeight(1)
        self._sep.setStyleSheet(f"background: {c['border']};")
        lay.addWidget(self._sep)

        # Scrollable content
        self._scroll = QtWidgets.QScrollArea()
        self._scroll.setObjectName("nodeInfoScroll")
        install_scrollbars(self._scroll, "bg_card")
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        content = QtWidgets.QWidget()
        cl = QtWidgets.QVBoxLayout(content)
        cl.setContentsMargins(0, 4, 0, 4); cl.setSpacing(10)

        self._sum_box = QtWidgets.QWidget()
        sb = QtWidgets.QVBoxLayout(self._sum_box)
        sb.setContentsMargins(0, 0, 0, 0); sb.setSpacing(3)
        self._sum_hdr = QtWidgets.QLabel("SUMMARY")
        self._sum_hdr.setStyleSheet(
            f"color: {c['text_mute']}; font-family: 'JetBrains Mono'; "
            f"font-size: 9px; letter-spacing: 1px;")
        sb.addWidget(self._sum_hdr)
        self._sum_lbl = QtWidgets.QLabel()
        self._sum_lbl.setWordWrap(True)
        self._sum_lbl.setStyleSheet(f"color: {c['text_dim']}; font-size: 11px;")
        sb.addWidget(self._sum_lbl)
        cl.addWidget(self._sum_box)

        self._notes_box = QtWidgets.QWidget()
        nb = QtWidgets.QVBoxLayout(self._notes_box)
        nb.setContentsMargins(0, 0, 0, 0); nb.setSpacing(3)
        self._notes_hdr = QtWidgets.QLabel("NOTES")
        self._notes_hdr.setStyleSheet(
            f"color: {c['text_mute']}; font-family: 'JetBrains Mono'; "
            f"font-size: 9px; letter-spacing: 1px;")
        nb.addWidget(self._notes_hdr)
        self._notes_lbl = QtWidgets.QLabel()
        self._notes_lbl.setWordWrap(True)
        self._notes_lbl.setStyleSheet(f"color: {c['text_dim']}; font-size: 11px;")
        nb.addWidget(self._notes_lbl)
        cl.addWidget(self._notes_box)

        cl.addStretch(1)
        self._scroll.setWidget(content)
        lay.addWidget(self._scroll, 1)

    def refresh_theme(self) -> None:
        """Re-apply the panel's inline stylesheets from the current theme."""
        c = COLORS
        self.setStyleSheet(f"""
            QFrame#nodeInfoPanel {{
                background: {c['bg_card']};
                border: 1px solid {c['border_hi']};
                border-radius: 10px;
            }}
            QWidget, QAbstractScrollArea, QScrollArea > QWidget > QWidget {{
                background: transparent;
            }}
        """)
        self._name_lbl.setStyleSheet(
            f"color: {c['accent']}; font-family: 'JetBrains Mono'; "
            f"font-size: 11px; font-weight: bold;")
        self._ea_lbl.setStyleSheet(
            f"color: {c['text_mute']}; font-family: 'JetBrains Mono'; font-size: 10px;")
        self._close_btn.setStyleSheet(
            f"background: transparent; border: none; "
            f"color: {c['text_mute']}; font-size: 10px;")
        self._sep.setStyleSheet(f"background: {c['border']};")
        for _h in (self._sum_hdr, self._notes_hdr):
            _h.setStyleSheet(
                f"color: {c['text_mute']}; font-family: 'JetBrains Mono'; "
                f"font-size: 9px; letter-spacing: 1px;")
        for _b in (self._sum_lbl, self._notes_lbl):
            _b.setStyleSheet(f"color: {c['text_dim']}; font-size: 11px;")

    def _close(self) -> None:
        self.hide(); self.sig_closed.emit()

    def show_for(self, ea: int, name: str, status: str,
                 notes: str, summary: str) -> None:
        self._name_lbl.setText(name)
        self._ea_lbl.setText(f"{ea:#x}")

        sc = STATUS_COLOR.get(status, COLORS["text_mute"])
        self._status_lbl.setText(f"● {STATUS_LABEL.get(status, status)}")
        self._status_lbl.setStyleSheet(
            f"color: {sc}; font-family: 'JetBrains Mono'; font-size: 10px;")

        has_sum   = bool(summary.strip())
        has_notes = bool(notes.strip())
        if has_sum:   self._sum_lbl.setText(summary[:600]);  self._sum_box.show()
        else:         self._sum_box.hide()
        if has_notes: self._notes_lbl.setText(notes[:900]);  self._notes_box.show()
        else:         self._notes_box.hide()

        self._scroll.setVisible(has_sum or has_notes)
        self.adjustSize()
        self.show(); self.raise_()


# ═══════════════════════════════════════════════════════════════════════════
#  Graph view
# ═══════════════════════════════════════════════════════════════════════════

class FunctionGraphView(QtWidgets.QGraphicsView):
    sig_node_selected = Signal(object, str, str, str)  # ea (64-bit), name, notes, summary

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scene = QtWidgets.QGraphicsScene(self)
        self.setScene(self._scene)

        self.setRenderHint(QtGui.QPainter.Antialiasing, True)
        self.setRenderHint(QtGui.QPainter.SmoothPixmapTransform, True)
        self.setBackgroundBrush(QtGui.QColor(COLORS["bg_base"]))
        self.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setTransformationAnchor(QtWidgets.QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self.setDragMode(QtWidgets.QGraphicsView.DragMode.ScrollHandDrag)
        self.setMouseTracking(True)
        # Always repaint the full viewport so partial-update seam boundaries never
        # leave stale pixels that look like spurious lines around items.
        self.setViewportUpdateMode(
            QtWidgets.QGraphicsView.ViewportUpdateMode.FullViewportUpdate
        )

        self._nodes:        dict[int, NodeItem]  = {}
        self._edges:        list[EdgeItem]       = []
        self._edge_by_child: dict[int, EdgeItem] = {}
        self._children:     dict[int, list[int]] = {}
        self._parent_of:    dict[int, int]       = {}
        self._roots:        list[int]            = []
        self._selected_ea:  Optional[int]        = None
        self._zoom = 1.0

        # Pixels reserved on the left by an overlaid widget (e.g. drawer tab).
        # Affects centering and fit so scene content appears centred in the
        # visible (non-obscured) area.  The background grid is unaffected.
        self._left_inset = 0

        # State
        self._collapsed:      set[int]    = set()
        self._focus_ea:       Optional[int] = None
        self._focus_lineage:  set[int]    = set()
        self._search_text:    str         = ""
        self._search_matches: list[int]   = []
        self._search_idx:     int         = 0
        self._hide_skipped:   bool        = False
        self._awaiting_initial_status: set[int] = set()
        self._pending_spawn_nodes: set[int] = set()
        self._spawning_nodes: set[int] = set()

        # Animation
        self._anim_timer = QtCore.QTimer(self)
        self._anim_timer.setInterval(16)
        self._anim_timer.timeout.connect(self._tick)
        self._last_tick = QtCore.QElapsedTimer()
        self._last_tick.start()

        self._layout_timer = QtCore.QTimer(self)
        self._layout_timer.setSingleShot(True)
        self._layout_timer.timeout.connect(self._perform_relayout)
        self._layout_starts: dict[int, QPointF] = {}
        self._layout_targets: dict[int, QPointF] = {}
        self._layout_anim = QtCore.QVariantAnimation(self)
        self._layout_anim.setDuration(MOTION_NORMAL_MS)
        self._layout_anim.setStartValue(0.0)
        self._layout_anim.setEndValue(1.0)
        self._layout_anim.setEasingCurve(QtCore.QEasingCurve.OutCubic)
        self._layout_anim.valueChanged.connect(self._apply_layout_progress)
        self._layout_anim.finished.connect(self._finish_layout_animation)
        self._auto_fit = True
        self._auto_fit_timer = QtCore.QTimer(self)
        self._auto_fit_timer.setSingleShot(True)
        self._auto_fit_timer.timeout.connect(self._apply_auto_fit)
        self._pan_press_pos = None

        # Overlays
        self._info_panel = NodeInfoPanel(self)
        self._info_panel.sig_closed.connect(self._on_panel_closed)
        self._build_overlays()

    def set_left_inset(self, px: int) -> None:
        """Reserve *px* pixels on the left edge (e.g. for a drawer tab).

        The background grid still fills the full widget; only the scene
        centering and fit calculations shift so the tree content is visually
        centred in the non-obscured area.
        """
        inset = max(0, px)
        if inset == self._left_inset:
            return
        self._left_inset = inset
        self._schedule_auto_fit()

    def refresh_theme(self) -> None:
        """Re-read theme colours after a live theme switch.

        The background brush is cached on the view (set once in __init__), so it
        must be reassigned; the grid and node painting read COLORS at paint time
        but need a repaint, and edge pens are rebuilt from the new colours.
        """
        self.setBackgroundBrush(QtGui.QColor(COLORS["bg_base"]))
        for e in self._edges:
            e.refresh()              # rebuilds each edge pen from COLORS
        self._style_overlays()       # fit button + search bar inline styles
        self._info_panel.refresh_theme()
        self.resetCachedContent()
        self._scene.update()
        self.viewport().update()

    # ── overlay construction ────────────────────────────────────────────

    def _build_overlays(self) -> None:
        # Fit button — bottom-right
        self._fit_btn = QtWidgets.QToolButton(self)
        self._fit_btn.setFixedSize(30, 30)
        self._fit_btn.setText("⊡")
        self._fit_btn.setToolTip("Fit all nodes and keep centered  (F)")
        self._fit_btn.setCursor(Qt.PointingHandCursor)
        self._fit_btn.clicked.connect(self._enable_auto_fit)

        # In-memory graph filter toggle; intentionally not persisted.
        self._hide_skipped_toggle = QtWidgets.QCheckBox("Hide skipped functions", self)
        self._hide_skipped_toggle.setFixedHeight(36)
        self._hide_skipped_toggle.setToolTip("Hide skipped functions")
        self._hide_skipped_toggle.setCursor(Qt.PointingHandCursor)
        self._hide_skipped_toggle.toggled.connect(self._set_hide_skipped)

        # Search bar — top-right, always visible
        self._search_wrap = QtWidgets.QFrame(self)
        self._search_wrap.setFixedHeight(36)
        sw = QtWidgets.QHBoxLayout(self._search_wrap)
        sw.setContentsMargins(10, 0, 6, 0)
        sw.setSpacing(6)

        self._search_icon = QtWidgets.QLabel("⌕")
        sw.addWidget(self._search_icon)

        self._search_input = QtWidgets.QLineEdit()
        self._search_input.setPlaceholderText("Search functions…")
        self._search_input.textChanged.connect(self._apply_search)
        self._search_input.returnPressed.connect(self._search_next)
        self._search_input.installEventFilter(self)
        sw.addWidget(self._search_input, 1)

        self._search_count_lbl = QtWidgets.QLabel("")
        sw.addWidget(self._search_count_lbl)

        self._search_close = QtWidgets.QToolButton()
        self._search_close.setText("✕"); self._search_close.setFixedSize(18, 18)
        self._search_close.setCursor(Qt.PointingHandCursor)
        self._search_close.clicked.connect(self._close_search)
        sw.addWidget(self._search_close)

        self._style_overlays()
        self._reposition_overlays()

    def _style_overlays(self) -> None:
        """(Re)apply the inline overlay stylesheets from the current theme.
        Called on build and again on a live theme switch (refresh_theme)."""
        c = COLORS
        self._fit_btn.setStyleSheet(f"""
            QToolButton {{
                background: {c['bg_card']};
                border: 1px solid {c['border_hi']};
                border-radius: 7px;
                color: {c['text_mute']};
                font-size: 15px;
            }}
            QToolButton:hover {{
                background: {c['bg_card_hi']};
                color: {c['text']};
                border-color: {c['accent']};
            }}
        """)
        self._hide_skipped_toggle.setStyleSheet(f"""
            QCheckBox {{
                background: {c['bg_card']};
                border: 1px solid {c['border_hi']};
                border-radius: 9px;
                color: {c['text_dim']};
                font-size: 11px;
                padding: 0 12px;
            }}
            QCheckBox:hover {{
                background: {c['bg_card_hi']};
                color: {c['text']};
                border-color: {c['accent']};
            }}
            QCheckBox::indicator {{
                width: 13px;
                height: 13px;
                margin-right: 7px;
                border-radius: 4px;
                border: 1px solid {c['border_hi']};
                background: {c['bg_input']};
            }}
            QCheckBox::indicator:checked {{
                border-color: {c['accent']};
                background: {c['accent']};
            }}
        """)
        self._search_wrap.setStyleSheet(f"""
            QFrame {{
                background: {c['bg_card']};
                border: 1px solid {c['border_hi']};
                border-radius: 9px;
            }}
        """)
        self._search_icon.setStyleSheet(
            f"color: {c['text_mute']}; font-size: 14px; "
            f"background: transparent; border: none;")
        self._search_input.setStyleSheet(f"""
            QLineEdit {{
                background: transparent; border: none;
                color: {c['text']};
                font-family: 'JetBrains Mono'; font-size: 12px;
            }}
        """)
        self._search_count_lbl.setStyleSheet(
            f"color: {c['text_mute']}; font-size: 10px; "
            f"background: transparent; border: none;")
        self._search_close.setStyleSheet(f"""
            QToolButton {{ background: transparent; border: none;
                           color: {c['text_mute']}; font-size: 10px; }}
            QToolButton:hover {{ color: {c['text']}; }}
        """)

    # ── overlay positioning ─────────────────────────────────────────────

    def resizeEvent(self, e: QtGui.QResizeEvent) -> None:
        super().resizeEvent(e)
        self._reposition_overlays()
        self._schedule_auto_fit()

    def _reposition_overlays(self) -> None:
        m = 12
        self._fit_btn.move(self.width()  - self._fit_btn.width()  - m,
                           self.height() - self._fit_btn.height() - m)
        # Search bar — top-right, fixed width, always shown. The skipped filter
        # toggle sits immediately to its left and is intentionally in-memory only.
        gap = 8
        available = max(0, self.width() - m * 2)
        toggle_w = self._hide_skipped_toggle.sizeHint().width()
        sw_w = min(260, max(160, self.width() // 3))
        if toggle_w + gap + sw_w > available:
            sw_w = max(150, available - toggle_w - gap)
        self._search_wrap.setFixedWidth(sw_w)
        search_x = self.width() - sw_w - m
        self._search_wrap.move(search_x, m)
        self._hide_skipped_toggle.setFixedWidth(toggle_w)
        self._hide_skipped_toggle.move(max(m, search_x - toggle_w - gap), m)
        # Info panel — top-right, directly below the search bar
        if self._info_panel.isVisible():
            self._info_panel.setFixedWidth(
                min(310, max(220, self.width() - m * 2))
            )
            panel_top = m + self._search_wrap.height() + 8
            self._info_panel.setMaximumHeight(
                max(120, self.height() - panel_top - m)
            )
            x = self.width() - self._info_panel.width() - m
            self._info_panel.move(max(m, x), panel_top)

    # ── background grid ─────────────────────────────────────────────────

    def drawBackground(self, p: QtGui.QPainter, rect: QRectF) -> None:
        del rect
        # Paint the background FILL ourselves from the live theme rather than
        # relying on the cached backgroundBrush (set once in __init__) — that
        # brush doesn't follow a live theme switch, which left the fill stale
        # while only the grid lines recoloured.
        #
        # Draw in viewport coordinates, not scene coordinates. If the grid is
        # painted through the scene transform it appears to slide/scale whenever
        # the graph is zoomed.
        p.save()
        p.resetTransform()
        viewport_rect = self.viewport().rect()
        p.fillRect(viewport_rect, QtGui.QColor(COLORS["bg_base"]))

        # Theme-aware grid: derive from the border colour at low alpha so it
        # reads as a faint light grid on dark themes and a faint dark grid on
        # light themes. Read at paint time, so it follows live theme switches.
        grid = QtGui.QColor(COLORS["border"])
        grid.setAlpha(40)

        # Cosmetic pen (width 0 → always exactly 1 device pixel regardless of
        # zoom) with antialiasing OFF for the grid pass.  Axis-aligned lines
        # don't benefit from AA; leaving it on causes sub-pixel bleed that
        # makes lines appear inside node rects at certain fractional zoom levels.
        pen = QtGui.QPen(grid)
        pen.setWidthF(0)           # cosmetic — 1 px at every zoom
        p.setPen(pen)
        p.setRenderHint(QtGui.QPainter.Antialiasing, False)

        step = 24
        left = viewport_rect.left()
        top  = viewport_rect.top()
        right = viewport_rect.right()
        bottom = viewport_rect.bottom()
        x = left
        while x <= right:
            p.drawLine(x, top, x, bottom); x += step
        y = top
        while y <= bottom:
            p.drawLine(left, y, right, y); y += step

        p.restore()

    # ── public API ──────────────────────────────────────────────────────

    def add_node(self, parent_ea: int, ea: int, name: str, duplicate: bool = False) -> None:
        if duplicate:
            # Node already shown elsewhere — just draw an edge to it so the
            # caller can see the reference, but don't create a new node or
            # traverse its subtree again.
            existing = self._nodes.get(ea)
            parent   = self._nodes.get(parent_ea)
            if existing and parent and ea not in self._edge_by_child:
                edge = EdgeItem(parent, existing)
                edge.setVisible(not self._node_hidden(parent_ea) and
                                not self._node_hidden(ea))
                self._scene.addItem(edge)
                self._edges.append(edge)
                self._sync_edge_activity()
                # Don't overwrite _edge_by_child — the canonical edge owns status.
            return
        if ea in self._nodes:
            return
        is_root = (parent_ea == 0 or parent_ea not in self._nodes)
        node = NodeItem(ea, name, is_root=is_root)
        node.sig_clicked.connect(self._on_node_clicked)
        node.sig_activated.connect(self._on_node_activated)
        node.sig_toggle_collapse.connect(self._toggle_collapse)
        self._nodes[ea] = node
        if self._hide_skipped:
            self._awaiting_initial_status.add(ea)

        if is_root:
            self._roots.append(ea)
        else:
            self._parent_of[ea] = parent_ea
            self._children.setdefault(parent_ea, []).append(ea)
            # Mark parent as having children immediately
            p_node = self._nodes.get(parent_ea)
            if p_node:
                p_node._has_children = True
                p_node.update()
                node.setPos(p_node.pos())
            edge = EdgeItem(self._nodes[parent_ea], node)
            edge.setVisible(not self._node_hidden(parent_ea) and
                            not self._node_hidden(ea))
            self._scene.addItem(edge)
            self._edges.append(edge)
            self._edge_by_child[ea] = edge
            self._sync_edge_activity()

        node.setVisible(not self._node_hidden(ea))
        node.setScale(0.6)
        node.setOpacity(0.0)
        self._scene.addItem(node)
        self._pending_spawn_nodes.add(ea)

        # If focus mode is active, refresh the lineage cache so new
        # descendants of the focused node are included immediately.
        if self._focus_ea is not None:
            self._focus_lineage = self._get_lineage(self._focus_ea)

        self._relayout()

    def _start_node_spawn_animation(self, ea: int) -> None:
        node = self._nodes.get(ea)
        if node is None:
            return

        self._spawning_nodes.add(ea)
        end_opacity = 0.15 if self._node_is_dim(ea) else 1.0
        node.setScale(0.6)
        node.setOpacity(0.0)
        anim_s = QtCore.QPropertyAnimation(node, b"scale", self)
        anim_s.setStartValue(0.6)
        anim_s.setEndValue(1.0)
        anim_s.setDuration(220)
        anim_s.setEasingCurve(QtCore.QEasingCurve.OutBack)
        anim_o = QtCore.QPropertyAnimation(node, b"opacity", self)
        anim_o.setStartValue(0.0)
        anim_o.setEndValue(end_opacity)
        anim_o.setDuration(220)
        anim_o.finished.connect(lambda ea=ea: self._finish_node_spawn(ea))
        anim_s.start(QtCore.QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)
        anim_o.start(QtCore.QAbstractAnimation.DeletionPolicy.DeleteWhenStopped)

    def _finish_node_spawn(self, ea: int) -> None:
        self._spawning_nodes.discard(ea)
        node = self._nodes.get(ea)
        if node is not None:
            node.setScale(1.0)
        self._update_opacity()

    def update_node(self, ea: int, name: str, status: str,
                    notes: str, summary: str) -> None:
        node = self._nodes.get(ea)
        if node is None:
            return
        first_status = ea in self._awaiting_initial_status
        node.update_data(name, status, notes, summary)
        self._awaiting_initial_status.discard(ea)
        self._sync_edge_activity()
        if self._hide_skipped or first_status:
            self._relayout()
        if self._selected_ea == ea:
            self.sig_node_selected.emit(ea, name, notes, summary)
            if self._info_panel.isVisible():
                self._info_panel.show_for(ea, name, status, notes, summary)
                self._reposition_overlays()

    def reset(self) -> None:
        self._layout_timer.stop()
        self._layout_anim.stop()
        self._auto_fit_timer.stop()
        self._anim_timer.stop()
        self._scene.clear()
        self._nodes.clear()
        self._edges.clear()
        self._edge_by_child.clear()
        self._children.clear()
        self._parent_of.clear()
        self._roots.clear()
        self._selected_ea   = None
        self._collapsed.clear()
        self._focus_ea      = None
        self._focus_lineage = set()
        self._search_text   = ""
        self._search_matches= []
        self._awaiting_initial_status.clear()
        self._pending_spawn_nodes.clear()
        self._spawning_nodes.clear()
        self._layout_starts.clear()
        self._layout_targets.clear()
        self._info_panel.hide()
        self._close_search()
        self.resetTransform()
        self._zoom = 1.0
        self._auto_fit = True
        self._pan_press_pos = None

    def _sync_edge_activity(self) -> None:
        """Set edge shimmer direction from the current node statuses.

        Analysing flows down the call tree into the callee. Refining flows from
        the callees of the function being refined back into that function.
        """
        for edge in self._edges:
            src_status = edge.src.status
            dst_status = edge.dst.status
            if src_status == "refining" and dst_status != "skipped":
                edge.set_active(True, reverse=True)
            elif dst_status == "analysing":
                edge.set_active(True, reverse=False)
            else:
                edge.set_active(False)
        self._sync_animation_timer()

    def _sync_animation_timer(self) -> None:
        active = any(
            node.status in ("analysing", "refining")
            for node in self._nodes.values()
        ) or any(edge._active for edge in self._edges)
        if active and not self._anim_timer.isActive():
            self._last_tick.restart()
            self._anim_timer.start()
        elif not active:
            self._anim_timer.stop()

    # ── collapse ────────────────────────────────────────────────────────

    def _toggle_collapse(self, ea: int) -> None:
        if ea in self._collapsed:
            self._collapsed.discard(ea)
        else:
            self._collapsed.add(ea)
        self._update_visibility()
        self._relayout()

    def _is_subtree_hidden(self, ea: int) -> bool:
        """True if any ancestor of ea is in the collapsed set."""
        p = self._parent_of.get(ea)
        while p is not None:
            if p in self._collapsed:
                return True
            p = self._parent_of.get(p)
        return False

    def _count_subtree(self, ea: int) -> int:
        total = 0
        for child in self._children.get(ea, []):
            total += 1 + self._count_subtree(child)
        return total

    def _is_skipped_hidden(self, ea: int) -> bool:
        if not self._hide_skipped:
            return False
        cur: Optional[int] = ea
        while cur is not None:
            node = self._nodes.get(cur)
            if node is not None and node.status == "skipped":
                return True
            cur = self._parent_of.get(cur)
        return False

    def _is_initial_status_hidden(self, ea: int) -> bool:
        if not self._hide_skipped:
            return False
        cur: Optional[int] = ea
        while cur is not None:
            if cur in self._awaiting_initial_status:
                return True
            cur = self._parent_of.get(cur)
        return False

    def _node_hidden(self, ea: int) -> bool:
        return (self._is_subtree_hidden(ea) or
                self._is_skipped_hidden(ea) or
                self._is_initial_status_hidden(ea))

    def _visible_children(self, ea: int) -> list[int]:
        return [c for c in self._children.get(ea, []) if not self._node_hidden(c)]

    def _update_visibility(self) -> None:
        for ea, node in self._nodes.items():
            hidden = self._node_hidden(ea)
            node.setVisible(not hidden)
            node.collapsed      = (ea in self._collapsed)
            node._has_children  = bool(self._children.get(ea))
            node._hidden_count  = self._count_subtree(ea) if ea in self._collapsed else 0
            node.update()
        for edge in self._edges:
            edge.setVisible(not self._node_hidden(edge.src.ea) and
                            not self._node_hidden(edge.dst.ea))

    def _set_hide_skipped(self, checked: bool) -> None:
        self._hide_skipped = checked
        if self._roots:
            self._relayout()
        else:
            self._update_visibility()
        if self._search_text:
            self._apply_search(self._search_input.text())

    # ── focus mode ──────────────────────────────────────────────────────

    def _get_lineage(self, ea: int) -> set[int]:
        lineage: set[int] = {ea}
        p = self._parent_of.get(ea)
        while p is not None:
            lineage.add(p); p = self._parent_of.get(p)
        def add_desc(e: int) -> None:
            for c in self._children.get(e, []):
                lineage.add(c); add_desc(c)
        add_desc(ea)
        return lineage

    def _set_focus(self, ea: int) -> None:
        self._focus_ea      = ea
        self._focus_lineage = self._get_lineage(ea)
        self._update_opacity()

    def _clear_focus(self) -> None:
        self._focus_ea      = None
        self._focus_lineage = set()
        self._update_opacity()

    def _node_is_dim(self, ea: int) -> bool:
        """Returns True if this node should be at 15% opacity."""
        if self._focus_ea is not None and ea not in self._focus_lineage:
            return True
        node = self._nodes.get(ea)
        if self._search_text and node and self._search_text not in node.fname.lower():
            return True
        return False

    def _update_opacity(self) -> None:
        """Apply focus/search dimming to every visible node and edge."""
        for ea, node in self._nodes.items():
            if not node.isVisible() or ea in self._spawning_nodes:
                continue
            node.setOpacity(0.15 if self._node_is_dim(ea) else 1.0)
        for edge in self._edges:
            if not edge.isVisible():
                continue
            # Dim an edge if either of its endpoints would be dimmed.
            dim = self._node_is_dim(edge.src.ea) or self._node_is_dim(edge.dst.ea)
            edge.setOpacity(0.15 if dim else 1.0)

    # ── search ──────────────────────────────────────────────────────────

    def _toggle_search(self) -> None:
        """Ctrl+F — focus the search input and select all existing text."""
        self._search_input.setFocus()
        self._search_input.selectAll()

    def _close_search(self) -> None:
        """Clear the search (✕ button or Escape) without hiding the bar."""
        self._search_input.blockSignals(True)
        self._search_input.clear()
        self._search_input.blockSignals(False)
        self._search_count_lbl.setText("")
        self._search_text    = ""
        self._search_matches = []
        self._update_opacity()
        self.setFocus()

    def _apply_search(self, text: str) -> None:
        self._search_text = text.strip().lower()
        if self._search_text:
            self._search_matches = [
                ea for ea, n in self._nodes.items()
                if self._search_text in n.fname.lower()
                and not self._is_skipped_hidden(ea)
            ]
            count = len(self._search_matches)
            if count:
                self._search_count_lbl.setText(
                    f"{count} match{'es' if count != 1 else ''}")
                self._search_idx = 0
                self._jump_to_node(self._search_matches[0])
            else:
                self._search_count_lbl.setText("no matches")
        else:
            self._search_matches = []
            self._search_count_lbl.setText("")
        self._update_opacity()

    def _search_next(self) -> None:
        if not self._search_matches:
            return
        self._search_idx = (self._search_idx + 1) % len(self._search_matches)
        self._jump_to_node(self._search_matches[self._search_idx])

    def _jump_to_node(self, ea: int) -> None:
        node = self._nodes.get(ea)
        if node:
            self.centerOn(node)

    def _visible_items_bounds(self) -> QRectF:
        bounds = QRectF()
        for item in self._scene.items():
            if not item.isVisible():
                continue
            item_rect = item.sceneBoundingRect()
            if item_rect.isNull():
                continue
            bounds = item_rect if bounds.isNull() else bounds.united(item_rect)
        return bounds

    # ── fit view ────────────────────────────────────────────────────────

    def _enable_auto_fit(self, _checked: bool = False) -> None:
        self._auto_fit = True
        self._fit_view()

    def _fit_view(self) -> None:
        self._auto_fit_timer.stop()
        if self._layout_timer.isActive():
            self._layout_timer.stop()
            self._perform_relayout()
        if self._layout_targets:
            self._layout_anim.stop()
            self._finish_layout_animation()
        self._update_visibility()
        self._fit_bounds(self._visible_items_bounds())

    def _fit_bounds(self, bounds: QRectF) -> None:
        if bounds.isNull():
            return
        # Expand the left side of the fit rect by the inset so fitInView
        # centres the content in the visible (non-obscured) area.
        left_pad = 30 + self._left_inset
        self.fitInView(bounds.adjusted(-left_pad, -30, 30, 30), Qt.KeepAspectRatio)
        self._zoom = self.transform().m11()

    def _schedule_auto_fit(self) -> None:
        if self._auto_fit and not self._auto_fit_timer.isActive():
            self._auto_fit_timer.start(0)

    def _apply_auto_fit(self) -> None:
        if not self._auto_fit:
            return
        self._update_visibility()
        bounds = QRectF()
        if self._layout_targets:
            for ea, target in self._layout_targets.items():
                node = self._nodes.get(ea)
                if node is None or not node.isVisible():
                    continue
                target_rect = node.boundingRect().translated(target)
                bounds = (
                    target_rect if bounds.isNull()
                    else bounds.united(target_rect)
                )
        else:
            bounds = self._visible_items_bounds()
        self._fit_bounds(bounds)

    # ── layout ──────────────────────────────────────────────────────────

    def _relayout(self) -> None:
        if not self._layout_timer.isActive():
            self._layout_timer.start(0)

    def _perform_relayout(self) -> None:
        if not self._roots:
            return

        self._update_visibility()

        widths: dict[int, float] = {}
        visible_roots = [r for r in self._roots if not self._node_hidden(r)]
        if not visible_roots:
            self._layout_anim.stop()
            self._layout_starts.clear()
            self._layout_targets.clear()
            bounds = self._visible_items_bounds()
            margin = 60
            if bounds.isNull():
                bounds = QRectF(-margin, -margin, margin * 2, margin * 2)
            self._scene.setSceneRect(bounds.adjusted(-margin, -margin, margin, margin))
            self._update_opacity()
            self._schedule_auto_fit()
            return

        def compute_w(ea: int) -> float:
            if self._node_hidden(ea):
                widths[ea] = 0.0
                return 0.0
            # Collapsed node takes its own width only (children hidden)
            if ea in self._collapsed:
                widths[ea] = NODE_W
                return NODE_W
            kids = self._visible_children(ea)
            if not kids:
                widths[ea] = NODE_W
                return NODE_W
            total = (sum(compute_w(k) for k in kids)
                     + H_SPACING * (len(kids) - 1))
            widths[ea] = max(NODE_W, total)
            return widths[ea]

        for r in visible_roots:
            compute_w(r)

        targets: dict[int, QPointF] = {}

        def place(ea: int, x_left: float, depth: int) -> None:
            if self._node_hidden(ea):
                return
            w  = widths[ea]
            cx = x_left + w / 2
            targets[ea] = QPointF(cx, depth * (NODE_H + V_SPACING))
            if ea not in self._collapsed:
                cursor = x_left
                for k in self._visible_children(ea):
                    place(k, cursor, depth + 1)
                    cursor += widths[k] + H_SPACING

        x_cursor = 0.0
        for r in visible_roots:
            place(r, x_cursor, 0)
            x_cursor += widths[r] + H_SPACING * 2

        self._start_layout_transition(targets)

    def _start_layout_transition(self, targets: dict[int, QPointF]) -> None:
        self._layout_anim.stop()

        spawn_eas = self._pending_spawn_nodes.intersection(targets)
        for ea in spawn_eas:
            node = self._nodes.get(ea)
            if node is not None:
                node.setPos(targets[ea])

        starts = {
            ea: QPointF(self._nodes[ea].pos())
            for ea in targets
            if ea in self._nodes
        }
        self._layout_starts = starts
        self._layout_targets = targets
        # A spawned node already pops at its final position. Moving the whole
        # graph at the same time adds a costly second animation.
        should_animate = (
            not spawn_eas
            and self.isVisible()
            and len(targets) > 1
            and any(
                (starts[ea] - target).manhattanLength() > 0.5
                for ea, target in targets.items()
            )
        )
        self._update_scene_bounds(targets)
        self._schedule_auto_fit()
        if should_animate:
            self._layout_anim.setCurrentTime(0)
            self._layout_anim.start()
        else:
            self._finish_layout_animation()

        for ea in spawn_eas:
            self._pending_spawn_nodes.discard(ea)
            self._start_node_spawn_animation(ea)

    def _apply_layout_progress(self, value) -> None:
        progress = float(value)
        for ea, target in self._layout_targets.items():
            node = self._nodes.get(ea)
            start = self._layout_starts.get(ea)
            if node is None or start is None:
                continue
            node.setPos(start + (target - start) * progress)
        self._refresh_edges()

    def _finish_layout_animation(self) -> None:
        if not self._layout_targets:
            return
        for ea, target in self._layout_targets.items():
            node = self._nodes.get(ea)
            if node is not None:
                node.setPos(target)
        self._refresh_edges()
        self._layout_starts.clear()
        self._layout_targets.clear()
        self._update_scene_bounds()
        self._update_opacity()
        self._schedule_auto_fit()

    def _refresh_edges(self) -> None:
        for edge in self._edges:
            edge.refresh_geometry()

    def _update_scene_bounds(
        self, targets: Optional[dict[int, QPointF]] = None
    ) -> None:
        bounds = self._visible_items_bounds()
        if targets:
            for ea, target in targets.items():
                node = self._nodes.get(ea)
                if node is None or not node.isVisible():
                    continue
                target_rect = node.boundingRect().translated(target)
                bounds = (
                    target_rect if bounds.isNull()
                    else bounds.united(target_rect)
                )
        margin = 60
        if bounds.isNull():
            bounds = QRectF(-margin, -margin, margin * 2, margin * 2)
        self._scene.setSceneRect(bounds.adjusted(-margin, -margin, margin, margin))
        visible_node_count = sum(1 for n in self._nodes.values() if n.isVisible())
        if visible_node_count <= 1 and self._auto_fit:
            # Shift the centre point right so the node appears centred in the
            # visible area (to the right of the drawer tab).  centerOn places
            # the given scene point at the viewport centre, so we offset it
            # left in scene space by left_inset / (2 * zoom) — that pushes the
            # node itself right by left_inset/2 viewport pixels.
            zoom = self.transform().m11() or 1.0
            cx = bounds.center().x() - self._left_inset / (2.0 * zoom)
            self.centerOn(QPointF(cx, bounds.center().y()))

    # ── interaction ────────────────────────────────────────────────────

    def mousePressEvent(self, e: QtGui.QMouseEvent) -> None:
        if e.button() == Qt.LeftButton and not isinstance(
            self.itemAt(e.pos()), NodeItem
        ):
            self._pan_press_pos = e.pos()
        else:
            self._pan_press_pos = None
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e: QtGui.QMouseEvent) -> None:
        if (
            self._pan_press_pos is not None
            and e.buttons() & Qt.LeftButton
            and (e.pos() - self._pan_press_pos).manhattanLength()
            >= QtWidgets.QApplication.startDragDistance()
        ):
            self._auto_fit = False
            self._auto_fit_timer.stop()
            self._pan_press_pos = None
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e: QtGui.QMouseEvent) -> None:
        super().mouseReleaseEvent(e)
        if e.button() == Qt.LeftButton:
            self._pan_press_pos = None

    def wheelEvent(self, e: QtGui.QWheelEvent) -> None:
        self._auto_fit = False
        self._auto_fit_timer.stop()
        if e.modifiers() & Qt.ControlModifier:
            factor   = 1.15 if e.angleDelta().y() > 0 else 1 / 1.15
            # Always derive current zoom from the live transform so fitInView
            # can zoom out below the old 0.3 floor without locking scroll.
            new_zoom = self.transform().m11() * factor
            if 0.05 <= new_zoom <= 5.0:
                self.scale(factor, factor)
            e.accept()
        else:
            super().wheelEvent(e)

    def keyPressEvent(self, e: QtGui.QKeyEvent) -> None:
        key  = e.key()
        mods = e.modifiers()
        if key == Qt.Key_F and mods == Qt.ControlModifier:
            self._toggle_search(); e.accept()
        elif key == Qt.Key_F and mods == Qt.NoModifier:
            self._enable_auto_fit(); e.accept()
        elif key == Qt.Key_Escape:
            if self._search_text:
                self._close_search()
            elif self._focus_ea is not None:
                self._clear_focus()
            elif self._info_panel.isVisible():
                self._info_panel._close()
            e.accept()
        else:
            super().keyPressEvent(e)

    def eventFilter(self, obj, event) -> bool:
        if obj is self._search_input and event.type() == QtCore.QEvent.KeyPress:
            if event.key() == Qt.Key_Escape:
                self._close_search()
                return True
        return super().eventFilter(obj, event)

    def _on_node_clicked(self, ea: int) -> None:
        # Toggle focus: second click on the already-focused node clears focus
        if self._focus_ea == ea:
            self._clear_focus()
        else:
            self._set_focus(ea)

        self._selected_ea = ea
        for n in self._nodes.values():
            n.highlighted = (n.ea == ea)
            n.update()

        node = self._nodes.get(ea)
        if node:
            self.sig_node_selected.emit(ea, node.fname, node.notes, node.summary)
            self._info_panel.show_for(
                ea, node.fname, node.status, node.notes, node.summary)
            self._reposition_overlays()

    def _on_node_activated(self, ea: int) -> None:
        try:
            import idaapi
            idaapi.jumpto(ea)
        except Exception:
            pass

    def _on_panel_closed(self) -> None:
        self._selected_ea = None
        self._clear_focus()
        for n in self._nodes.values():
            if n.highlighted:
                n.highlighted = False
                n.update()

    # ── animation tick ─────────────────────────────────────────────────

    def _tick(self) -> None:
        dt = self._last_tick.restart() / 1000.0
        active = False
        for n in self._nodes.values():
            if n.status in ("analysing", "refining"):
                n.tick_pulse(dt)
                active = True
        for e in self._edges:
            if e._active:
                e.tick_shimmer(dt)
                active = True
        if not active:
            self._anim_timer.stop()
