"""
dialogs.py — Modern animated UI for the AI Analyser.

Flow:
    1. Compact prompt dialog (~540x380) — single textarea, one Analyse button.
    2. On Analyse click, the window grows to ~1120x740 with eased animation;
       the prompt collapses into a one-line summary in a toolbar; the graph
       view and log panel fade in.

The settings dialog opens from the title-bar Settings control and remains separate.
"""

from __future__ import annotations

import re
import datetime
import math
import threading
import webbrowser
from collections import deque
from functools import lru_cache
from html import escape
from typing import Optional

from ..compat.qt import (
    QtCore,
    QtGui,
    QtNetwork,
    QtWidgets,
    Qt,
    QPoint,
    QPropertyAnimation,
    QEasingCurve,
    QSize,
    Signal,
    Property,
    QShortcut,
)

from ..config import (
    PLUGIN_NAME,
    REQUESTS_AVAILABLE,
    SETUP_WIZARD_RELEASE_URL,
    g_settings,
    is_loopback_server_url,
)
from ..settings import save_settings
from ..session  import reset_shared_auth_context
from ..ida.navigation import get_current_view
from .. import secret_store
from .. import browser_auth
from .. import auth_state
from .. import updater
from .worker     import AnalysisWorker, NetworkHistorySession, load_session_names, load_usage_percent
from .graph_view import FunctionGraphView
from .update_network import create_update_session
from .styles     import (
    COLORS,
    FONT_SANS,
    FONT_MONO,
    MOTION_FAST_MS,
    MOTION_NORMAL_MS,
    MOTION_SLOW_MS,
    main_qss,
    ROOT_RADIUS,
    apply_theme,
    theme_names,
)

try:
    from pygments import highlight as _pygments_highlight
    from pygments.formatters import HtmlFormatter as _PygmentsHtmlFormatter
    from pygments.lexers import TextLexer as _PygmentsTextLexer
    from pygments.lexers import get_lexer_by_name as _pygments_lexer_by_name
    from pygments.util import ClassNotFound as _PygmentsClassNotFound
except Exception:  # pragma: no cover - optional runtime dependency in IDA Python
    _pygments_highlight = None
    _PygmentsHtmlFormatter = None
    _PygmentsTextLexer = None
    _pygments_lexer_by_name = None
    _PygmentsClassNotFound = Exception


COMPACT_SIZE  = QSize(540, 355)
EXPANDED_SIZE = QSize(1120, 740)
ANIM_DURATION = MOTION_SLOW_MS

# Mapping between combo-box display labels and the wire value for model_tier.
# Order matters: index 0 is the default for users who haven't picked yet.
_MODEL_TIER_OPTIONS = [
    ("Fast",    "fast"),
    ("Adaptive", "dynamic"),
    ("Smart",   "smart"),
]


def _tier_label_for(tier_value: str) -> int:
    for i, (_label, value) in enumerate(_MODEL_TIER_OPTIONS):
        if value == tier_value:
            return i
    return 0


# Human-readable copy for 402 reasons returned by the server.
# See AI-Reversal-Backend/billing/gate.go for the canonical list.
_BILLING_REASON_COPY = {
    "usage_limit_reached": (
        "You've reached this period's analysis limit. Extend your usage "
        "in the dashboard or wait for your next renewal."
    ),
    "free_usage_limit_reached": (
        "Your free analysis allowance is used up. "
        "Upgrade your plan in the dashboard to keep analysing."
    ),
    "model_tier_not_in_plan": (
        "This model mode isn't included in your current plan. "
        "Pick Fast for now, or upgrade your plan in the dashboard."
    ),
    "concurrency_limit_reached": (
        "Your plan's concurrent-session limit is reached. "
        "Close another running analysis (in this or another IDA window) and retry."
    ),
    "token_velocity_cap": (
        "This sign-in has hit its daily spend cap (security throttle). "
        "Wait until tomorrow or sign in again from the dashboard."
    ),
}


@lru_cache(maxsize=32)
def _rounded_region(w: int, h: int, r: int) -> QtGui.QRegion:
    """Build the native window mask without allocating a supersampled bitmap."""
    if w <= 0 or h <= 0:
        return QtGui.QRegion()
    r = min(r, w // 2, h // 2)
    path = QtGui.QPainterPath()
    path.addRoundedRect(QtCore.QRectF(0, 0, w, h), r, r)
    return QtGui.QRegion(path.toFillPolygon().toPolygon())


@lru_cache(maxsize=32)
def _inset_rounded_region(
    w: int,
    h: int,
    r: int,
    inset: int,
) -> QtGui.QRegion:
    """Clip opaque content just inside an antialiased foreground outline."""
    if w <= inset * 2 or h <= inset * 2:
        return QtGui.QRegion()
    radius = min(
        max(0, r - inset),
        (w - inset * 2) // 2,
        (h - inset * 2) // 2,
    )
    path = QtGui.QPainterPath()
    path.addRoundedRect(
        QtCore.QRectF(
            inset,
            inset,
            w - inset * 2,
            h - inset * 2,
        ),
        radius,
        radius,
    )
    return QtGui.QRegion(path.toFillPolygon().toPolygon())


class RoundedDialogMixin:
    """Re-applies a rounded window mask on every resize."""

    def _apply_rounded_mask(self) -> None:
        if getattr(self, "_use_native_rounded_mask", True):
            self.setMask(
                _rounded_region(self.width(), self.height(), ROOT_RADIUS)
            )
        else:
            self.clearMask()

    def resizeEvent(self, e):  # type: ignore[override]
        super().resizeEvent(e)
        self._apply_rounded_mask()

    def showEvent(self, e):  # type: ignore[override]
        super().showEvent(e)
        self._apply_rounded_mask()


class _RoundedAnalysisSurface(QtWidgets.QFrame):
    """Antialiased background surface for the translucent main window."""

    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QtGui.QColor(COLORS["bg_elev"]))
        painter.drawRoundedRect(
            QtCore.QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5),
            ROOT_RADIUS - 0.5,
            ROOT_RADIUS - 0.5,
        )


class _RoundedAnalysisContent(QtWidgets.QWidget):
    """Clips opaque main-window children without clipping the background."""

    def _apply_content_clip(self) -> None:
        self.setMask(
            _inset_rounded_region(
                self.width(),
                self.height(),
                ROOT_RADIUS,
                1,
            )
        )

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._apply_content_clip()

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        self._apply_content_clip()


class _RoundedBorderOverlay(QtWidgets.QWidget):
    """Antialiased foreground outline above a rounded content surface."""

    def __init__(
        self,
        target: QtWidgets.QWidget,
        parent=None,
        *,
        radius: float = ROOT_RADIUS,
    ):
        super().__init__(parent)
        self._target = target
        self._radius = max(1.0, float(radius))
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self.setAutoFillBackground(False)
        target.installEventFilter(self)
        self.sync_geometry()

    def sync_geometry(self) -> None:
        target = self._target
        if target.parentWidget() is self.parentWidget():
            self.setGeometry(target.geometry())
        else:
            top_left = target.mapTo(
                self.parentWidget(),
                QtCore.QPoint(0, 0),
            )
            self.setGeometry(QtCore.QRect(top_left, target.size()))
        self.raise_()

    def eventFilter(
        self,
        watched: QtCore.QObject,
        event: QtCore.QEvent,
    ) -> bool:  # type: ignore[override]
        if watched is self._target and event.type() in {
            QtCore.QEvent.Move,
            QtCore.QEvent.Resize,
            QtCore.QEvent.Show,
        }:
            self.sync_geometry()
        return False

    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        pen = QtGui.QPen(QtGui.QColor(COLORS["border_hi"]))
        pen.setWidthF(1.0)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawRoundedRect(
            QtCore.QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5),
            self._radius - 0.5,
            self._radius - 0.5,
        )


class OutlinedButton(QtWidgets.QPushButton):
    """QPushButton painted with two concentric rounded outlines."""

    def __init__(self, text: str = "", primary: bool = False,
                 variant: str = "", parent=None):
        super().__init__(text, parent)
        self._primary = primary
        self._variant = variant  # "danger" | "warn" | ""
        self.setCursor(Qt.PointingHandCursor)
        self.setFocusPolicy(Qt.StrongFocus)
        self.setAttribute(Qt.WA_StyledBackground, False)
        self.setStyleSheet("")

    def sizeHint(self):  # type: ignore[override]
        sh = super().sizeHint()
        if self._primary:
            sh.setHeight(max(sh.height(), 38))
        else:
            sh.setHeight(max(sh.height(), 30))
        sh.setWidth(sh.width() + (22 if self._primary else 16))
        return sh

    def _colors(self):
        c = COLORS
        hover   = self.underMouse() and self.isEnabled()
        pressed = self.isDown()      and self.isEnabled()
        enabled = self.isEnabled()

        if self._primary:
            if not enabled:
                return c['border_lo'], c['border_hi'], c['bg_card_hi'], c['text_mute']
            # "subtle" variant: raised fill (lighter than the dialog surface),
            # accent border + accent text. bg_card_hi is the lightest surface
            # tone, so the button reads as a raised, clickable element.
            if self._variant == "subtle":
                if pressed:
                    return c['accent'], c['accent_lo'], c['bg_card'], c['accent_hi']
                if hover:
                    return c['accent_hi'], c['accent'], c['border_hi'], c['accent_hi']
                return c['accent_lo'], c['accent_hi'], c['bg_card_hi'], c['accent']
            if pressed:
                return c['accent_hi'], c['accent_lo'], c['accent_lo'], "#ffffff"
            if hover:
                return c['accent_lo'], c['accent_hi'], c['accent_hi'], "#ffffff"
            return c['accent_lo'], c['accent_hi'], c['accent'], "#ffffff"

        hov_accent = {
            "danger": c['failed'],
            "warn":   c['warn'],
        }.get(self._variant, c['accent'])

        if not enabled:
            return c['border_lo'], c['border_hi'], c['bg_card'], c['text_mute']
        if pressed:
            return c['border_hi'], c['border_lo'], c['bg_card'], c['text']
        if hover:
            return hov_accent, hov_accent, c['bg_card_hi'], c['text']
        return c['border_lo'], c['border_hi'], c['bg_card_hi'], c['text_dim']

    def paintEvent(self, _e):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)

        rect = QtCore.QRectF(self.rect())
        radius = 8 if self._primary else 7
        outer_c, inner_c, fill_c, text_c = self._colors()
        if self.hasFocus() and self.isEnabled():
            outer_c = COLORS["accent_hi"]
            inner_c = COLORS["accent"]

        fill_rect = rect.adjusted(1.5, 1.5, -1.5, -1.5)
        p.setPen(Qt.NoPen)
        p.setBrush(QtGui.QColor(fill_c))
        p.drawRoundedRect(fill_rect, radius - 1.5, radius - 1.5)

        pen = QtGui.QPen(QtGui.QColor(outer_c))
        pen.setWidthF(1.0)
        p.setPen(pen)
        p.setBrush(Qt.NoBrush)
        p.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5),
                          radius - 0.5, radius - 0.5)

        pen.setColor(QtGui.QColor(inner_c))
        p.setPen(pen)
        p.drawRoundedRect(rect.adjusted(1.5, 1.5, -1.5, -1.5),
                          radius - 1.5, radius - 1.5)

        font = self.font()
        if self._primary:
            font.setPointSize(10); font.setWeight(QtGui.QFont.Weight.DemiBold)
        else:
            font.setPointSize(9)
        p.setFont(font)
        p.setPen(QtGui.QColor(text_c))
        text_rect = rect.translated(0, 1 if self.isDown() else 0)
        p.drawText(text_rect, Qt.AlignCenter, self.text())

    def enterEvent(self, e):  # type: ignore[override]
        super().enterEvent(e)
        self.update()

    def leaveEvent(self, e):  # type: ignore[override]
        super().leaveEvent(e)
        self.update()

    def focusInEvent(self, e):  # type: ignore[override]
        super().focusInEvent(e)
        self.update()

    def focusOutEvent(self, e):  # type: ignore[override]
        super().focusOutEvent(e)
        self.update()


# ═══════════════════════════════════════════════════════════════════════════
#  Helper widgets
# ═══════════════════════════════════════════════════════════════════════════

class IconButton(QtWidgets.QToolButton):
    """Small icon-only button used in the title bar."""
    def __init__(self, glyph: str, tooltip: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("iconBtn")
        self.setToolTip(tooltip)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(26, 26)
        self.setText(glyph)
        f = QtGui.QFont()
        f.setPointSize(11)
        self.setFont(f)


class _SettingsIconButton(QtWidgets.QToolButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("iconBtn")
        self.setToolTip("Settings")
        self.setAccessibleName("Settings")
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(26, 26)

    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)

        hovered = self.isEnabled() and self.underMouse()
        if hovered:
            painter.setPen(Qt.NoPen)
            painter.setBrush(QtGui.QColor(COLORS["bg_card_hi"]))
            painter.drawRoundedRect(QtCore.QRectF(self.rect()), 6, 6)

        center = QtCore.QPointF(self.rect().center()) + QtCore.QPointF(1, 1)
        path = QtGui.QPainterPath()
        for tooth in range(8):
            angle = tooth * math.pi / 4
            for offset, radius in (
                (-0.20, 5.8), (-0.11, 7.5), (0.11, 7.5), (0.20, 5.8)
            ):
                point = QtCore.QPointF(
                    center.x() + math.cos(angle + offset) * radius,
                    center.y() + math.sin(angle + offset) * radius,
                )
                if path.elementCount() == 0:
                    path.moveTo(point)
                else:
                    path.lineTo(point)
        path.closeSubpath()

        pen = QtGui.QPen(
            QtGui.QColor(COLORS["text"] if hovered else COLORS["text_mute"]),
            1.35,
        )
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)
        painter.drawPath(path)
        painter.drawEllipse(center, 2.25, 2.25)


class TitleBar(QtWidgets.QFrame):
    """Custom title bar with status dot, title, settings, and close icons."""
    sig_settings = Signal()
    sig_sign_in  = Signal()
    sig_account  = Signal()
    sig_update   = Signal()
    sig_close    = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("titleBar")
        self.setFixedHeight(40)

        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(14, 0, 10, 0)
        lay.setSpacing(10)

        self._dot = QtWidgets.QLabel()
        self._dot.setFixedSize(10, 10)
        self._dot_role = "accent"
        self.set_dot_color("accent")
        lay.addWidget(self._dot)

        self._title = QtWidgets.QLabel("Decompile.re")
        self._title.setObjectName("titleLabel")
        lay.addWidget(self._title)
        lay.addStretch(1)

        self.btn_account = QtWidgets.QToolButton()
        self.btn_account.setObjectName("profileBtn")
        self.btn_account.setCursor(Qt.PointingHandCursor)
        self.btn_account.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.btn_account.setFixedHeight(28)
        self.btn_account.setIconSize(QSize(20, 20))
        self.btn_account.clicked.connect(self._account_clicked)
        self._signed_in = False
        self._profile_label = ""
        self._avatar_url = ""
        self._avatar_reply = None
        self._avatar_cache: dict[str, QtGui.QIcon] = {}
        self._avatar_manager = (
            QtNetwork.QNetworkAccessManager(self)
            if QtNetwork is not None else None
        )
        self.set_profile(False, "", "")

        self.btn_settings = _SettingsIconButton()
        self.btn_settings.clicked.connect(self.sig_settings.emit)

        self.btn_update = QtWidgets.QToolButton()
        self.btn_update.setObjectName("updateBtn")
        self.btn_update.setCursor(Qt.PointingHandCursor)
        self.btn_update.setText("Update")
        self.btn_update.setFixedHeight(28)
        self.btn_update.clicked.connect(self.sig_update.emit)
        self.btn_update.hide()

        lay.addWidget(self.btn_settings)
        lay.addWidget(self.btn_update)
        lay.addWidget(self.btn_account)

        self.btn_close = IconButton("✕", "Close")
        self.btn_close.clicked.connect(self.sig_close.emit)
        lay.addWidget(self.btn_close)

        self._drag_start: Optional[QPoint] = None

    def _account_clicked(self) -> None:
        if self._signed_in:
            self.sig_account.emit()
        else:
            self.sig_sign_in.emit()

    def set_profile(self, signed_in: bool, name: str = "", avatar_url: str = "") -> None:
        self._signed_in = signed_in
        self._profile_label = name if signed_in else ""
        self._avatar_url = avatar_url if signed_in else ""
        label = name if signed_in else "Sign in"
        self.btn_account.setText(("  " + label) if signed_in else label)
        self.btn_account.setToolTip(
            "Open account settings" if signed_in else "Sign in with browser"
        )
        if self._avatar_reply is not None:
            previous_reply = self._avatar_reply
            self._avatar_reply = None
            previous_reply.abort()
            previous_reply.deleteLater()
        if not signed_in:
            self.btn_account.setIcon(QtGui.QIcon())
            return

        self.btn_account.setIcon(QtGui.QIcon(self._initials_pixmap(label)))
        cached = self._avatar_cache.get(avatar_url)
        if cached is not None:
            self.btn_account.setIcon(cached)
        elif avatar_url:
            self._load_avatar(avatar_url)

    def set_update_available(self, version: str = "") -> None:
        self.btn_update.setEnabled(True)
        self.btn_update.setText("Update")
        self.btn_update.setToolTip(
            f"Install Decompile.re {version}" if version else "Update Decompile.re"
        )
        self.btn_update.setVisible(bool(version))

    def set_update_busy(self, busy: bool) -> None:
        self.btn_update.setEnabled(not busy)
        self.btn_update.setText("Updating..." if busy else "Update")

    def _load_avatar(self, avatar_url: str) -> None:
        if self._avatar_manager is None:
            return
        url = QtCore.QUrl(avatar_url)
        if not url.isValid() or url.scheme().lower() != "https":
            return

        request = QtNetwork.QNetworkRequest(url)
        request.setRawHeader(b"Accept", b"image/*")
        if hasattr(request, "setTransferTimeout"):
            request.setTransferTimeout(4_000)
        reply = self._avatar_manager.get(request)
        self._avatar_reply = reply
        reply.downloadProgress.connect(
            lambda received, _total, target=reply:
                self._limit_avatar_download(target, received)
        )
        reply.finished.connect(
            lambda target=reply, expected=avatar_url:
                self._avatar_loaded(target, expected)
        )

    @staticmethod
    def _limit_avatar_download(reply, received: int) -> None:
        if received > 1_048_576:
            reply.abort()

    def _avatar_loaded(self, reply, expected_url: str) -> None:
        if reply is self._avatar_reply:
            self._avatar_reply = None
        try:
            no_error = getattr(
                getattr(QtNetwork.QNetworkReply, "NetworkError",
                        QtNetwork.QNetworkReply),
                "NoError",
            )
            if reply.error() != no_error:
                return
            if reply.url().scheme().lower() != "https":
                return
            data = bytes(reply.readAll())
            if not data or len(data) > 1_048_576:
                return

            buffer = QtCore.QBuffer()
            buffer.setData(data)
            read_only = getattr(
                getattr(QtCore.QIODevice, "OpenModeFlag", QtCore.QIODevice),
                "ReadOnly",
            )
            if not buffer.open(read_only):
                return
            reader = QtGui.QImageReader(buffer)
            reader.setDecideFormatFromContent(True)
            image_size = reader.size()
            if (
                not image_size.isValid()
                or image_size.width() > 2_048
                or image_size.height() > 2_048
            ):
                return
            reader.setScaledSize(
                image_size.scaled(64, 64, Qt.KeepAspectRatio)
            )
            image = reader.read()
            if image.isNull():
                return
            icon = QtGui.QIcon(
                self._circular_pixmap(QtGui.QPixmap.fromImage(image), 20)
            )
            if len(self._avatar_cache) >= 16:
                self._avatar_cache.pop(next(iter(self._avatar_cache)))
            self._avatar_cache[expected_url] = icon
            if self._signed_in and self._avatar_url == expected_url:
                self.btn_account.setIcon(icon)
        finally:
            reply.deleteLater()

    @staticmethod
    def _circular_pixmap(source: QtGui.QPixmap, size: int) -> QtGui.QPixmap:
        """Crop and clip a remote avatar so Qt5 and Qt6 render it identically."""
        scaled = source.scaled(
            size, size, Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation
        )
        canvas = QtGui.QPixmap(size, size)
        canvas.fill(Qt.transparent)

        painter = QtGui.QPainter(canvas)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        path = QtGui.QPainterPath()
        path.addEllipse(0, 0, size, size)
        painter.setClipPath(path)
        left = (scaled.width() - size) // 2
        top = (scaled.height() - size) // 2
        painter.drawPixmap(-left, -top, scaled)
        painter.end()
        return canvas

    def _initials_pixmap(self, label: str) -> QtGui.QPixmap:
        initial = (label.strip()[:1] or "?").upper()
        pix = QtGui.QPixmap(20, 20)
        pix.fill(Qt.transparent)
        p = QtGui.QPainter(pix)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        p.setBrush(QtGui.QColor(COLORS["accent"]))
        p.setPen(Qt.NoPen)
        p.drawEllipse(0, 0, 20, 20)
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setWeight(QtGui.QFont.Weight.DemiBold)
        p.setFont(font)
        p.setPen(QtGui.QColor("#ffffff"))
        p.drawText(pix.rect(), Qt.AlignCenter, initial)
        p.end()
        return pix

    def set_title(self, text: str) -> None:
        self._title.setText(text)

    def set_dot_color(self, role: str, pulse: bool = False) -> None:
        """`role` is a COLORS key ("accent", "analyzing", "done", "failed",
        "warn"). Stored so the dot can be re-resolved on a theme switch. A raw
        hex string is still accepted (falls through COLORS.get)."""
        self._dot_role = role
        col = COLORS.get(role, role)
        self._dot.setStyleSheet(f"background: {col}; border-radius: 5px;")

    def refresh_theme(self) -> None:
        """Re-resolve the dot colour for the current theme + role."""
        self.set_dot_color(self._dot_role)
        if self._signed_in and self._avatar_url not in self._avatar_cache:
            self.btn_account.setIcon(
                QtGui.QIcon(self._initials_pixmap(self._profile_label))
            )

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self._drag_start = e.globalPos() - self.window().frameGeometry().topLeft()
            e.accept()

    def mouseMoveEvent(self, e):
        if self._drag_start is not None and e.buttons() & Qt.LeftButton:
            self.window().move(e.globalPos() - self._drag_start)
            e.accept()

    def mouseReleaseEvent(self, _e):
        self._drag_start = None


class TargetPill(QtWidgets.QFrame):
    """The function-name pill at the top of the compact prompt."""
    sig_refresh = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("targetPill")
        self.setSizePolicy(QtWidgets.QSizePolicy.Maximum, QtWidgets.QSizePolicy.Fixed)

        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 6, 0)
        lay.setSpacing(8)

        lbl = QtWidgets.QLabel("Target")
        lbl.setObjectName("targetLabel")
        lay.addWidget(lbl)

        self._name = QtWidgets.QLabel("—")
        self._name.setObjectName("targetName")
        lay.addWidget(self._name)

        self._ea = QtWidgets.QLabel("")
        self._ea.setObjectName("targetEA")
        lay.addWidget(self._ea)

        btn = QtWidgets.QToolButton()
        btn.setObjectName("iconBtn")
        btn.setText("↻")
        btn.setToolTip("Refresh from cursor")
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedSize(20, 20)
        btn.clicked.connect(self.sig_refresh.emit)
        lay.addWidget(btn)

    def set_target(self, name: str, ea: Optional[int]) -> None:
        if ea is None:
            self._name.setText("⚠ no function at cursor")
            self._ea.setText("")
        else:
            self._name.setText(name)
            self._ea.setText(f"{ea:#x}")


# ═══════════════════════════════════════════════════════════════════════════
#  Settings dialog
# ═══════════════════════════════════════════════════════════════════════════

class _BrowserSignInWorker(QtCore.QObject):
    sig_done = Signal(object)
    sig_error = Signal(str)
    sig_finished = Signal()

    def __init__(self):
        super().__init__()
        self._cancelled = threading.Event()

    def cancel(self):
        self._cancelled.set()

    def run(self):
        try:
            self.sig_done.emit(
                browser_auth.sign_in_with_browser(cancel_event=self._cancelled)
            )
        except browser_auth.BrowserAuthCancelled:
            pass
        except Exception as e:
            self.sig_error.emit(str(e))
        finally:
            self.sig_finished.emit()


class _UpdateCheckWorker(QtCore.QObject):
    sig_done = Signal(object)
    sig_finished = Signal()

    def __init__(self):
        super().__init__()
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        session = None
        try:
            session = create_update_session(self._cancelled)
            release_client = updater.GitHubReleaseClient(
                session=session
            )
            self.sig_done.emit(
                updater.check_for_update(
                    cancel_event=self._cancelled,
                    client=release_client,
                )
            )
        except updater.UpdateCancelled:
            pass
        except Exception as exc:
            print(f"[Decompile.re] Update check failed: {exc}")
            self.sig_done.emit(None)
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
            self.sig_finished.emit()


class _UpdateInstallWorker(QtCore.QObject):
    sig_done = Signal(object)
    sig_error = Signal(object)
    sig_finished = Signal()

    def __init__(self):
        super().__init__()
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    def run(self) -> None:
        session = None
        try:
            session = create_update_session(self._cancelled)
            release_client = updater.GitHubReleaseClient(
                session=session
            )
            self.sig_done.emit(
                updater.install_latest(
                    cancel_event=self._cancelled,
                    client=release_client,
                )
            )
        except updater.UpdateCancelled:
            pass
        except Exception as exc:
            self.sig_error.emit(exc)
        finally:
            close = getattr(session, "close", None)
            if callable(close):
                close()
            self.sig_finished.emit()


class _SendChatWorker(QtCore.QObject):
    sig_error = Signal(object, str)
    sig_finished = Signal(object)

    def __init__(self, entry, message: str, current_view: dict):
        super().__init__()
        self._entry = entry
        self._message = message
        self._current_view = dict(current_view)

    def run(self):
        try:
            self._entry.worker.send_chat(
                self._message,
                current_view=self._current_view,
            )
        except Exception as exc:
            self.sig_error.emit(self._entry, str(exc))
        finally:
            self.sig_finished.emit(self._entry)


class _VerifySignInWorker(QtCore.QObject):
    sig_done = Signal(object)

    def run(self):
        self.sig_done.emit(auth_state.verify_saved_sign_in())


class _DeleteHistoryWorker(QtCore.QObject):
    sig_done = Signal()
    sig_error = Signal(str)

    def __init__(self, analysis_worker):
        super().__init__()
        self._analysis_worker = analysis_worker

    def run(self):
        try:
            self._analysis_worker.delete_history()
            self.sig_done.emit()
        except Exception as exc:
            self.sig_error.emit(str(exc))


class _RenameHistoryWorker(QtCore.QObject):
    sig_done = Signal(object, str)
    sig_error = Signal(object, str)

    def __init__(self, entry, name: str):
        super().__init__()
        self._entry = entry
        self._name = name

    def run(self):
        try:
            renamed = self._entry.worker.rename_history(self._name)
            self.sig_done.emit(self._entry, renamed)
        except Exception as exc:
            self.sig_error.emit(self._entry, str(exc))


class _LoadSessionNamesWorker(QtCore.QObject):
    sig_done = Signal(str, object)
    sig_error = Signal(str)

    def __init__(self, account_id: str):
        super().__init__()
        self._account_id = account_id

    def run(self):
        try:
            self.sig_done.emit(
                self._account_id,
                load_session_names(self._account_id),
            )
        except Exception as exc:
            self.sig_error.emit(str(exc))


class _LoadUsageWorker(QtCore.QObject):
    sig_done = Signal(str, float)
    sig_finished = Signal()

    def __init__(self, account_id: str):
        super().__init__()
        self._account_id = account_id

    def run(self):
        try:
            percent = load_usage_percent(self._account_id)
            self.sig_done.emit(self._account_id, percent)
        except Exception:
            pass
        finally:
            self.sig_finished.emit()


class _LoadSessionDetailWorker(QtCore.QObject):
    sig_done = Signal(object, object)
    sig_error = Signal(object, str)

    def __init__(self, entry):
        super().__init__()
        self._entry = entry

    def run(self):
        try:
            self.sig_done.emit(self._entry, self._entry.worker.load_history())
        except Exception as exc:
            self.sig_error.emit(self._entry, str(exc))


class SettingsDialog(RoundedDialogMixin, QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"{PLUGIN_NAME} — Settings")
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self.setAutoFillBackground(False)
        self.setStyleSheet(main_qss())
        self.setMinimumWidth(500)
        self._browser_auth_thread = None
        self._browser_auth_worker = None
        self._pending_close_result = None
        self._populating_accounts = False
        self._build_ui()
        self._populate()

    def _build_ui(self):
        dlg_lay = QtWidgets.QVBoxLayout(self)
        dlg_lay.setContentsMargins(0, 0, 0, 0)
        dlg_lay.setSpacing(0)

        surface = QtWidgets.QFrame()
        surface.setObjectName("rootSurface")
        dlg_lay.addWidget(surface)

        root = QtWidgets.QVBoxLayout(surface)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        title = TitleBar()
        title.set_title("Settings")
        title.sig_close.connect(self.reject)
        title.btn_settings.hide()
        title.btn_account.hide()
        root.addWidget(title)

        body = QtWidgets.QWidget()
        body.setObjectName("settingsBody")
        body_lay = QtWidgets.QVBoxLayout(body)
        body_lay.setContentsMargins(22, 18, 22, 18)
        body_lay.setSpacing(16)

        # ── SERVER group ───────────────────────────────────────────────────
        grp_server = QtWidgets.QGroupBox("ACCOUNT")
        f1 = QtWidgets.QFormLayout(grp_server)
        f1.setSpacing(10)

        self.lbl_token_status = QtWidgets.QLabel("")
        self.lbl_token_status.setObjectName("hintLabel")
        self.cmb_account = QtWidgets.QComboBox()
        self.cmb_account.currentIndexChanged.connect(self._account_changed)
        self.btn_browser_signin = OutlinedButton("Sign in with browser", primary=False)
        self.btn_browser_signin.clicked.connect(self._sign_in_with_browser)

        f1.addRow("Active account",  self.cmb_account)
        f1.addRow("",              self.lbl_token_status)
        f1.addRow("",              self.btn_browser_signin)
        body_lay.addWidget(grp_server)

        # ── ANALYSIS group ─────────────────────────────────────────────────
        grp_an = QtWidgets.QGroupBox("ANALYSIS")
        f2 = QtWidgets.QFormLayout(grp_an)
        f2.setSpacing(10)

        self.chk_limit_depth = QtWidgets.QCheckBox("Limit max call depth")
        self.spin_depth = QtWidgets.QSpinBox()
        self.spin_depth.setRange(1, 10)
        self.chk_limit_depth.toggled.connect(self.spin_depth.setEnabled)

        self.chk_renames = QtWidgets.QCheckBox("Apply renames")
        self.chk_types   = QtWidgets.QCheckBox("Apply struct member type changes")
        self.chk_structs = QtWidgets.QCheckBox("Create new structures")
        self.cmb_rename_style = QtWidgets.QComboBox()
        self.cmb_rename_style.addItem("snake_case", "snake_case")
        self.cmb_rename_style.addItem("camelCase", "camelCase")
        self.cmb_rename_style.addItem("PascalCase", "PascalCase")
        self.cmb_rename_style.setToolTip("Preferred style for function, global, local, and parameter renames.")
        self.cmb_struct_member_style = QtWidgets.QComboBox()
        self.cmb_struct_member_style.addItem("Default", "default")
        self.cmb_struct_member_style.addItem("m_ prefix", "m_prefix")
        self.cmb_struct_member_style.addItem("typed m_ prefix", "typed_m_prefix")
        self.cmb_struct_member_style.setToolTip("Preferred style for structure member names.")

        f2.addRow("", self.chk_limit_depth)
        f2.addRow("Max call depth", self.spin_depth)
        f2.addRow("Rename style", self.cmb_rename_style)
        f2.addRow("Struct member style", self.cmb_struct_member_style)
        f2.addRow("", self.chk_renames)
        f2.addRow("", self.chk_types)
        f2.addRow("", self.chk_structs)
        body_lay.addWidget(grp_an)

        # ── APPEARANCE group ───────────────────────────────────────────────
        grp_ap = QtWidgets.QGroupBox("APPEARANCE")
        f3 = QtWidgets.QFormLayout(grp_ap)
        f3.setSpacing(10)
        self.cmb_theme = QtWidgets.QComboBox()
        for _name in theme_names():
            self.cmb_theme.addItem(_name)
        self.cmb_theme.setToolTip("Colour theme — applied on Save")
        f3.addRow("Theme", self.cmb_theme)
        body_lay.addWidget(grp_ap)

        row = QtWidgets.QHBoxLayout()
        row.addStretch(1)
        cancel = OutlinedButton("Cancel", primary=False)
        cancel.clicked.connect(self.reject)
        ok = OutlinedButton("Save", primary=True)
        ok.clicked.connect(self._on_ok)
        row.addWidget(cancel)
        row.addWidget(ok)
        body_lay.addLayout(row)

        root.addWidget(body)

    def _populate(self):
        s = g_settings
        max_call_depth = s.get("max_call_depth", 0)
        limit_call_depth = max_call_depth > 0
        self.spin_depth.setValue(max_call_depth if limit_call_depth else 2)
        self.chk_limit_depth.setChecked(limit_call_depth)
        self.spin_depth.setEnabled(limit_call_depth)
        self.chk_renames.setChecked(s.get("auto_renames", True))
        self.chk_types.setChecked(s.get("auto_types", True))
        self.chk_structs.setChecked(s.get("auto_structs", True))
        _idx = self.cmb_rename_style.findData(s.get("rename_style", "snake_case"))
        self.cmb_rename_style.setCurrentIndex(_idx if _idx >= 0 else 0)
        _idx = self.cmb_struct_member_style.findData(s.get("struct_member_style", "default"))
        self.cmb_struct_member_style.setCurrentIndex(_idx if _idx >= 0 else 0)
        _idx = self.cmb_theme.findText(s.get("theme", "Nord"))
        self.cmb_theme.setCurrentIndex(_idx if _idx >= 0 else 0)
        self._populate_accounts()
        prof = auth_state.profile()
        if prof["verified"] and prof["name"]:
            self.lbl_token_status.setText(f"Signed in as {prof['name']}.")
        elif secret_store.load_refresh_token(server_url=g_settings.get("server_url", "")):
            self.lbl_token_status.setText("Saved sign-in will be verified before analysis.")
        else:
            self.lbl_token_status.setText("Not signed in.")

    def _populate_accounts(self):
        self._populating_accounts = True
        try:
            self.cmb_account.clear()
            accounts = auth_state.saved_accounts()
            active = auth_state.active_account_id()
            if not accounts:
                self.cmb_account.addItem("No saved accounts", "")
                self.cmb_account.setEnabled(False)
                return
            for account in accounts:
                label = account.get("name") or account.get("email") or account["account_id"]
                email = account.get("email", "")
                if email and email != label:
                    label = f"{label} ({email})"
                self.cmb_account.addItem(label, account["account_id"])
            idx = self.cmb_account.findData(active)
            self.cmb_account.setCurrentIndex(idx if idx >= 0 else 0)
            self.cmb_account.setEnabled(len(accounts) > 1)
        finally:
            self._populating_accounts = False

    def _account_changed(self, _idx: int = -1):
        if self._populating_accounts:
            return
        account_id = self.cmb_account.currentData()
        if account_id:
            auth_state.set_active_account(str(account_id))
            self._populate()

    def _sign_in_with_browser(self):
        self.btn_browser_signin.setEnabled(False)
        self.btn_browser_signin.setText("Waiting for browser...")
        self.lbl_token_status.setText("Browser sign-in started. Complete it in your browser.")

        thread = QtCore.QThread(self)
        worker = _BrowserSignInWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._browser_sign_in_done)
        worker.sig_error.connect(self._browser_sign_in_error)
        worker.sig_finished.connect(thread.quit)
        worker.sig_finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._browser_sign_in_finished)
        self._browser_auth_thread = thread
        self._browser_auth_worker = worker
        thread.start()

    def _browser_sign_in_done(self, result: dict):
        refresh_token = str(result.get("refresh_token", "") or "")
        if not refresh_token:
            self._browser_sign_in_error("Browser sign-in did not return a refresh token.")
            return
        account_id = auth_state.account_id_for_data(result)
        server_url = str(
            result.get("server_url", "") or g_settings.get("server_url", "")
        )
        try:
            secret_store.save_refresh_token(
                refresh_token, account_id, server_url
            )
        except secret_store.CredentialStoreUnavailable as e:
            self._browser_sign_in_error(str(e))
            return
        reset_shared_auth_context(account_id, server_url)
        auth_state.save_signed_in_profile(result, verified=True, account_id=account_id)
        self._populate_accounts()
        prof = auth_state.profile()
        self.lbl_token_status.setText(f"Signed in as {prof['name']}.")

    def _browser_sign_in_error(self, message: str):
        self.lbl_token_status.setText("Browser sign-in failed.")
        QtWidgets.QMessageBox.critical(self, "Browser sign-in failed", message)

    def _browser_sign_in_finished(self):
        self.btn_browser_signin.setEnabled(True)
        self.btn_browser_signin.setText("Sign in with browser")
        self._browser_auth_thread = None
        self._browser_auth_worker = None
        if self._pending_close_result is not None:
            result = self._pending_close_result
            self._pending_close_result = None
            super().done(result)

    def _finish_dialog(self, result: int) -> None:
        thread = self._browser_auth_thread
        if thread is not None and thread.isRunning():
            self._pending_close_result = result
            if self._browser_auth_worker is not None:
                self._browser_auth_worker.cancel()
            self.setEnabled(False)
            self.hide()
            return
        super().done(result)

    def accept(self) -> None:
        self._finish_dialog(QtWidgets.QDialog.Accepted)

    def reject(self) -> None:
        self._finish_dialog(QtWidgets.QDialog.Rejected)

    def closeEvent(self, event) -> None:
        thread = self._browser_auth_thread
        if thread is not None and thread.isRunning():
            event.ignore()
            self.reject()
            return
        super().closeEvent(event)

    def _on_ok(self):
        new_theme = self.cmb_theme.currentText()
        theme_changed = new_theme != g_settings.get("theme")
        g_settings.update({
            "max_call_depth": (
                self.spin_depth.value()
                if self.chk_limit_depth.isChecked()
                else 0
            ),
            "auto_renames":         self.chk_renames.isChecked(),
            "auto_types":           self.chk_types.isChecked(),
            "auto_structs":         self.chk_structs.isChecked(),
            "rename_style":         self.cmb_rename_style.currentData() or "snake_case",
            "struct_member_style":  self.cmb_struct_member_style.currentData() or "default",
            "theme":                new_theme,
        })
        save_settings()
        if theme_changed:
            apply_theme(new_theme)
            self._restyle_open_windows()
        self.accept()

    def _restyle_open_windows(self) -> None:
        """Re-apply the QSS (which reads the now-updated COLORS) to this dialog
        and the parent analysis dialog, then repaint custom-painted widgets.
        Newly created widgets (chat bubbles, graph nodes) pick up the theme on
        their own; this refreshes the chrome that is already on screen."""
        qss = main_qss()
        targets = [self]
        par = self.parent()
        if isinstance(par, QtWidgets.QWidget):
            targets.append(par.window())
        for w in targets:
            try:
                w.setStyleSheet(qss)
                # Widgets that bake COLORS into inline stylesheets at build time
                # need an explicit re-style — the cascaded QSS doesn't reach them.
                for cls in (ChatMessageWidget, StreamingChatMessageWidget,
                            WorkingWidget, FunctionGraphView, TitleBar):
                    for inst in w.findChildren(cls):
                        if cls in (FunctionGraphView, TitleBar):
                            inst.refresh_theme()
                        else:
                            inst.restyle()
                for child in w.findChildren(QtWidgets.QWidget):
                    child.update()
                w.update()
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
#  Small custom widgets — spinner + shimmer
# ═══════════════════════════════════════════════════════════════════════════

class SpinnerLabel(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(14, 14)
        self._angle = 0
        self._active = False
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)

    def set_active(self, active: bool) -> None:
        self._active = active
        if active:
            self._timer.start(40)
        else:
            self._timer.stop()
            self.update()

    def _tick(self):
        self._angle = (self._angle + 18) % 360
        self.update()

    def paintEvent(self, _e):
        if not self._active:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        rect = QtCore.QRect(1, 1, 12, 12)
        pen = QtGui.QPen(QtGui.QColor(COLORS["border"]))
        pen.setWidthF(1.5)
        p.setPen(pen)
        p.drawArc(rect, 0, 360 * 16)
        pen.setColor(QtGui.QColor(COLORS["accent"]))
        p.setPen(pen)
        p.drawArc(rect, -self._angle * 16, 100 * 16)


class _SessionLoadingOverlay(QtWidgets.QWidget):
    def __init__(self, parent: QtWidgets.QWidget, excluded_widget):
        super().__init__(parent)
        self._excluded_widget = excluded_widget
        self._angle = 0
        self._timer = QtCore.QTimer(self)
        self._timer.setInterval(32)
        self._timer.timeout.connect(self._tick)
        parent.installEventFilter(self)
        self.hide()

    def set_active(self, active: bool) -> None:
        if active:
            self.setGeometry(self.parentWidget().rect())
            self._update_mask()
            self.show()
            self.raise_()
            self._timer.start()
        else:
            self._timer.stop()
            self.hide()

    def _tick(self) -> None:
        self._angle = (self._angle + 12) % 360
        self.update()

    def _update_mask(self) -> None:
        excluded = self._excluded_widget
        # Avoid QWidget.mapTo() here.  IDA 8.3 ships Qt 5.15.3, which can
        # dereference a null QWidget during nested signal delivery (notably
        # when a session row is double-clicked).  The tab and overlay share
        # the same root parent, so accumulating child positions is equivalent
        # and does not cross the fragile Qt mapping path.
        top_left = QtCore.QPoint(0, 0)
        parent = self.parentWidget()
        widget = excluded
        while widget is not None and widget is not parent:
            top_left += widget.pos()
            widget = widget.parentWidget()
        if widget is None:
            return
        cutout = QtCore.QRect(top_left, excluded.size()).adjusted(-1, -1, 1, 1)
        self.setMask(
            QtGui.QRegion(self.rect()).subtracted(QtGui.QRegion(cutout))
        )

    def eventFilter(self, obj, event):
        if obj is self.parentWidget() and event.type() in (
            QtCore.QEvent.Resize,
        ):
            # Qt 5.15 can deliver the parent's Show event before all child
            # widgets have a valid native QWidget hierarchy.  Mapping the
            # excluded tab during that event can crash inside QWidget::mapTo.
            # set_active() performs the same update when the overlay is
            # actually needed, after the hierarchy is fully constructed.
            if self.isVisible():
                self.setGeometry(self.parentWidget().rect())
                self._update_mask()
        return False

    def paintEvent(self, _event) -> None:
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing, True)
        painter.fillRect(self.rect(), QtGui.QColor(0, 0, 0, 170))

        spinner_size = 38
        spinner = QtCore.QRectF(
            (self.width() - spinner_size) / 2,
            (self.height() - spinner_size) / 2,
            spinner_size,
            spinner_size,
        )
        base_pen = QtGui.QPen(QtGui.QColor(COLORS["border_hi"]))
        base_pen.setWidthF(3.0)
        painter.setPen(base_pen)
        painter.drawArc(spinner, 0, 360 * 16)

        active_pen = QtGui.QPen(QtGui.QColor(COLORS["accent_hi"]))
        active_pen.setWidthF(3.0)
        active_pen.setCapStyle(Qt.RoundCap)
        painter.setPen(active_pen)
        painter.drawArc(spinner, -self._angle * 16, 105 * 16)


class ShimmerBar(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(2)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self._pos = -0.3
        self._active = False
        self._timer = QtCore.QTimer(self)
        self._timer.timeout.connect(self._tick)

    def set_active(self, active: bool) -> None:
        self._active = active
        if active:
            self._timer.start(30)
        else:
            self._timer.stop()
            self.update()

    def _tick(self):
        self._pos += 0.015
        if self._pos > 1.3:
            self._pos = -0.3
        self.update()

    def paintEvent(self, _e):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing, True)
        w, h = self.width(), self.height()
        p.fillRect(0, 0, w, h, QtGui.QColor(COLORS["border_soft"]))
        if not self._active:
            return
        band_w = w * 0.3
        x = int(self._pos * w)
        grad = QtGui.QLinearGradient(x, 0, x + band_w, 0)
        c0 = QtGui.QColor(COLORS["accent"]); c0.setAlpha(0)
        c1 = QtGui.QColor(COLORS["accent"])
        c2 = QtGui.QColor(COLORS["accent"]); c2.setAlpha(0)
        grad.setColorAt(0.0, c0)
        grad.setColorAt(0.5, c1)
        grad.setColorAt(1.0, c2)
        p.fillRect(QtCore.QRect(x, 0, int(band_w), h), QtGui.QBrush(grad))


# ???????????????????????????????????????????????????????????????????????????
#  Chat thread widgets
# ???????????????????????????????????????????????????????????????????????????

class ShimmerTextLabel(QtWidgets.QWidget):
    """Gradient text label with an animated bright-band shimmer sweep.

    While ``set_active(True)`` the shimmer loops continuously.
    After ``set_active(False)`` the gradient is drawn statically.
    """

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._text    = text
        self._pos     = -0.5       # shimmer band centre, normalised –0.5 → 1.5
        self._active  = False
        self._font    = QtGui.QFont()
        self._font.setPixelSize(13)            # match font-size: 13px in QSS
        self._font.setWeight(QtGui.QFont.Weight.Medium)
        self._timer   = QtCore.QTimer(self)
        self._timer.setInterval(32)            # ~30 fps — half speed
        self._timer.timeout.connect(self._tick)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Fixed)
        self.setAutoFillBackground(False)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)

    def set_text(self, text: str) -> None:
        self._text = text
        self.update()

    def set_active(self, active: bool) -> None:
        self._active = active
        if active:
            self._pos = -0.5
            self._timer.start()
        else:
            self._timer.stop()
            self.update()

    def sizeHint(self) -> QtCore.QSize:
        fm = QtGui.QFontMetrics(self._font)
        return QtCore.QSize(fm.horizontalAdvance(self._text) + 24, fm.height() + 10)

    def _tick(self) -> None:
        self._pos += 0.018
        if self._pos > 1.5:
            self._pos = -0.5
        self.update()

    def paintEvent(self, _e) -> None:  # type: ignore[override]
        if not self._text:
            return
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setRenderHint(QtGui.QPainter.TextAntialiasing)
        w, h = self.width(), self.height()

        # Build text path so we can fill with a gradient brush. Text starts at
        # x=0 (no internal indent) so it aligns with the header's left edge —
        # i.e. the same X the chevron occupies in the done state.
        fm     = QtGui.QFontMetrics(self._font)
        base_y = (h + fm.ascent() - fm.descent()) // 2
        path   = QtGui.QPainterPath()
        path.addText(0, base_y, self._font, self._text)

        # Theme-derived base gradient stays legible on dark and light palettes.
        base_grad = QtGui.QLinearGradient(0, 0, w, 0)
        base_grad.setColorAt(0.0, QtGui.QColor(COLORS["text_mute"]))
        base_grad.setColorAt(0.55, QtGui.QColor(COLORS["text_dim"]))
        base_grad.setColorAt(1.0, QtGui.QColor(COLORS["text_mute"]))
        p.fillPath(path, QtGui.QBrush(base_grad))

        # Accent shimmer clipped to the text glyphs.
        if self._active:
            band_w = w * 0.35
            bx     = self._pos * w
            shine  = QtGui.QLinearGradient(bx, 0, bx + band_w, 0)
            edge = QtGui.QColor(COLORS["accent_hi"]); edge.setAlpha(0)
            peak = QtGui.QColor(COLORS["accent_hi"]); peak.setAlpha(220)
            shine.setColorAt(0.0, edge)
            shine.setColorAt(0.45, peak)
            shine.setColorAt(1.0, edge)
            p.save()
            p.setClipPath(path)
            p.fillRect(QtCore.QRectF(bx, 0, band_w, h), QtGui.QBrush(shine))
            p.restore()



class _ActivityChevron(QtWidgets.QWidget):
    """Small animated disclosure chevron without a button frame."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rotation = 0.0
        self.setFixedSize(16, 16)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._animation = QPropertyAnimation(self, b"rotation", self)
        self._animation.setDuration(MOTION_FAST_MS)
        self._animation.setEasingCurve(QEasingCurve.OutCubic)

    def _get_rotation(self) -> float:
        return self._rotation

    def _set_rotation(self, value: float) -> None:
        self._rotation = float(value)
        self.update()

    rotation = Property(float, _get_rotation, _set_rotation)

    def set_expanded(self, expanded: bool) -> None:
        target = 90.0 if expanded else 0.0
        if abs(self._rotation - target) < 0.1:
            return
        self._animation.stop()
        self._animation.setStartValue(self._rotation)
        self._animation.setEndValue(target)
        self._animation.start()

    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.translate(self.rect().center())
        painter.rotate(self._rotation)
        pen = QtGui.QPen(QtGui.QColor(COLORS["text_mute"]), 1.7)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        path = QtGui.QPainterPath()
        path.moveTo(-2.5, -4.0)
        path.lineTo(2.0, 0.0)
        path.lineTo(-2.5, 4.0)
        painter.drawPath(path)


def _draw_pencil_glyph(
    painter: QtGui.QPainter,
    center: QtCore.QPointF,
) -> None:
    cx = float(center.x())
    cy = float(center.y())
    pencil = QtGui.QPainterPath()
    pencil.moveTo(cx - 4.5, cy + 2.8)
    pencil.lineTo(cx + 2.6, cy - 4.3)
    pencil.quadTo(cx + 3.5, cy - 5.2, cx + 4.4, cy - 4.3)
    pencil.lineTo(cx + 5.3, cy - 3.4)
    pencil.quadTo(cx + 6.2, cy - 2.5, cx + 5.3, cy - 1.6)
    pencil.lineTo(cx - 1.8, cy + 5.5)
    pencil.lineTo(cx - 5.8, cy + 6.8)
    pencil.closeSubpath()
    painter.drawPath(pencil)
    painter.drawLine(
        QtCore.QPointF(cx - 4.5, cy + 2.8),
        QtCore.QPointF(cx - 1.8, cy + 5.5),
    )
    painter.drawLine(
        QtCore.QPointF(cx + 2.3, cy - 4.0),
        QtCore.QPointF(cx + 5.0, cy - 1.3),
    )


_ACTIVITY_NOTE_TOOLS = {
    "add_note",
    "replace_note",
    "move_note",
    "remove_note",
    "remove_section",
}

_ACTIVITY_RENAME_KINDS = {
    "function_rename",
    "parameter_renames",
    "local_renames",
    "global_rename",
    "rename_section",
}

_ZERO_WIDTH_WRAP = "\u200b"


def _text_advance(metrics: QtGui.QFontMetrics, text: str) -> int:
    horizontal_advance = getattr(metrics, "horizontalAdvance", None)
    if callable(horizontal_advance):
        return int(horizontal_advance(text))
    return int(metrics.width(text))


def _add_character_wrap_fallback(
    text: str,
    metrics: QtGui.QFontMetrics,
    width: int,
) -> str:
    """Keep word wrapping, but let an over-wide token break by character."""
    text = str(text or "")
    width = max(1, int(width))

    def add_breaks(match: re.Match) -> str:
        token = match.group(0)
        if _text_advance(metrics, token) <= width:
            return token
        return _ZERO_WIDTH_WRAP.join(token)

    return re.sub(r"\S+", add_breaks, text)


class _FallbackWrapLabel(QtWidgets.QLabel):
    """QLabel with word-first wrapping and an over-wide-token fallback."""

    def __init__(
        self,
        text: str = "",
        parent=None,
        *,
        horizontal_inset: int = 0,
    ):
        self._source_text = ""
        self._wrap_width = -1
        self._horizontal_inset = max(0, int(horizontal_inset))
        super().__init__("", parent)
        self.setWordWrap(True)
        self.setText(text)

    def setText(self, text: str) -> None:  # type: ignore[override]
        self._source_text = str(text or "")
        self._wrap_width = -1
        self._refresh_wrapped_text()

    def _refresh_wrapped_text(self) -> None:
        width = max(
            1,
            self.contentsRect().width() - self._horizontal_inset,
        )
        if width == self._wrap_width:
            return
        self._wrap_width = width
        wrapped = _add_character_wrap_fallback(
            self._source_text,
            self.fontMetrics(),
            width,
        )
        if wrapped != super().text():
            super().setText(wrapped)

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._refresh_wrapped_text()

    def changeEvent(self, event) -> None:  # type: ignore[override]
        super().changeEvent(event)
        event_type = event.type()
        metric_change_types = {
            value
            for value in (
                getattr(QtCore.QEvent, "FontChange", None),
                getattr(QtCore.QEvent, "StyleChange", None),
                getattr(QtCore.QEvent, "ApplicationFontChange", None),
            )
            if value is not None
        }
        if event_type in metric_change_types:
            self._wrap_width = -1
            self._refresh_wrapped_text()


def _activity_color_key(kind: str) -> str:
    if kind in {"error", "failed"}:
        return "failed"
    if kind in {"warn", "warning"}:
        return "warn"
    if kind in {"success", "result", "done", "completed"}:
        return "done"
    if kind in {"skipped", "skipped_callees"}:
        return "text_mute"
    return "accent"


def _paint_activity_icon(
    painter: QtGui.QPainter,
    kind: str,
    top_left: Optional[QtCore.QPointF] = None,
) -> None:
    painter.save()
    if top_left is not None:
        painter.translate(top_left)
    painter.setRenderHint(QtGui.QPainter.Antialiasing)

    accent = QtGui.QColor(COLORS[_activity_color_key(kind)])
    fill = QtGui.QColor(accent)
    fill.setAlpha(24)
    outline = QtGui.QColor(accent)
    outline.setAlpha(72)
    painter.setPen(QtGui.QPen(outline, 1))
    painter.setBrush(fill)
    painter.drawRoundedRect(QtCore.QRectF(1.5, 1.5, 21.0, 21.0), 5.0, 5.0)

    pen = QtGui.QPen(accent, 1.55)
    pen.setCapStyle(Qt.RoundCap)
    pen.setJoinStyle(Qt.RoundJoin)
    painter.setPen(pen)
    painter.setBrush(Qt.NoBrush)

    if kind in {"get_pseudocode", "get_pseudocodes", "read_pseudocode"}:
        painter.drawLine(QtCore.QPointF(9.0, 8.0), QtCore.QPointF(6.0, 12.0))
        painter.drawLine(QtCore.QPointF(6.0, 12.0), QtCore.QPointF(9.0, 16.0))
        painter.drawLine(QtCore.QPointF(15.0, 8.0), QtCore.QPointF(18.0, 12.0))
        painter.drawLine(QtCore.QPointF(18.0, 12.0), QtCore.QPointF(15.0, 16.0))
        painter.drawLine(QtCore.QPointF(13.5, 7.5), QtCore.QPointF(10.5, 16.5))
    elif kind in {"reverse_functions", "callees", "virtual_call"}:
        painter.drawLine(QtCore.QPointF(8.0, 12.0), QtCore.QPointF(15.0, 8.0))
        painter.drawLine(QtCore.QPointF(8.0, 12.0), QtCore.QPointF(15.0, 16.0))
        painter.setBrush(accent)
        for point in ((7.0, 12.0), (16.0, 7.5), (16.0, 16.5)):
            painter.drawEllipse(QtCore.QPointF(*point), 1.8, 1.8)
    elif kind in {"get_memory", "get_memory_ranges", "struct_created", "struct_updated"}:
        painter.drawRoundedRect(
            QtCore.QRectF(7.0, 7.0, 10.0, 10.0),
            1.5,
            1.5,
        )
        for pos in (9.0, 12.0, 15.0):
            painter.drawLine(QtCore.QPointF(pos, 5.0), QtCore.QPointF(pos, 7.0))
            painter.drawLine(QtCore.QPointF(pos, 17.0), QtCore.QPointF(pos, 19.0))
            painter.drawLine(QtCore.QPointF(5.0, pos), QtCore.QPointF(7.0, pos))
            painter.drawLine(QtCore.QPointF(17.0, pos), QtCore.QPointF(19.0, pos))
    elif kind in {
        "get_value_from_name",
        "get_values_from_names",
        "search_strings",
        "search_global_names",
        "get_xrefs",
        "search_named_functions",
        "search_types",
        "get_entrypoints",
        "investigate",
    }:
        painter.drawEllipse(QtCore.QRectF(6.5, 6.5, 8.5, 8.5))
        painter.drawLine(QtCore.QPointF(14.0, 14.0), QtCore.QPointF(18.0, 18.0))
        painter.drawLine(QtCore.QPointF(9.0, 10.8), QtCore.QPointF(12.5, 10.8))
    elif kind in _ACTIVITY_RENAME_KINDS:
        _draw_pencil_glyph(painter, QtCore.QPointF(12.0, 12.0))
    elif kind == "refining":
        painter.drawArc(
            QtCore.QRectF(6.5, 6.5, 11.0, 11.0),
            25 * 16,
            275 * 16,
        )
        path = QtGui.QPainterPath()
        path.moveTo(16.5, 6.5)
        path.lineTo(17.5, 10.0)
        path.lineTo(14.0, 9.0)
        painter.drawPath(path)
    elif kind in _ACTIVITY_NOTE_TOOLS or kind == "sectioned_analysis":
        painter.drawRoundedRect(
            QtCore.QRectF(7.0, 5.5, 10.0, 13.0),
            1.2,
            1.2,
        )
        painter.drawLine(QtCore.QPointF(9.5, 9.0), QtCore.QPointF(14.5, 9.0))
        painter.drawLine(QtCore.QPointF(9.5, 12.0), QtCore.QPointF(14.5, 12.0))
        painter.drawLine(QtCore.QPointF(9.5, 15.0), QtCore.QPointF(13.0, 15.0))
    elif kind in {"success", "result", "done", "completed"}:
        painter.drawLine(QtCore.QPointF(7.0, 12.5), QtCore.QPointF(10.5, 16.0))
        painter.drawLine(QtCore.QPointF(10.5, 16.0), QtCore.QPointF(17.5, 8.5))
    elif kind in {"error", "failed"}:
        painter.drawLine(QtCore.QPointF(8.0, 8.0), QtCore.QPointF(16.0, 16.0))
        painter.drawLine(QtCore.QPointF(16.0, 8.0), QtCore.QPointF(8.0, 16.0))
    elif kind in {"warn", "warning", "skipped", "skipped_callees"}:
        painter.drawLine(QtCore.QPointF(12.0, 7.0), QtCore.QPointF(12.0, 13.0))
        painter.drawPoint(QtCore.QPointF(12.0, 16.5))
    else:
        painter.drawEllipse(QtCore.QPointF(12.0, 8.0), 0.8, 0.8)
        painter.drawLine(QtCore.QPointF(12.0, 11.0), QtCore.QPointF(12.0, 17.0))
    painter.restore()


class _ActivityIcon(QtWidgets.QWidget):
    """Theme-aware vector icon used by final-agent activity rows."""

    def __init__(self, kind: str, parent=None):
        super().__init__(parent)
        self._kind = str(kind or "info")
        self.setFixedSize(24, 24)
        self.setAttribute(Qt.WA_TransparentForMouseEvents)

    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        _paint_activity_icon(painter, self._kind)

    def set_kind(self, kind: str) -> None:
        self._kind = str(kind or "info")
        self.update()


class _ActivityActionRow(QtWidgets.QWidget):
    """One compact tool or status entry in the activity timeline."""

    def __init__(self, kind: str, label: str, detail: str = "", parent=None):
        super().__init__(parent)
        self._hovered = False
        self._kind = str(kind or "info")
        self._icon = _ActivityIcon(self._kind)

        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(2, 3, 8, 3)
        layout.setSpacing(9)
        has_detail = bool(str(detail or "").strip())
        layout.addWidget(self._icon, 0, Qt.AlignTop)

        text_layout = QtWidgets.QVBoxLayout()
        text_layout.setContentsMargins(0, 1, 0, 1)
        text_layout.setSpacing(1)
        self._label = _FallbackWrapLabel(str(label or "Activity"))
        self._label.setObjectName("activityActionLabel")
        self._label.setMinimumWidth(0)
        self._label.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self._label.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )
        self._label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        text_layout.addWidget(self._label)

        self._detail = _FallbackWrapLabel(str(detail or ""))
        self._detail.setObjectName("activityActionDetail")
        self._detail.setMinimumWidth(0)
        self._detail.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )
        self._detail.setAlignment(Qt.AlignLeft | Qt.AlignTop)
        self._detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._detail.setVisible(has_detail)
        text_layout.addWidget(self._detail)
        layout.addLayout(text_layout, 1)

        self.setMouseTracking(True)
        self.setMinimumWidth(0)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Maximum
        )
        self.restyle()

    def enterEvent(self, event) -> None:  # type: ignore[override]
        self._hovered = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        if self._hovered:
            painter = QtGui.QPainter(self)
            painter.setRenderHint(QtGui.QPainter.Antialiasing)
            color = QtGui.QColor(COLORS["accent"])
            color.setAlpha(11)
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(QtCore.QRectF(self.rect()).adjusted(0.5, 0.5, -0.5, -0.5), 5, 5)

    def restyle(self) -> None:
        self._icon.update()
        self.update()


def _constrain_layout_to_minimum(layout: QtWidgets.QLayout) -> None:
    constraint = getattr(QtWidgets.QLayout, "SetMinimumSize", None)
    if constraint is None:
        constraint = QtWidgets.QLayout.SizeConstraint.SetMinimumSize
    layout.setSizeConstraint(constraint)


class _ActivityActionList(QtWidgets.QWidget):
    """Tool rows connected by a restrained vertical timeline."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: list[_ActivityActionRow] = []
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(2)
        self._layout.setAlignment(Qt.AlignTop)
        _constrain_layout_to_minimum(self._layout)
        self.setMinimumWidth(0)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Maximum,
        )

    def add_action(self, kind: str, label: str, detail: str = "") -> None:
        row = _ActivityActionRow(kind, label, detail)
        self._rows.append(row)
        self._layout.addWidget(row)
        self.updateGeometry()
        self.update()

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        if len(self._rows) > 1:
            first = self._rows[0]
            last = self._rows[-1]
            start = first.y() + first._icon.y() + first._icon.height() / 2
            end = last.y() + last._icon.y() + last._icon.height() / 2
            painter = QtGui.QPainter(self)
            painter.setRenderHint(QtGui.QPainter.Antialiasing)
            pen = QtGui.QPen(QtGui.QColor(COLORS["border_hi"]), 1.25)
            pen.setCapStyle(Qt.RoundCap)
            painter.setPen(pen)
            painter.drawLine(QtCore.QPointF(14.0, start), QtCore.QPointF(14.0, end))

    def restyle(self) -> None:
        for row in self._rows:
            row.restyle()
        self.update()


class _AgentTurnWidget(QtWidgets.QWidget):
    """Visible agent narration followed by the tools used for that turn."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._notes: list[QtWidgets.QLabel] = []
        self._streaming_note: Optional[QtWidgets.QLabel] = None
        self._streaming_text = ""
        self._draft_markdown = None
        self._actions = _ActivityActionList()
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setContentsMargins(0, 3, 0, 5)
        self._layout.setSpacing(6)
        self._layout.setAlignment(Qt.AlignTop)
        _constrain_layout_to_minimum(self._layout)
        self._layout.addWidget(self._actions)
        self.setMinimumWidth(0)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Maximum,
        )

    def _add_note_label(self, note: str) -> QtWidgets.QLabel:
        label = _FallbackWrapLabel(note, horizontal_inset=12)
        label.setMinimumWidth(0)
        label.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._notes.append(label)
        self._layout.insertWidget(self._layout.count() - 1, label)
        self.restyle()
        return label

    def append_note(self, note: str) -> None:
        note = str(note or "")
        if self._streaming_note is not None:
            self._streaming_text = note
            self._streaming_note.setText(note)
            self._streaming_note = None
            self._layout.invalidate()
            self.updateGeometry()
            return
        self._add_note_label(note)

    def clear_notes(self) -> None:
        for label in self._notes:
            self._layout.removeWidget(label)
            label.setParent(None)
            label.deleteLater()
        self._notes.clear()
        self._streaming_note = None
        self._streaming_text = ""
        self._layout.invalidate()
        self.updateGeometry()

    def append_chunk(self, delta: str) -> None:
        delta = str(delta or "")
        if not delta:
            return
        if self._streaming_note is None:
            self._streaming_text = ""
            self._streaming_note = self._add_note_label("")
        self._streaming_text += delta
        self._streaming_note.setText(self._streaming_text)
        self._layout.invalidate()
        self.updateGeometry()

    def append_action(self, kind: str, label: str, detail: str = "") -> None:
        self._actions.add_action(kind, label, detail)
        self._layout.invalidate()
        self.updateGeometry()

    def finalize_draft(self, text: str = "") -> None:
        draft = str(text or self._streaming_text or "")
        for label in self._notes:
            self._layout.removeWidget(label)
            label.setParent(None)
            label.deleteLater()
        self._notes.clear()
        self._streaming_note = None
        self._streaming_text = draft
        if self._draft_markdown is None:
            self._draft_markdown = MarkdownContentWidget(draft)
            self._layout.insertWidget(0, self._draft_markdown)
        else:
            self._draft_markdown.set_markdown(draft)
        self._layout.invalidate()
        self.updateGeometry()

    def replace_draft(self, text: str) -> None:
        self.finalize_draft(text)

    def restyle(self) -> None:
        for label in self._notes:
            label.setStyleSheet(
                f"QLabel {{ color: {COLORS['text']}; font-family: {FONT_SANS};"
                f" font-size: 12px; background: transparent;"
                f" border-left: 2px solid {COLORS['accent']};"
                " padding: 2px 0 2px 10px; }}"
            )
        if self._draft_markdown is not None:
            self._draft_markdown.restyle()
        self._actions.restyle()


class _AnswerAuditWidget(QtWidgets.QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QtWidgets.QHBoxLayout(self)
        layout.setContentsMargins(2, 6, 8, 6)
        layout.setSpacing(9)

        self._spinner = SpinnerLabel()
        self._spinner.set_active(True)
        layout.addWidget(self._spinner, 0, Qt.AlignTop)

        self._result_icon = _ActivityIcon("done")
        self._result_icon.hide()
        layout.addWidget(self._result_icon, 0, Qt.AlignTop)

        text_layout = QtWidgets.QVBoxLayout()
        text_layout.setContentsMargins(0, 0, 0, 0)
        text_layout.setSpacing(1)
        self._title = QtWidgets.QLabel("AUDITING")
        self._detail = _FallbackWrapLabel(
            "Deciding whether semantic verification is required",
        )
        text_layout.addWidget(self._title)
        text_layout.addWidget(self._detail)
        layout.addLayout(text_layout, 1)
        self.restyle()

    def set_state(self, state: str, edit_count: int = 0) -> None:
        state = str(state or "").strip().lower()
        if state in {"start", "running"}:
            self._spinner.show()
            self._spinner.set_active(True)
            self._result_icon.hide()
            self._title.setText("AUDITING")
            self._detail.setText(
                "Verifying reconstructed behavior against the reversed evidence"
                if state == "running"
                else "Deciding whether semantic verification is required"
            )
            return

        self._spinner.set_active(False)
        self._spinner.hide()
        self._result_icon.show()
        if state == "skipped":
            self._result_icon.set_kind("done")
            self._title.setText("AUDIT NOT REQUIRED")
            self._detail.setText("The answer does not reconstruct binary behavior")
        elif state == "complete":
            self._result_icon.set_kind("done")
            self._title.setText("AUDITED")
            if edit_count:
                noun = "correction" if edit_count == 1 else "corrections"
                self._detail.setText(f"Applied {edit_count} verified {noun}")
            else:
                self._detail.setText("No source-backed errors found")
        else:
            self._result_icon.set_kind("warning")
            self._title.setText("AUDIT UNAVAILABLE")
            self._detail.setText(
                "The answer was published without semantic corrections"
            )

    def restyle(self) -> None:
        self._title.setStyleSheet(
            f"color: {COLORS['text_dim']}; font-family: {FONT_SANS};"
            " font-size: 11px; font-weight: 600; background: transparent;"
        )
        self._detail.setStyleSheet(
            f"color: {COLORS['text_mute']}; font-family: {FONT_SANS};"
            " font-size: 11px; background: transparent;"
        )
        self._result_icon.update()


class _ReversalActivityTranscript(QtWidgets.QWidget):
    """Single-widget renderer for the complete reversal activity transcript."""

    _GROUP_GAP = 4
    _ACTION_GAP = 2
    _ICON_SIZE = 24

    def __init__(self, parent=None):
        super().__init__(parent)
        self._groups: dict[str, dict] = {}
        self._order: list[str] = []
        self._layout_width = -1
        self._content_height = 0
        self._layout_refresh_pending = False
        self._hovered_action: Optional[tuple[str, int]] = None
        self.setMouseTracking(True)
        self.setMinimumWidth(0)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding,
            QtWidgets.QSizePolicy.Minimum,
        )
        self.setAccessibleName("Reversal activity")
        self._init_fonts()

    def _init_fonts(self) -> None:
        self._title_font = QtGui.QFont(FONT_SANS)
        self._title_font.setPixelSize(12)
        self._title_font.setBold(True)
        self._meta_font = QtGui.QFont(FONT_MONO)
        self._meta_font.setPixelSize(10)
        self._context_font = QtGui.QFont(FONT_SANS)
        self._context_font.setPixelSize(11)
        self._label_font = QtGui.QFont(FONT_SANS)
        self._label_font.setPixelSize(12)
        self._detail_font = QtGui.QFont(FONT_MONO)
        self._detail_font.setPixelSize(10)
        self._title_metrics = QtGui.QFontMetrics(self._title_font)
        self._meta_metrics = QtGui.QFontMetrics(self._meta_font)
        self._context_metrics = QtGui.QFontMetrics(self._context_font)
        self._label_metrics = QtGui.QFontMetrics(self._label_font)
        self._detail_metrics = QtGui.QFontMetrics(self._detail_font)

    @staticmethod
    def _text_flags():
        return (
            Qt.AlignLeft
            | Qt.AlignTop
            | Qt.TextWordWrap
        )

    def _measure_text(
        self,
        metrics: QtGui.QFontMetrics,
        text: str,
        width: int,
    ) -> int:
        if not text:
            return 0
        wrapped = _add_character_wrap_fallback(text, metrics, width)
        bounds = metrics.boundingRect(
            QtCore.QRect(0, 0, max(1, width), 100_000),
            self._text_flags(),
            wrapped,
        )
        return max(metrics.height(), bounds.height())

    def append_activities(self, activities: list[dict]) -> int:
        dirty: set[str] = set()
        added = 0
        for activity in activities:
            action = str(activity.get("action", "") or "").strip()
            label = str(activity.get("label", "") or "").strip()
            if not action or not label:
                continue

            function_ea = str(
                activity.get("function_ea", "") or ""
            ).strip()
            function_name = str(
                activity.get("function_name", "") or ""
            ).strip()
            parent_name = str(
                activity.get("parent_name", "") or ""
            ).strip()
            detail = str(activity.get("detail", "") or "").strip()
            status = str(activity.get("status", "") or "").strip()
            items = activity.get("items", [])
            if not isinstance(items, list):
                items = []

            key = function_ea or f"program:{function_name or 'updates'}"
            group = self._groups.get(key)
            if group is None:
                group = {
                    "ea": function_ea,
                    "name": function_name or function_ea or "Program updates",
                    "parent": "",
                    "status": "active",
                    "context": "",
                    "actions": [],
                    "layout": None,
                    "y": 0,
                }
                self._groups[key] = group
                self._order.append(key)

            if function_name:
                group["name"] = function_name
            if parent_name:
                group["parent"] = parent_name
            if action == "investigate":
                group["status"] = "active"
                group["context"] = detail
            else:
                detail_lines = []
                if detail:
                    detail_lines.append(detail)
                detail_lines.extend(
                    str(item).strip()
                    for item in items
                    if str(item).strip()
                )
                group["actions"].append(
                    {
                        "kind": action,
                        "label": label,
                        "detail": "\n".join(detail_lines),
                    }
                )
            if status:
                group["status"] = status
            dirty.add(key)
            added += 1

        if added:
            self._relayout(dirty)
        return added

    @staticmethod
    def _group_title(group: dict) -> str:
        prefix = {
            "done": "Investigated",
            "failed": "Could not analyse",
            "skipped": "Skipped",
        }.get(group["status"], "Investigating")
        if not group["ea"] and group["name"] == "Program updates":
            return group["name"]
        return f"{prefix} {group['name']}"

    @staticmethod
    def _group_meta(group: dict) -> str:
        parts = []
        if group["ea"]:
            parts.append(group["ea"])
        if group["parent"]:
            parts.append(f"called by {group['parent']}")
        return "  ·  ".join(parts)

    def _build_group_layout(self, group: dict, width: int) -> dict:
        text_x = 10
        text_width = max(1, width - text_x)
        cursor = 5

        title = self._group_title(group)
        title_h = self._measure_text(
            self._title_metrics,
            title,
            text_width,
        )
        title_rect = (text_x, cursor, text_width, title_h)
        cursor += title_h

        meta = self._group_meta(group)
        meta_rect = None
        if meta:
            cursor += 1
            meta_h = self._measure_text(
                self._meta_metrics,
                meta,
                text_width,
            )
            meta_rect = (text_x, cursor, text_width, meta_h)
            cursor += meta_h

        context = group["context"]
        context_rect = None
        if context:
            cursor += 1
            context_h = self._measure_text(
                self._context_metrics,
                context,
                text_width,
            )
            context_rect = (text_x, cursor, text_width, context_h)
            cursor += context_h

        header_bottom = cursor + 3
        cursor = header_bottom
        action_layouts = []
        actions = group["actions"]
        if actions:
            cursor += 6
        action_text_x = 35
        action_text_width = max(1, width - action_text_x - 8)
        for index, action in enumerate(actions):
            if index:
                cursor += self._ACTION_GAP
            row_y = cursor
            label_h = self._measure_text(
                self._label_metrics,
                action["label"],
                action_text_width,
            )
            label_rect = (
                action_text_x,
                row_y + 4,
                action_text_width,
                label_h,
            )
            detail_rect = None
            text_height = label_h
            if action["detail"]:
                detail_h = self._measure_text(
                    self._detail_metrics,
                    action["detail"],
                    action_text_width,
                )
                detail_rect = (
                    action_text_x,
                    row_y + 5 + label_h,
                    action_text_width,
                    detail_h,
                )
                text_height += 1 + detail_h
            row_h = max(self._ICON_SIZE, text_height + 2) + 6
            action_layouts.append(
                {
                    "kind": action["kind"],
                    "label": action["label"],
                    "detail": action["detail"],
                    "rect": (0, row_y, width, row_h),
                    "icon_y": row_y + 3,
                    "label_rect": label_rect,
                    "detail_rect": detail_rect,
                }
            )
            cursor += row_h

        return {
            "height": cursor + 6,
            "header_top": 3,
            "header_bottom": header_bottom,
            "title": title,
            "title_rect": title_rect,
            "meta": meta,
            "meta_rect": meta_rect,
            "context": context,
            "context_rect": context_rect,
            "actions": action_layouts,
        }

    def _relayout(self, dirty: set[str]) -> None:
        width = max(1, self.width())
        if width != self._layout_width:
            dirty = set(self._order)
            self._layout_width = width

        for key in dirty:
            group = self._groups.get(key)
            if group is not None:
                group["layout"] = self._build_group_layout(group, width)

        y = 0
        for index, key in enumerate(self._order):
            group = self._groups[key]
            group["y"] = y
            layout = group["layout"]
            if layout is None:
                layout = self._build_group_layout(group, width)
                group["layout"] = layout
            y += layout["height"]
            if index + 1 < len(self._order):
                y += self._GROUP_GAP

        self._content_height = y
        minimum_height = max(0, y)
        if self.minimumHeight() != minimum_height:
            self.setMinimumHeight(minimum_height)
        self.updateGeometry()
        self.update()

    def _schedule_full_relayout(self) -> None:
        if self._layout_refresh_pending:
            return
        self._layout_refresh_pending = True
        QtCore.QTimer.singleShot(0, self._full_relayout)

    def _full_relayout(self) -> None:
        self._layout_refresh_pending = False
        self._layout_width = -1
        self._relayout(set(self._order))

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        if event.oldSize().width() != event.size().width():
            self._schedule_full_relayout()

    def sizeHint(self) -> QtCore.QSize:  # type: ignore[override]
        return QtCore.QSize(0, self._content_height)

    def minimumSizeHint(self) -> QtCore.QSize:  # type: ignore[override]
        return QtCore.QSize(0, self._content_height)

    @staticmethod
    def _translated_rect(rect: tuple, y_offset: int) -> QtCore.QRectF:
        return QtCore.QRectF(
            rect[0],
            rect[1] + y_offset,
            rect[2],
            rect[3],
        )

    def _draw_text(
        self,
        painter: QtGui.QPainter,
        font: QtGui.QFont,
        color_key: str,
        rect: tuple,
        y_offset: int,
        text: str,
    ) -> None:
        if not text:
            return
        painter.setFont(font)
        painter.setPen(QtGui.QColor(COLORS[color_key]))
        wrapped = _add_character_wrap_fallback(
            text,
            QtGui.QFontMetrics(font),
            rect[2],
        )
        painter.drawText(
            self._translated_rect(rect, y_offset),
            self._text_flags(),
            wrapped,
        )

    def paintEvent(self, event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        clip_top = event.rect().top()
        clip_bottom = event.rect().bottom()

        for key in self._order:
            group = self._groups[key]
            layout = group["layout"]
            if layout is None:
                continue
            group_y = group["y"]
            group_bottom = group_y + layout["height"]
            if group_bottom < clip_top:
                continue
            if group_y > clip_bottom:
                break

            status_color = {
                "done": "done",
                "failed": "failed",
                "skipped": "text_mute",
            }.get(group["status"], "accent")
            header_pen = QtGui.QPen(
                QtGui.QColor(COLORS[status_color]),
                2,
            )
            painter.setPen(header_pen)
            painter.drawLine(
                QtCore.QPointF(1, group_y + layout["header_top"]),
                QtCore.QPointF(1, group_y + layout["header_bottom"]),
            )
            self._draw_text(
                painter,
                self._title_font,
                "text",
                layout["title_rect"],
                group_y,
                layout["title"],
            )
            if layout["meta_rect"] is not None:
                self._draw_text(
                    painter,
                    self._meta_font,
                    "text_mute",
                    layout["meta_rect"],
                    group_y,
                    layout["meta"],
                )
            if layout["context_rect"] is not None:
                self._draw_text(
                    painter,
                    self._context_font,
                    "text_dim",
                    layout["context_rect"],
                    group_y,
                    layout["context"],
                )

            actions = layout["actions"]
            if len(actions) > 1:
                first_center = (
                    group_y + actions[0]["icon_y"] + self._ICON_SIZE / 2
                )
                last_center = (
                    group_y + actions[-1]["icon_y"] + self._ICON_SIZE / 2
                )
                line_pen = QtGui.QPen(
                    QtGui.QColor(COLORS["border_hi"]),
                    1.25,
                )
                line_pen.setCapStyle(Qt.RoundCap)
                painter.setPen(line_pen)
                painter.drawLine(
                    QtCore.QPointF(14, first_center),
                    QtCore.QPointF(14, last_center),
                )

            for action_index, action in enumerate(actions):
                row_rect = self._translated_rect(
                    action["rect"],
                    group_y,
                )
                if row_rect.bottom() < clip_top:
                    continue
                if row_rect.top() > clip_bottom:
                    break
                if self._hovered_action == (key, action_index):
                    hover = QtGui.QColor(COLORS["accent"])
                    hover.setAlpha(11)
                    painter.setPen(Qt.NoPen)
                    painter.setBrush(hover)
                    painter.drawRoundedRect(
                        row_rect.adjusted(0.5, 0.5, -0.5, -0.5),
                        5,
                        5,
                    )
                _paint_activity_icon(
                    painter,
                    action["kind"],
                    QtCore.QPointF(2, group_y + action["icon_y"]),
                )
                self._draw_text(
                    painter,
                    self._label_font,
                    "text_dim",
                    action["label_rect"],
                    group_y,
                    action["label"],
                )
                if action["detail_rect"] is not None:
                    self._draw_text(
                        painter,
                        self._detail_font,
                        "text_mute",
                        action["detail_rect"],
                        group_y,
                        action["detail"],
                    )

    def _action_at_y(self, y: int) -> Optional[tuple[str, int]]:
        for key in self._order:
            group = self._groups[key]
            layout = group["layout"]
            if layout is None:
                continue
            group_y = group["y"]
            if y < group_y:
                return None
            if y >= group_y + layout["height"]:
                continue
            for index, action in enumerate(layout["actions"]):
                row_y = group_y + action["rect"][1]
                if row_y <= y < row_y + action["rect"][3]:
                    return key, index
            return None
        return None

    def mouseMoveEvent(self, event) -> None:  # type: ignore[override]
        position = getattr(event, "position", None)
        point = position().toPoint() if callable(position) else event.pos()
        hovered = self._action_at_y(point.y())
        if hovered != self._hovered_action:
            self._hovered_action = hovered
            self.update()
        super().mouseMoveEvent(event)

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        if self._hovered_action is not None:
            self._hovered_action = None
            self.update()
        super().leaveEvent(event)

    def restyle(self) -> None:
        self._init_fonts()
        self._full_relayout()


class WorkingWidget(QtWidgets.QWidget):
    """Fixed summary row for live and completed engine activity."""

    sig_toggle = Signal()

    def __init__(self, mode: str = "reversing", parent=None):
        super().__init__(parent)
        self._mode = mode
        self._done = False
        self._elapsed_ms = 0
        self._activity_count = 0
        self._summary_meta = ""
        self._hovered = False
        self._log_pane_ref: Optional["WorkingLogPane"] = None
        self._build_ui()

    def _build_ui(self) -> None:
        lay = QtWidgets.QHBoxLayout(self)
        lay.setContentsMargins(10, 5, 10, 5)
        lay.setSpacing(8)

        self._chevron = _ActivityChevron()
        self._chevron.hide()
        lay.addWidget(self._chevron)

        if self._mode == "preparing_answer":
            _initial_text = "Preparing answer…"
        elif self._mode == "answering":
            _initial_text = "Answering…"
        elif self._mode == "thinking":
            _initial_text = "Generating report…"
        else:
            _initial_text = "Reversing..."
        self._shimmer = ShimmerTextLabel(_initial_text)
        self._shimmer.set_active(True)
        lay.addWidget(self._shimmer)

        self._done_lbl = QtWidgets.QLabel("")
        self._done_lbl.setAttribute(Qt.WA_TransparentForMouseEvents)
        self._done_lbl.hide()
        lay.addWidget(self._done_lbl)
        lay.addStretch(1)

        self.setMinimumHeight(34)
        self.setMouseTracking(True)
        self.setCursor(Qt.ArrowCursor)
        self.restyle()

    def set_chevron(self, expanded: bool) -> None:
        self._chevron.set_expanded(expanded)
        if self._done:
            self.setToolTip("Hide activity" if expanded else "Show activity")

    def mark_done(self, elapsed_ms: int) -> None:
        self._done = True
        self._elapsed_ms = max(0, int(elapsed_ms))
        self._refresh_done_label()
        self._shimmer.set_active(False)
        self._shimmer.hide()
        self._done_lbl.show()
        self._chevron.show()
        self.setCursor(Qt.PointingHandCursor)
        self.setToolTip("Show activity")

    def set_activity_count(self, count: int) -> None:
        self._activity_count = max(0, int(count))
        if self._done:
            self._refresh_done_label()

    def set_summary_meta(self, text: str) -> None:
        self._summary_meta = str(text or "").strip()
        if self._done:
            self._refresh_done_label()

    def _refresh_done_label(self) -> None:
        secs = self._elapsed_ms // 1000
        m, s = divmod(secs, 60)
        label = f"Worked for {m}m {s:02d}s" if m else f"Worked for {s}s"
        if self._summary_meta:
            label += f"  ·  {self._summary_meta}"
        elif self._activity_count:
            noun = "action" if self._activity_count == 1 else "actions"
            label += f"  ·  {self._activity_count} {noun}"
        self._done_lbl.setText(label)

    def set_status(self, text: str) -> None:
        if self._done:
            return
        if self._mode == "reversing":
            text = "Reversing..."
        self._shimmer.set_text(text)
        self._shimmer.updateGeometry()

    def enterEvent(self, event) -> None:  # type: ignore[override]
        self._hovered = self._done
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        self._hovered = False
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        if self._done and event.button() == Qt.LeftButton:
            self.sig_toggle.emit()
            event.accept()
            return
        super().mousePressEvent(event)

    def paintEvent(self, event) -> None:  # type: ignore[override]
        super().paintEvent(event)
        if self._hovered:
            painter = QtGui.QPainter(self)
            painter.setRenderHint(QtGui.QPainter.Antialiasing)
            color = QtGui.QColor(COLORS["accent"])
            color.setAlpha(10)
            painter.setPen(Qt.NoPen)
            painter.setBrush(color)
            painter.drawRoundedRect(
                QtCore.QRectF(self.rect()).adjusted(2.5, 0.5, -2.5, -0.5), 6, 6
            )

    def restyle(self) -> None:
        self._done_lbl.setStyleSheet(
            f"color: {COLORS['text_dim']}; font-family: {FONT_SANS}; font-size: 13px;"
            " background: transparent;"
        )
        self._chevron.update()
        self._shimmer.update()
        self.update()
        if self._log_pane_ref is not None:
            self._log_pane_ref.restyle()


class _ActivityRevealViewport(QtWidgets.QWidget):
    """Clips a stable-height activity pane during reveal animations."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._child: Optional[QtWidgets.QWidget] = None
        self._content_height = 0
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Expanding
        )

    def set_child(self, child: QtWidgets.QWidget) -> None:
        self._child = child
        child.setParent(self)
        self._sync_child_geometry()
        child.show()

    def set_content_height(self, height: int) -> None:
        height = max(0, int(height))
        if height == self._content_height:
            return
        self._content_height = height
        self._sync_child_geometry()

    def _sync_child_geometry(self) -> None:
        if self._child is None:
            return
        geometry = QtCore.QRect(
            0,
            0,
            max(0, self.width()),
            self._content_height,
        )
        if self._child.geometry() != geometry:
            self._child.setGeometry(geometry)

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._sync_child_geometry()


class WorkingLogPane(QtWidgets.QWidget):
    """Borderless, collapsible transcript for engine narration and tools."""

    _MAX_LOG_H = 340
    _REVERSAL_BATCH_SIZE = 12
    _REVERSAL_BATCH_DELAY_MS = 16

    def _get_log_h(self) -> int:
        return self.maximumHeight()

    def _set_log_h(self, h: int) -> None:
        height = max(0, int(h))
        if self.minimumHeight() == height and self.maximumHeight() == height:
            return
        self.setMinimumHeight(height)
        self.setMaximumHeight(height)
        self.updateGeometry()

    log_h = Property(int, _get_log_h, _set_log_h)

    def __init__(self, header: "WorkingWidget", parent=None):
        super().__init__(parent)
        self._expanded = False
        self._header = header
        self._pending_agent_turn = 0
        self._active_agent_turn = 0
        self._final_answer_turn = 0
        self._audit_widget: Optional[_AnswerAuditWidget] = None
        self._turns: dict[int, _AgentTurnWidget] = {}
        self._reversal_transcript: Optional[
            _ReversalActivityTranscript
        ] = None
        self._reversal_function_eas: set[str] = set()
        self._reversal_change_count = 0
        self._pending_reversal_activities: deque[dict] = deque()
        self._has_reversal_activity = False
        self._action_count = 0
        self._height_update_pending = False
        self._scroll_update_pending = False
        self._follow_output = True
        self._scroll_programmatic = False
        self._height_animating = False
        self._refresh_after_animation = False
        self._content_height_saturated = False
        self._general_actions: Optional[_ActivityActionList] = None
        header._log_pane_ref = self
        self._build_ui()

    def _build_ui(self) -> None:
        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(34, 0, 8, 0)
        outer.setSpacing(0)

        self._reveal_viewport = _ActivityRevealViewport()
        outer.addWidget(self._reveal_viewport)

        self._scroll = QtWidgets.QScrollArea(self._reveal_viewport)
        self._scroll.setObjectName("workingActivityPane")
        self._scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self._scroll.setWidgetResizable(True)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._scroll.verticalScrollBar().valueChanged.connect(
            self._on_scroll_value_changed
        )

        self._content = QtWidgets.QWidget()
        self._content.setObjectName("workingActivityContent")
        self._content.setMinimumWidth(0)
        self._content.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )
        self._content_layout = QtWidgets.QVBoxLayout(self._content)
        self._content_layout.setContentsMargins(0, 0, 4, 0)
        self._content_layout.setSpacing(4)
        _constrain_layout_to_minimum(self._content_layout)
        self._content_layout.setAlignment(Qt.AlignTop)
        self._scroll.setWidget(self._content)
        self._reveal_viewport.set_child(self._scroll)
        self._reveal_viewport.set_content_height(self._MAX_LOG_H)

        self.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred
        )
        self._set_log_h(0)

        self._anim = QPropertyAnimation(self, b"log_h", self)
        self._anim.setDuration(MOTION_NORMAL_MS)
        self._anim.setEasingCurve(QEasingCurve.InOutCubic)
        self._anim.finished.connect(self._on_height_animation_finished)

        self._reversal_flush_timer = QtCore.QTimer(self)
        self._reversal_flush_timer.setSingleShot(True)
        self._reversal_flush_timer.timeout.connect(
            self.flush_pending_reversal_activities
        )

    def toggle_expand(self) -> None:
        self.set_expanded(not self._expanded)

    def set_expanded(self, expanded: bool) -> None:
        expanded = bool(expanded)
        if expanded == self._expanded:
            return
        self._expanded = expanded
        self._header.set_chevron(expanded)
        target = self._expanded_target_height() if expanded else 0
        if expanded:
            self._content_height_saturated = target >= self._MAX_LOG_H
        self._animate_height(target)

    def _animate_height(self, target: int) -> None:
        start = self.maximumHeight()
        target = max(0, int(target))
        self._anim.stop()
        if abs(start - target) <= 1:
            self._height_animating = False
            self._set_log_h(target)
            return
        self._height_animating = True
        self._set_log_h(start)
        self._anim.setStartValue(start)
        self._anim.setEndValue(target)
        self._anim.start()

    def _on_height_animation_finished(self) -> None:
        self._height_animating = False
        if self._refresh_after_animation:
            self._refresh_after_animation = False
            self._schedule_height_refresh()

    def _expanded_target_height(self) -> int:
        self._content_layout.activate()
        margins = self._content_layout.contentsMargins()
        content_width = max(
            1,
            self._scroll.viewport().width() - margins.left() - margins.right(),
        )
        content_height = margins.top() + margins.bottom()
        widget_count = 0
        for index in range(self._content_layout.count()):
            widget = self._content_layout.itemAt(index).widget()
            if widget is None:
                continue
            layout = widget.layout()
            if layout is not None:
                layout.invalidate()
                layout.activate()
            height = widget.sizeHint().height()
            if layout is not None:
                height = max(height, layout.sizeHint().height())
            if layout is not None and layout.hasHeightForWidth():
                wrapped_height = layout.heightForWidth(content_width)
                if wrapped_height > 0:
                    height = wrapped_height
            if widget_count:
                content_height += self._content_layout.spacing()
            content_height += max(0, height)
            widget_count += 1
            if content_height >= self._MAX_LOG_H:
                return self._MAX_LOG_H
        if not widget_count:
            return 0
        content_height = max(
            content_height,
            self._content_layout.minimumSize().height(),
            self._content_layout.sizeHint().height(),
        )
        return min(self._MAX_LOG_H, content_height)

    def _schedule_height_refresh(self) -> None:
        if self._height_update_pending:
            return
        self._height_update_pending = True
        QtCore.QTimer.singleShot(0, self._refresh_height)

    def _on_scroll_value_changed(self, value: int) -> None:
        if self._scroll_programmatic:
            return
        scrollbar = self._scroll.verticalScrollBar()
        self._follow_output = scrollbar.maximum() - int(value) <= 24

    def _schedule_scroll_to_end(self) -> None:
        if not self._follow_output or self._scroll_update_pending:
            return
        self._scroll_update_pending = True
        QtCore.QTimer.singleShot(0, self._scroll_to_end)

    def _refresh_height(self) -> None:
        self._height_update_pending = False
        if self._expanded:
            target = self._expanded_target_height()
            self._content_height_saturated = target >= self._MAX_LOG_H
            if self._height_animating:
                self._refresh_after_animation = True
            else:
                self._set_log_h(target)
        self._schedule_scroll_to_end()

    def _content_changed(self) -> None:
        self._content.updateGeometry()
        if (
            self._expanded
            and self._content_height_saturated
            and not self._height_animating
        ):
            self._schedule_scroll_to_end()
            return
        self._schedule_height_refresh()

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        old_width = event.oldSize().width()
        width_changed = old_width < 0 or old_width != event.size().width()
        if not self._expanded or not width_changed:
            return
        self._content_height_saturated = False
        if self._height_animating:
            self._refresh_after_animation = True
        else:
            self._schedule_height_refresh()

    @property
    def has_reversal_activity(self) -> bool:
        return self._has_reversal_activity

    @property
    def has_activity(self) -> bool:
        return bool(
            self._turns
            or self._has_reversal_activity
            or self._pending_reversal_activities
            or self._general_actions is not None
            or self._audit_widget is not None
        )

    def start_agent_turn(self, turn: int) -> None:
        self._pending_agent_turn = int(turn)
        self._active_agent_turn = int(turn)
        self.set_expanded(True)

    def end_agent_turn(self, turn: int, status: str = "") -> None:
        if str(status or "").strip().lower() in {"draft", "final"}:
            self._final_answer_turn = turn
        if self._pending_agent_turn == turn:
            self._pending_agent_turn = 0
        if self._active_agent_turn == turn:
            self._active_agent_turn = 0

    def _ensure_turn(self, turn: int = 0) -> _AgentTurnWidget:
        turn = int(turn or self._active_agent_turn or self._pending_agent_turn or 1)
        widget = self._turns.get(turn)
        if widget is None:
            widget = _AgentTurnWidget()
            self._turns[turn] = widget
            self._content_layout.addWidget(widget)
        self._active_agent_turn = turn
        return widget

    def append_agent_note(self, turn: int, note: str) -> None:
        note = str(note or "").strip()
        if not note:
            return
        self._ensure_turn(turn).append_note(note)
        self.set_expanded(True)
        self._content_changed()

    def move_agent_note_to_reversal(self, turn: int, note: str) -> None:
        note = str(note or "").strip()
        if not note:
            return
        widget = self._turns.get(int(turn))
        if widget is not None:
            widget.clear_notes()
        self.queue_reversal_activity({
            "action": "agent_reversal_note",
            "label": note,
        })
        self.set_expanded(True)
        self._content_changed()

    def append_agent_actions(self, turn: int, actions) -> None:
        if not isinstance(actions, list):
            return
        target = self._ensure_turn(turn)
        added = 0
        for action in actions:
            if not isinstance(action, dict):
                continue
            tool = str(action.get("tool", "") or "info").strip()
            label = str(action.get("label", "") or "").strip()
            detail = str(action.get("detail", "") or "").strip()
            if not label:
                continue
            target.append_action(tool, label, detail)
            added += 1
        if not added:
            return
        self._action_count += added
        self._header.set_activity_count(self._action_count)
        self.set_expanded(True)
        self._content_changed()

    def append_agent_read(self, kind: str, label: str, turn: int = 0) -> None:
        tool, action_label = {
            "function": ("get_pseudocode", "Read pseudocode"),
            "memory": ("get_memory", "Read memory"),
            "value": ("get_value_from_name", "Read symbol value"),
        }.get(kind, ("info", "Reviewed evidence"))
        self.append_agent_actions(
            turn,
            [{"tool": tool, "label": action_label, "detail": str(label or "")}],
        )

    def append_reversal_activity(self, activity: dict) -> None:
        self._append_reversal_activities([activity])

    def queue_reversal_activity(self, activity: dict) -> None:
        if not isinstance(activity, dict):
            return
        self._pending_reversal_activities.append(activity)
        if not self._reversal_flush_timer.isActive():
            self._reversal_flush_timer.start(self._REVERSAL_BATCH_DELAY_MS)

    def flush_pending_reversal_activities(self, drain: bool = False) -> None:
        self._reversal_flush_timer.stop()
        if not self._pending_reversal_activities:
            return

        count = (
            len(self._pending_reversal_activities)
            if drain
            else min(
                self._REVERSAL_BATCH_SIZE,
                len(self._pending_reversal_activities),
            )
        )
        activities = [
            self._pending_reversal_activities.popleft()
            for _ in range(count)
        ]
        self._append_reversal_activities(activities)

        if self._pending_reversal_activities:
            self._reversal_flush_timer.start(self._REVERSAL_BATCH_DELAY_MS)

    def _append_reversal_activities(self, activities: list[dict]) -> None:
        valid = []
        for activity in activities:
            action = str(activity.get("action", "") or "").strip()
            label = str(activity.get("label", "") or "").strip()
            if not action or not label:
                continue
            valid.append(activity)

            function_ea = str(
                activity.get("function_ea", "") or ""
            ).strip()
            items = activity.get("items", [])
            if not isinstance(items, list):
                items = []
            if (
                action == "investigate"
                and function_ea
                and function_ea not in self._reversal_function_eas
            ):
                self._reversal_function_eas.add(function_ea)
            if action in {
                "function_rename",
                "global_rename",
                "struct_created",
                "struct_updated",
            }:
                self._reversal_change_count += 1
            elif action in {"local_renames", "parameter_renames"}:
                self._reversal_change_count += max(1, len(items))

        if not valid:
            return
        if not self._has_reversal_activity:
            self._has_reversal_activity = True
            if self._general_actions is not None:
                self._content_layout.removeWidget(self._general_actions)
                self._general_actions.deleteLater()
                self._general_actions = None
        if self._reversal_transcript is None:
            self._reversal_transcript = _ReversalActivityTranscript()
            self._content_layout.addWidget(self._reversal_transcript)

        self._reversal_transcript.append_activities(valid)
        self._refresh_reversal_summary()
        self.set_expanded(True)
        self._content_changed()

    def append_agent_chunk(self, turn: int, delta: str) -> None:
        if not delta:
            return
        self._ensure_turn(turn).append_chunk(delta)
        self.set_expanded(True)
        self._content_changed()

    def start_answer_audit(self, answer: str) -> None:
        turn = (
            self._final_answer_turn
            or self._active_agent_turn
            or self._pending_agent_turn
        )
        if turn:
            self._final_answer_turn = turn
            self._ensure_turn(turn).finalize_draft(answer)
        if self._audit_widget is None:
            self._audit_widget = _AnswerAuditWidget()
            self._content_layout.addWidget(self._audit_widget)
        self._audit_widget.set_state("start")
        self.set_expanded(True)
        self._content_changed()

    def update_answer_audit(
        self,
        state: str,
        answer: str = "",
        edit_count: int = 0,
    ) -> None:
        if self._audit_widget is None:
            self.start_answer_audit(answer)
        elif answer and self._final_answer_turn:
            self._ensure_turn(self._final_answer_turn).replace_draft(answer)
        if self._audit_widget is not None:
            self._audit_widget.set_state(state, edit_count)
        self.set_expanded(True)
        self._content_changed()

    def _refresh_reversal_summary(self) -> None:
        summary_parts = []
        function_count = len(self._reversal_function_eas)
        if function_count:
            noun = "function" if function_count == 1 else "functions"
            summary_parts.append(f"{function_count} {noun}")
        if self._reversal_change_count:
            noun = "change" if self._reversal_change_count == 1 else "changes"
            summary_parts.append(f"{self._reversal_change_count} {noun}")
        self._header.set_summary_meta("  ·  ".join(summary_parts))

    def append_log(self, msg_type: str, text: str) -> None:
        text = str(text or "").strip()
        if not text:
            return
        if self._general_actions is None:
            self._general_actions = _ActivityActionList()
            self._content_layout.addWidget(self._general_actions)
        self._general_actions.show()
        self._general_actions.add_action(msg_type, text)
        self._content_changed()

    def _scroll_to_end(self) -> None:
        self._scroll_update_pending = False
        if not self._follow_output:
            return
        scrollbar = self._scroll.verticalScrollBar()
        self._scroll_programmatic = True
        try:
            scrollbar.setValue(scrollbar.maximum())
        finally:
            self._scroll_programmatic = False

    def restyle(self) -> None:
        for turn in self._turns.values():
            turn.restyle()
        if self._reversal_transcript is not None:
            self._reversal_transcript.restyle()
        if self._general_actions is not None:
            self._general_actions.restyle()
        if self._audit_widget is not None:
            self._audit_widget.restyle()
        self._content.update()
        self._scroll.viewport().update()


# ── Markdown table → bordered HTML (QLabel's MarkdownText mode renders GFM
#    tables without any grid lines, and we can't reach into its internal
#    QTextDocument to restyle them — so we pre-convert table blocks to raw
#    HTML <table> markup with explicit borders. CommonMark/md4c passes raw
#    HTML blocks through untouched, so the rest of the message still renders
#    as normal theme-aware markdown.) ─────────────────────────────────────────

_MD_TABLE_RE = re.compile(
    r'(?P<header>^[ \t]*\|.+\|[ \t]*\n)'
    r'(?P<sep>[ \t]*\|?[ \t]*:?-{2,}:?[ \t]*(?:\|[ \t]*:?-{2,}:?[ \t]*)*\|?[ \t]*\n)'
    r'(?P<body>(?:^[ \t]*\|.*\|[ \t]*\n?)*)',
    re.MULTILINE,
)
_INLINE_CODE   = re.compile(r'`([^`]+?)`')
_INLINE_BOLD   = re.compile(r'\*\*(.+?)\*\*|__(.+?)__')
_INLINE_ITALIC = re.compile(r'(?<!\*)\*([^*\n]+?)\*(?!\*)|(?<!_)_([^_\n]+?)_(?!_)')


def _inline_md_to_html(text: str) -> str:
    """Minimal inline-markdown → HTML for table-cell contents (bold/code/italic)."""
    text = escape(text.strip())
    text = _INLINE_CODE.sub(lambda m: f'<code>{m.group(1)}</code>', text)
    text = _INLINE_BOLD.sub(lambda m: f'<b>{m.group(1) or m.group(2)}</b>', text)
    text = _INLINE_ITALIC.sub(lambda m: f'<i>{m.group(1) or m.group(2)}</i>', text)
    return text


def _split_table_row(row: str) -> list[str]:
    row = row.strip()
    if row.startswith('|'):
        row = row[1:]
    if row.endswith('|'):
        row = row[:-1]
    cells: list[str] = []
    cur: list[str] = []
    escaped = False
    for ch in row:
        if escaped:
            cur.append(ch)
            escaped = False
        elif ch == '\\':
            escaped = True
        elif ch == '|':
            cells.append(''.join(cur))
            cur = []
        else:
            cur.append(ch)
    cells.append(''.join(cur))
    return [c.strip() for c in cells]


def _styled_markdown_tables(text: str) -> str:
    """Replace GFM-style '| a | b |' tables with bordered HTML <table> blocks
    (grid lines drawn in the current theme's border colour) while leaving the
    surrounding markdown untouched."""
    border = COLORS['border_hi']
    cell_style = f'border:1px solid {border}; padding:4px 10px; text-align:left;'

    def repl(m: 're.Match[str]') -> str:
        header_cells = _split_table_row(m.group('header'))
        body_rows = [
            _split_table_row(r) for r in m.group('body').splitlines() if r.strip('| \t')
        ]
        out = [
            f'<table style="border-collapse:collapse; border:1px solid {border}; margin:6px 0;">',
            '<tr>',
        ]
        for c in header_cells:
            out.append(f'<th style="{cell_style} font-weight:600;">{_inline_md_to_html(c)}</th>')
        out.append('</tr>')
        for row in body_rows:
            out.append('<tr>')
            for c in row:
                out.append(f'<td style="{cell_style}">{_inline_md_to_html(c)}</td>')
            out.append('</tr>')
        out.append('</table>')
        return '\n\n' + ''.join(out) + '\n\n'

    return _MD_TABLE_RE.sub(repl, text)


def _preserve_markdown_soft_breaks(text: str) -> str:
    """Make explicit AI newlines visible in QLabel's Markdown renderer.

    Markdown treats a single newline inside a paragraph as a space. Add hard
    break markers to those soft-break lines while leaving fenced code blocks
    and blank-line paragraph breaks alone.
    """
    def split_ending(line: str) -> tuple[str, str]:
        if line.endswith("\r\n"):
            return line[:-2], "\r\n"
        if line.endswith("\n") or line.endswith("\r"):
            return line[:-1], line[-1]
        return line, ""

    lines = text.splitlines(keepends=True)
    out: list[str] = []
    in_fence = False

    for i, line in enumerate(lines):
        body, ending = split_ending(line)
        stripped = body.lstrip()
        is_fence = stripped.startswith("```") or stripped.startswith("~~~")

        if in_fence:
            out.append(line)
            if is_fence:
                in_fence = False
            continue
        if is_fence:
            in_fence = True
            out.append(line)
            continue

        next_body = ""
        if i + 1 < len(lines):
            next_body, _ = split_ending(lines[i + 1])

        if (ending and body.strip() and next_body.strip()
                and not body.endswith(("  ", "\\"))):
            out.append(body.rstrip(" \t") + "  " + ending)
        else:
            out.append(line)

    return "".join(out)


def _preserve_markdown_tabs(text: str) -> str:
    """Render literal tabs in non-code Markdown text as visible indentation."""
    return text.replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;")


def _renderable_ai_markdown(text: str) -> str:
    rendered = _preserve_markdown_soft_breaks(_styled_markdown_tables(text))
    return _preserve_markdown_tabs(rendered)



_LANGUAGE_ALIASES = {
    "": "",
    "asm": "nasm",
    "assembly": "nasm",
    "bat": "batch",
    "c#": "csharp",
    "c++": "cpp",
    "cmd": "batch",
    "console": "text",
    "cs": "csharp",
    "cxx": "cpp",
    "docker": "dockerfile",
    "golang": "go",
    "h": "c",
    "hpp": "cpp",
    "ida": "c",
    "ida-pseudocode": "c",
    "js": "javascript",
    "jsonc": "json",
    "md": "markdown",
    "node": "javascript",
    "objc": "objective-c",
    "plaintext": "text",
    "powershell": "powershell",
    "ps": "powershell",
    "ps1": "powershell",
    "py": "python",
    "python3": "python",
    "shell": "bash",
    "sh": "bash",
    "text": "text",
    "ts": "typescript",
    "x64": "nasm",
    "x86": "nasm",
    "x86-64": "nasm",
    "yml": "yaml",
}


def _strip_line_ending(line: str) -> tuple[str, str]:
    if line.endswith("\r\n"):
        return line[:-2], "\r\n"
    if line.endswith("\n") or line.endswith("\r"):
        return line[:-1], line[-1]
    return line, ""


def _normalise_code_language(info: str) -> str:
    lang = (info or "").strip()
    if not lang:
        return ""
    lang = lang.split()[0].strip("{}")
    if lang.startswith("."):
        lang = lang[1:]
    return _LANGUAGE_ALIASES.get(lang.lower(), lang.lower())


def _fence_marker(line: str) -> tuple[str, int, str] | None:
    body, _ending = _strip_line_ending(line)
    stripped = body.lstrip()
    if not stripped.startswith(("```", "~~~")):
        return None
    marker = stripped[0]
    count = 0
    while count < len(stripped) and stripped[count] == marker:
        count += 1
    if count < 3:
        return None
    return marker, count, stripped[count:].strip()


def _is_closing_fence(line: str, marker: str, count: int) -> bool:
    body, _ending = _strip_line_ending(line)
    stripped = body.lstrip()
    if not stripped.startswith(marker * count):
        return False
    i = 0
    while i < len(stripped) and stripped[i] == marker:
        i += 1
    return i >= count and not stripped[i:].strip()


def _split_markdown_segments(text: str) -> list[tuple[str, str, str]]:
    """Split Markdown into ("text"|"code", content, language) segments."""
    segments: list[tuple[str, str, str]] = []
    text_lines: list[str] = []
    code_lines: list[str] = []
    in_code = False
    fence_char = ""
    fence_count = 0
    language = ""

    def flush_text() -> None:
        if text_lines:
            segments.append(("text", "".join(text_lines), ""))
            text_lines.clear()

    for line in text.splitlines(keepends=True):
        if not in_code:
            marker_info = _fence_marker(line)
            if marker_info is None:
                text_lines.append(line)
                continue
            flush_text()
            fence_char, fence_count, fence_info = marker_info
            language = _normalise_code_language(fence_info)
            code_lines = []
            in_code = True
            continue

        if _is_closing_fence(line, fence_char, fence_count):
            segments.append(("code", "".join(code_lines), language))
            code_lines = []
            language = ""
            in_code = False
        else:
            code_lines.append(line)

    if in_code:
        segments.append(("code", "".join(code_lines), language))
    else:
        flush_text()

    return segments


def _is_light_theme() -> bool:
    try:
        color = QtGui.QColor(COLORS["bg_base"])
        luminance = 0.299 * color.red() + 0.587 * color.green() + 0.114 * color.blue()
        return luminance > 150
    except Exception:
        return False


def _pygments_style_name() -> str:
    return "default" if _is_light_theme() else "monokai"


_CODE_GROUP_BY_LANGUAGE = {
    "asm": "asm",
    "bash": "shell",
    "batch": "shell",
    "c": "c",
    "cpp": "c",
    "csharp": "c",
    "css": "css",
    "dockerfile": "shell",
    "go": "go",
    "html": "markup",
    "java": "c",
    "javascript": "js",
    "json": "json",
    "kotlin": "c",
    "lua": "script",
    "markdown": "text",
    "nasm": "asm",
    "objective-c": "c",
    "perl": "script",
    "php": "php",
    "powershell": "powershell",
    "python": "python",
    "ruby": "script",
    "rust": "rust",
    "sql": "sql",
    "swift": "c",
    "tsx": "js",
    "typescript": "js",
    "xml": "markup",
    "yaml": "yaml",
}

_COMMON_KEYWORDS = {
    "and", "as", "async", "await", "break", "case", "catch", "class", "const",
    "continue", "default", "defer", "del", "do", "else", "enum", "except",
    "export", "extends", "false", "finally", "for", "from", "func", "function",
    "if", "import", "in", "interface", "is", "lambda", "let", "match", "module",
    "namespace", "new", "nil", "none", "not", "null", "or", "package", "pass",
    "private", "protected", "public", "return", "self", "static", "struct",
    "super", "switch", "this", "throw", "throws", "trait", "true", "try",
    "type", "using", "var", "while", "with", "yield",
}

_KEYWORDS_BY_GROUP = {
    "asm": {
        "add", "and", "call", "cmp", "dec", "div", "imul", "inc", "int", "ja",
        "jae", "jb", "jbe", "je", "jg", "jge", "jl", "jle", "jmp", "jne",
        "lea", "mov", "movsx", "movzx", "mul", "neg", "nop", "not", "or",
        "pop", "push", "ret", "rol", "ror", "sar", "sbb", "shl", "shr",
        "sub", "test", "xor",
    },
    "c": {
        "auto", "bool", "char", "class", "const", "constexpr", "delete",
        "double", "enum", "extern", "float", "int", "long", "new", "nullptr",
        "operator", "override", "private", "protected", "public", "short",
        "signed", "sizeof", "static", "struct", "template", "typedef", "union",
        "unsigned", "virtual", "void", "volatile",
    },
    "css": {
        "align-items", "animation", "background", "border", "color", "display",
        "flex", "font", "grid", "height", "margin", "padding", "position",
        "transform", "transition", "width",
    },
    "go": {"chan", "defer", "fallthrough", "func", "go", "map", "range", "select"},
    "json": {"false", "null", "true"},
    "php": {"echo", "function", "namespace", "require", "require_once", "use"},
    "powershell": {
        "begin", "catch", "end", "foreach", "function", "param", "process",
        "switch", "trap", "where",
    },
    "python": {
        "def", "elif", "global", "nonlocal", "raise", "with", "yield",
    },
    "rust": {
        "crate", "dyn", "impl", "let", "macro", "mod", "move", "mut", "pub",
        "ref", "where",
    },
    "shell": {
        "case", "done", "elif", "esac", "fi", "for", "function", "if", "in",
        "then", "until",
    },
    "sql": {
        "alter", "and", "as", "between", "by", "create", "delete", "desc",
        "distinct", "drop", "from", "group", "having", "insert", "join", "like",
        "limit", "not", "null", "on", "or", "order", "select", "set", "table",
        "update", "values", "where",
    },
    "yaml": {"false", "no", "null", "off", "on", "true", "yes"},
}

_BUILTINS_BY_GROUP = {
    "asm": {
        "ah", "al", "ax", "bh", "bl", "bp", "bpl", "bx", "ch", "cl", "cs",
        "cx", "dh", "di", "dil", "dl", "ds", "dx", "eax", "ebp", "ebx",
        "ecx", "edi", "edx", "eip", "esi", "esp", "ip", "r10", "r10d",
        "r10w", "r11", "r11d", "r11w", "r12", "r12d", "r12w", "r13", "r13d",
        "r13w", "r14", "r14d", "r14w", "r15", "r15d", "r15w", "r8", "r8d",
        "r8w", "r9", "r9d", "r9w", "rax", "rbp", "rbx", "rcx", "rdi",
        "rdx", "rip", "rsi", "rsp", "si", "sil", "sp", "spl", "ss",
    },
    "python": {
        "dict", "enumerate", "int", "len", "list", "open", "print", "range",
        "set", "str", "sum", "tuple",
    },
    "js": {
        "array", "console", "document", "map", "math", "promise", "settimeout",
        "string", "window",
    },
}


def _code_palette() -> dict[str, str]:
    if _is_light_theme():
        return {
            "keyword": "#005cc5",
            "builtin": "#6f42c1",
            "string": "#032f62",
            "comment": "#6a737d",
            "number": "#005cc5",
            "operator": "#d73a49",
            "tag": "#22863a",
            "attr": "#6f42c1",
        }
    return {
        "keyword": "#ff7b72",
        "builtin": "#d2a8ff",
        "string": "#a5d6ff",
        "comment": "#8b949e",
        "number": "#79c0ff",
        "operator": "#ff7b72",
        "tag": "#7ee787",
        "attr": "#d2a8ff",
    }


def _span(kind: str, text: str) -> str:
    return f'<span style="color:{_code_palette()[kind]};">{escape(text)}</span>'


def _code_group(language: str) -> str:
    normalised = _normalise_code_language(language)
    return _CODE_GROUP_BY_LANGUAGE.get(normalised, normalised or "text")


def _line_comment_markers(group: str) -> tuple[str, ...]:
    if group in {"python", "shell", "powershell", "script", "yaml"}:
        return ("#",)
    if group == "sql":
        return ("--",)
    if group == "asm":
        return (";", "#")
    if group in {"c", "go", "js", "php", "rust", "css"}:
        return ("//",)
    return ()


def _has_block_comments(group: str) -> bool:
    return group in {"c", "go", "js", "php", "rust", "css"}


def _fallback_markup_highlight(code: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(code):
        if code.startswith("<!--", i):
            end = code.find("-->", i + 4)
            j = len(code) if end < 0 else end + 3
            out.append(_span("comment", code[i:j]))
            i = j
            continue
        if code[i] == "<":
            end = code.find(">", i + 1)
            j = len(code) if end < 0 else end + 1
            out.append(_span("tag", code[i:j]))
            i = j
            continue
        out.append(escape(code[i]))
        i += 1
    return "".join(out)


def _fallback_highlight_code_html(code: str, language: str) -> str:
    group = _code_group(language)
    if group == "text":
        return escape(code)
    if group == "markup":
        return _fallback_markup_highlight(code)

    keywords = _COMMON_KEYWORDS | _KEYWORDS_BY_GROUP.get(group, set())
    builtins = _BUILTINS_BY_GROUP.get(group, set())
    line_comments = _line_comment_markers(group)
    out: list[str] = []
    i = 0

    while i < len(code):
        ch = code[i]

        if _has_block_comments(group) and code.startswith("/*", i):
            end = code.find("*/", i + 2)
            j = len(code) if end < 0 else end + 2
            out.append(_span("comment", code[i:j]))
            i = j
            continue

        matched_comment = ""
        for marker in line_comments:
            if code.startswith(marker, i):
                matched_comment = marker
                break
        if matched_comment:
            j = code.find("\n", i)
            if j < 0:
                j = len(code)
            out.append(_span("comment", code[i:j]))
            i = j
            continue

        if ch in ("'", '"', "`"):
            if group == "python" and code.startswith(ch * 3, i):
                end = code.find(ch * 3, i + 3)
                j = len(code) if end < 0 else end + 3
            else:
                j = i + 1
                escaped = False
                while j < len(code):
                    c = code[j]
                    if escaped:
                        escaped = False
                    elif c == "\\":
                        escaped = True
                    elif c == ch:
                        j += 1
                        break
                    elif c == "\n" and group not in {"js", "go", "shell"}:
                        break
                    j += 1
            out.append(_span("string", code[i:j]))
            i = j
            continue

        if ch == "$" and group in {"powershell", "php", "shell"}:
            m = re.match(r"\$[A-Za-z_][A-Za-z0-9_]*", code[i:])
            if m:
                out.append(_span("builtin", m.group(0)))
                i += len(m.group(0))
                continue

        if ch.isdigit():
            m = re.match(r"0x[0-9A-Fa-f]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?", code[i:])
            if m:
                out.append(_span("number", m.group(0)))
                i += len(m.group(0))
                continue

        if ch.isalpha() or ch == "_":
            m = re.match(r"[A-Za-z_][A-Za-z0-9_]*", code[i:])
            if m:
                word = m.group(0)
                lower = word.lower()
                if lower in keywords:
                    out.append(_span("keyword", word))
                elif lower in builtins:
                    out.append(_span("builtin", word))
                else:
                    out.append(escape(word))
                i += len(word)
                continue

        if ch in "+-*/%=!<>|&^~:.":
            out.append(_span("operator", ch))
        else:
            out.append(escape(ch))
        i += 1

    return "".join(out)


def _highlight_code_html(code: str, language: str) -> str:
    if _pygments_highlight is None or _PygmentsHtmlFormatter is None:
        return _fallback_highlight_code_html(code, language)

    lexer = None
    normalised = _normalise_code_language(language)
    if normalised and normalised != "text" and _pygments_lexer_by_name is not None:
        try:
            lexer = _pygments_lexer_by_name(normalised)
        except _PygmentsClassNotFound:
            lexer = None
    if lexer is None:
        lexer = _PygmentsTextLexer() if _PygmentsTextLexer is not None else None
    if lexer is None:
        return _fallback_highlight_code_html(code, language)

    formatter = _PygmentsHtmlFormatter(
        nowrap=True,
        noclasses=True,
        style=_pygments_style_name(),
    )
    return _pygments_highlight(code, lexer, formatter).rstrip("\n")


def _code_html_document(code: str, language: str) -> str:
    highlighted = _highlight_code_html(code, language)
    return (
        f'<html><body style="margin:0; background:{COLORS["bg_input"]};">'
        f'<pre style="margin:0; padding:0; white-space:pre;'
        f' color:{COLORS["text"]}; font-family:{FONT_MONO}; font-size:12px;'
        f' line-height:1.35;">{highlighted}</pre></body></html>'
    )


class _RoundedCodeSurface(QtWidgets.QFrame):
    """Clips code-block header and body beneath the foreground outline."""

    _RADIUS = 7

    def _apply_content_clip(self) -> None:
        self.setMask(
            _inset_rounded_region(
                self.width(),
                self.height(),
                self._RADIUS,
                1,
            )
        )

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._apply_content_clip()

    def showEvent(self, event) -> None:  # type: ignore[override]
        super().showEvent(event)
        self._apply_content_clip()


class CodeBlockWidget(QtWidgets.QFrame):
    """Syntax-highlighted fenced code block with a hover copy button."""

    _MAX_CODE_H = 420
    _CONTENT_PADDING = 9

    def __init__(self, code: str, language: str, parent=None):
        super().__init__(parent)
        self._code = code
        self._language = _normalise_code_language(language)
        self.setObjectName("markdownCodeBlock")
        self.setMouseTracking(True)
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                           QtWidgets.QSizePolicy.Preferred)

        outer = QtWidgets.QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._surface = _RoundedCodeSurface()
        self._surface.setObjectName("markdownCodeSurface")
        surface_layout = QtWidgets.QVBoxLayout(self._surface)
        surface_layout.setContentsMargins(0, 0, 0, 0)
        surface_layout.setSpacing(0)

        header = QtWidgets.QFrame()
        header.setObjectName("markdownCodeHeader")
        header.setMouseTracking(True)
        header_lay = QtWidgets.QHBoxLayout(header)
        header_lay.setContentsMargins(10, 5, 6, 5)
        header_lay.setSpacing(8)

        self._lang_lbl = QtWidgets.QLabel((self._language or "text").upper())
        header_lay.addWidget(self._lang_lbl)
        header_lay.addStretch(1)

        self._copy_btn = QtWidgets.QPushButton("Copy")
        self._copy_btn.setFixedHeight(22)
        self._copy_btn.setCursor(Qt.PointingHandCursor)
        self._copy_btn.setToolTip("Copy code")
        self._copy_btn.clicked.connect(self._copy_code)
        header_lay.addWidget(self._copy_btn)

        self._code_view = QtWidgets.QTextEdit()
        self._code_view.setReadOnly(True)
        self._code_view.setFrameShape(QtWidgets.QFrame.NoFrame)
        self._code_view.setLineWrapMode(QtWidgets.QTextEdit.LineWrapMode.NoWrap)
        self._code_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._code_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._code_view.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._code_view.document().setDocumentMargin(self._CONTENT_PADDING)

        surface_layout.addWidget(header)
        surface_layout.addWidget(self._code_view)
        outer.addWidget(self._surface)

        self._border_overlay = _RoundedBorderOverlay(
            self._surface,
            self,
            radius=self._surface._RADIUS,
        )

        self.restyle()
        QtCore.QTimer.singleShot(0, self._adjust_code_height)

    def restyle(self) -> None:
        self.setStyleSheet(
            "QFrame#markdownCodeBlock { background: transparent; border: none; }"
            f"QFrame#markdownCodeSurface {{ background: {COLORS['bg_input']};"
            " border: none; }}"
            f"QFrame#markdownCodeHeader {{ background: {COLORS['bg_card']};"
            " border: none; }}"
        )
        self._lang_lbl.setStyleSheet(
            f"color: {COLORS['text_mute']}; font-family: {FONT_MONO};"
            f" font-size: 10px; font-weight: 600; background: transparent;"
        )
        self._copy_btn.setStyleSheet(
            f"QPushButton {{ background: {COLORS['bg_card_hi']}; color: {COLORS['text_dim']};"
            f" font-family: {FONT_SANS}; font-size: 11px; border: 1px solid {COLORS['border_hi']};"
            f" border-radius: 5px; padding: 1px 8px; }}"
            f"QPushButton:hover {{ color: {COLORS['accent']}; border-color: {COLORS['accent']}; }}"
        )
        self._code_view.setStyleSheet(
            f"QTextEdit {{ background: {COLORS['bg_input']}; color: {COLORS['text']};"
            f" border: none; selection-background-color: {COLORS['accent']};"
            f" font-family: {FONT_MONO}; font-size: 12px; }}"
        )
        self._code_view.setHtml(_code_html_document(self._code, self._language))
        self._surface.update()
        self._border_overlay.update()
        self._adjust_code_height()

    def set_code(self, code: str) -> None:
        if code == self._code:
            return
        self._code = code
        self._code_view.setHtml(_code_html_document(self._code, self._language))
        QtCore.QTimer.singleShot(0, self._adjust_code_height)

    def _adjust_code_height(self) -> None:
        doc_h = math.ceil(self._code_view.document().size().height())
        target = max(1, min(self._MAX_CODE_H, doc_h))
        if self._code_view.height() != target:
            self._code_view.setFixedHeight(target)

    def _copy_code(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self._code)


class MarkdownContentWidget(QtWidgets.QWidget):
    """Markdown renderer that gives fenced code blocks their own widgets."""

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._text = ""
        self._segments: list[list] = []
        self.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                           QtWidgets.QSizePolicy.Preferred)
        self._layout = QtWidgets.QVBoxLayout(self)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(7)
        self.setStyleSheet("background: transparent;")
        self._layout.addStretch(0)
        self.set_markdown(text)

    def set_markdown(self, text: str, force: bool = False) -> None:
        if not force and text == self._text:
            return
        self._text = text
        incoming = [
            segment for segment in _split_markdown_segments(text)
            if segment[1]
        ]

        shared = 0
        limit = min(len(self._segments), len(incoming))
        while shared < limit:
            old_kind, old_content, old_language, widget = self._segments[shared]
            kind, content, language = incoming[shared]
            if old_kind != kind or old_language != language:
                break
            if force or old_content != content:
                self._update_segment_widget(widget, kind, content)
            self._segments[shared][1] = content
            shared += 1

        self._remove_segments_from(shared)
        for kind, content, language in incoming[shared:]:
            widget = self._make_segment_widget(kind, content, language)
            self._layout.insertWidget(self._layout.count() - 1, widget)
            self._segments.append([kind, content, language, widget])

    def restyle(self) -> None:
        for kind, content, _language, widget in self._segments:
            if kind == "code" and isinstance(widget, CodeBlockWidget):
                widget.restyle()
            elif kind == "code" and isinstance(widget, QtWidgets.QLabel):
                self._update_code_fallback_label(widget, content)
            else:
                self._update_text_label(widget, content)

    def _clear(self) -> None:
        while self._layout.count():
            item = self._layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        if hasattr(self, "_segments"):
            self._segments.clear()

    def _remove_segments_from(self, index: int) -> None:
        while len(self._segments) > index:
            self._segments.pop()
            item = self._layout.takeAt(index)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()

    def _make_segment_widget(
        self, kind: str, content: str, language: str
    ) -> QtWidgets.QWidget:
        if kind == "code":
            try:
                return CodeBlockWidget(content, language, self)
            except Exception:
                return self._make_code_fallback_label(content)
        return self._make_text_label(content)

    def _update_segment_widget(
        self, widget: QtWidgets.QWidget, kind: str, content: str
    ) -> None:
        if kind == "code" and isinstance(widget, CodeBlockWidget):
            widget.set_code(content)
        elif kind == "code" and isinstance(widget, QtWidgets.QLabel):
            self._update_code_fallback_label(widget, content)
        elif isinstance(widget, QtWidgets.QLabel):
            self._update_text_label(widget, content)

    def _make_text_label(self, text: str) -> QtWidgets.QLabel:
        label = QtWidgets.QLabel()
        label.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                            QtWidgets.QSizePolicy.Preferred)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        label.setCursor(Qt.IBeamCursor)
        label.setOpenExternalLinks(True)
        label.setTextFormat(Qt.TextFormat.MarkdownText)
        self._update_text_label(label, text)
        return label

    @staticmethod
    def _update_text_label(label: QtWidgets.QLabel, text: str) -> None:
        label.setText(_renderable_ai_markdown(text))
        label.setStyleSheet(
            f"color: {COLORS['text']}; font-family: {FONT_SANS}; font-size: 13px;"
            f" background: transparent; line-height: 1.6;"
        )

    def _make_code_fallback_label(self, code: str) -> QtWidgets.QLabel:
        label = QtWidgets.QLabel()
        label.setObjectName("markdownCodeFallback")
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        label.setCursor(Qt.IBeamCursor)
        label.setTextFormat(Qt.TextFormat.RichText)
        self._update_code_fallback_label(label, code)
        return label

    @staticmethod
    def _update_code_fallback_label(
        label: QtWidgets.QLabel, code: str
    ) -> None:
        label.setText(
            f'<pre style="white-space:pre; color:{COLORS["text"]};'
            f' font-family:{FONT_MONO}; font-size:12px;">{escape(code)}</pre>'
        )
        label.setStyleSheet(
            f"background: {COLORS['bg_input']}; border: 1px solid {COLORS['border_hi']};"
            f" border-radius: 7px; padding: 9px;"
        )


class ChatMessageWidget(QtWidgets.QWidget):
    """Chat message widget.

    'You' messages: right-aligned pill bubble (very dark accent bg, accent text).
    'AI' messages: raw left-aligned text — no bubble, no border, slightly larger font.
    AI messages fill the available conversation width.
    """

    def __init__(self, role: str, text: str, parent=None):
        super().__init__(parent)
        self._is_you   = (role == "You")
        self._copy_btn = None
        self._text     = text
        self._last_bubble_width = -1

        outer = QtWidgets.QHBoxLayout(self)
        outer.setContentsMargins(10, 4, 10, 4)
        outer.setSpacing(0)

        if self._is_you:
            body = QtWidgets.QLabel(text)
            body.setWordWrap(True)
            body.setTextInteractionFlags(Qt.TextSelectableByMouse)
            body.setCursor(Qt.IBeamCursor)
            body.setOpenExternalLinks(True)
        else:
            body = MarkdownContentWidget(text)
        self._body = body

        if self._is_you:
            # Pill bubble — dark accent bg, accent text, right-aligned
            self._bubble = QtWidgets.QFrame()
            blay = QtWidgets.QVBoxLayout(self._bubble)
            blay.setContentsMargins(13, 9, 13, 9)
            blay.setSpacing(0)
            blay.addWidget(body)
            self._bubble.setStyleSheet(
                f"QFrame {{ background: {COLORS['bubble']}; border-radius: 14px; }}"
            )
            body.setStyleSheet(
                f"color: {COLORS['accent']}; font-family: {FONT_SANS}; font-size: 13px;"
                f" background: transparent; line-height: 1.5;"
            )
            outer.addStretch(1)
            outer.addWidget(self._bubble)
        else:
            # Raw text — no bubble, left-aligned; with a fading copy button below
            self._bubble = None
            # Inner vertical layout: text row + copy button row
            v_wrap = QtWidgets.QWidget()
            v_wrap.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                                 QtWidgets.QSizePolicy.Preferred)
            v_wrap.setStyleSheet("background: transparent;")
            v_lay = QtWidgets.QVBoxLayout(v_wrap)
            v_lay.setContentsMargins(0, 0, 0, 0)
            v_lay.setSpacing(2)
            v_lay.addWidget(body)

            # Copy button stays visible at the bottom of the AI message.
            self._copy_btn = QtWidgets.QPushButton("⎘  Copy")
            self._copy_btn.setFixedHeight(20)
            self._copy_btn.setCursor(Qt.PointingHandCursor)
            self._copy_btn.setStyleSheet(
                f"QPushButton {{ background: transparent; color: {COLORS['text_mute']};"
                f" font-family: {FONT_SANS}; font-size: 11px; border: none;"
                f" padding: 0px 0px; text-align: left; }}"
                f"QPushButton:hover {{ color: {COLORS['text_dim']}; }}"
            )
            self._copy_btn.clicked.connect(self._copy_text)

            copy_row = QtWidgets.QHBoxLayout()
            copy_row.setContentsMargins(0, 0, 0, 0)
            copy_row.addWidget(self._copy_btn)
            copy_row.addStretch(1)
            v_lay.addLayout(copy_row)

            outer.addWidget(v_wrap, 1)

    def restyle(self) -> None:
        """Re-apply inline styles from the current theme (live theme switch)."""
        if self._is_you:
            self._bubble.setStyleSheet(
                f"QFrame {{ background: {COLORS['bubble']}; border-radius: 14px; }}"
            )
            self._body.setStyleSheet(
                f"color: {COLORS['accent']}; font-family: {FONT_SANS}; font-size: 13px;"
                f" background: transparent; line-height: 1.5;"
            )
        else:
            if isinstance(self._body, MarkdownContentWidget):
                self._body.restyle()
            if self._copy_btn is not None:
                self._copy_btn.setStyleSheet(
                    f"QPushButton {{ background: transparent; color: {COLORS['text_mute']};"
                    f" font-family: {FONT_SANS}; font-size: 11px; border: none;"
                    f" padding: 0px 0px; text-align: left; }}"
                    f"QPushButton:hover {{ color: {COLORS['text_dim']}; }}"
                )

    # ── Copy button ───────────────────────────────────────────────────────────

    def _animate_copy(self, show: bool) -> None:
        del show

    def enterEvent(self, e):  # type: ignore[override]
        super().enterEvent(e)
        self._animate_copy(True)

    def leaveEvent(self, e):  # type: ignore[override]
        super().leaveEvent(e)
        self._animate_copy(False)

    def _copy_text(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self._text)

    # ── Layout constraint via resizeEvent ─────────────────────────────────────

    def resizeEvent(self, e):  # type: ignore[override]
        super().resizeEvent(e)
        if self._bubble is not None:
            # Maximum bubble width = 80 % of available content area.
            content_w = self.width() - 20          # subtract 10px margins each side
            max_w = max(80, int(content_w * 0.80))

            # Natural (single-line) width of the text so short messages stay compact
            fm    = self._body.fontMetrics()
            lines = self._body.text().split('\n') or ['']
            natural_label_w  = max((fm.horizontalAdvance(ln) for ln in lines), default=0)
            natural_bubble_w = natural_label_w + 28   # 13+13 padding + 2 safety

            # Hug the text: natural width when it fits, capped at max_w when it
            # needs to wrap. No minimum floor — a short message stays tight.
            target_w = min(natural_bubble_w, max_w)
            if target_w != self._last_bubble_width:
                self._last_bubble_width = target_w
                self._bubble.setFixedWidth(target_w)
                self._body.setMaximumWidth(max(1, target_w - 26))


class UsageLimitWidget(QtWidgets.QFrame):
    """Quiet, always-visible monthly usage percentage."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self.setAutoFillBackground(False)
        self.setStyleSheet("background: transparent; border: none;")
        self.setFixedSize(32, 32)
        self.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)

        self._month_pct = 0.0
        self._month_value = "0%"
        self._update_tooltip()

    def set_usage(self, month_pct: float, month_value: str = "") -> None:
        self._month_pct = max(0.0, min(1.0, month_pct))
        self._month_value = month_value or f"{int(self._month_pct * 100)}%"
        self._update_tooltip()
        self.update()

    def _update_tooltip(self) -> None:
        self.setToolTip(f"Monthly usage: {self._month_value}")

    def paintEvent(self, e):  # type: ignore[override]
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)

        c = COLORS
        rect = QtCore.QRectF(0.5, 0.5, self.width() - 1, self.height() - 1)
        p.setBrush(QtGui.QColor(c["bg_input"]))
        p.setPen(QtGui.QPen(QtGui.QColor(c["border_hi"]), 1))
        p.drawRoundedRect(rect, 8, 8)

        self._draw_arc(p, QtCore.QPointF(16, 16), 10, self._month_pct, c["accent"], 3)
        font = QtGui.QFont(FONT_SANS)
        font.setPixelSize(7 if len(self._month_value) >= 4 else 8)
        font.setBold(True)
        p.setFont(font)
        p.setPen(QtGui.QColor(c["text"]))
        p.drawText(QtCore.QRectF(4, 11, 24, 10), Qt.AlignCenter, self._month_value)
        p.end()

    def _draw_arc(self, p, center, radius: int, pct: float, color: str, width: int) -> None:
        base_pen = QtGui.QPen(QtGui.QColor(COLORS["border"]), width)
        base_pen.setCapStyle(Qt.RoundCap)
        p.setPen(base_pen)
        box = QtCore.QRectF(center.x() - radius, center.y() - radius, radius * 2, radius * 2)
        p.drawArc(box, 90 * 16, -360 * 16)

        arc_pen = QtGui.QPen(QtGui.QColor(color), width)
        arc_pen.setCapStyle(Qt.RoundCap)
        p.setPen(arc_pen)
        p.drawArc(box, 90 * 16, int(-360 * pct * 16))


class StreamingChatMessageWidget(QtWidgets.QWidget):
    """An AI message bubble that accepts incremental text via append_text().

    Incoming deltas are coalesced to the display refresh rate so network bursts
    produce stable layout updates without adding artificial typing latency.
    """

    _TICK_MS = 33
    _MARKDOWN_RENDER_MS = 66

    def __init__(self, parent=None):
        super().__init__(parent)
        self._received  = ""   # full text received from server so far
        self._displayed = ""   # text currently shown in label
        self._last_rendered = ""
        self._render_clock = QtCore.QElapsedTimer()
        self._render_clock.start()
        self._last_render_ms = -self._MARKDOWN_RENDER_MS

        outer = QtWidgets.QHBoxLayout(self)
        outer.setContentsMargins(10, 4, 10, 4)
        outer.setSpacing(0)

        self._markdown = MarkdownContentWidget("")

        # Inner vertical layout: label + copy button
        v_wrap = QtWidgets.QWidget()
        v_wrap.setSizePolicy(QtWidgets.QSizePolicy.Expanding,
                             QtWidgets.QSizePolicy.Preferred)
        v_wrap.setStyleSheet("background: transparent;")
        v_lay = QtWidgets.QVBoxLayout(v_wrap)
        v_lay.setContentsMargins(0, 0, 0, 0)
        v_lay.setSpacing(2)
        v_lay.addWidget(self._markdown)

        self._copy_btn = QtWidgets.QPushButton("⎘  Copy")
        self._copy_btn.setFixedHeight(20)
        self._copy_btn.setCursor(Qt.PointingHandCursor)
        self._copy_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {COLORS['text_mute']};"
            f" font-family: {FONT_SANS}; font-size: 11px; border: none;"
            f" padding: 0px 0px; text-align: left; }}"
            f"QPushButton:hover {{ color: {COLORS['text_dim']}; }}"
        )
        self._copy_btn.clicked.connect(self._copy_text)

        copy_row = QtWidgets.QHBoxLayout()
        copy_row.setContentsMargins(0, 0, 0, 0)
        copy_row.addWidget(self._copy_btn)
        copy_row.addStretch(1)
        v_lay.addLayout(copy_row)

        outer.addWidget(v_wrap, 1)

        # Coalesce network chunks before updating the rich-text layout.
        self._lerp_timer = QtCore.QTimer(self)
        self._lerp_timer.setInterval(self._TICK_MS)
        self._lerp_timer.timeout.connect(self._lerp_tick)

    def restyle(self) -> None:
        """Re-apply inline styles from the current theme (live theme switch)."""
        self._markdown.restyle()
        self._copy_btn.setStyleSheet(
            f"QPushButton {{ background: transparent; color: {COLORS['text_mute']};"
            f" font-family: {FONT_SANS}; font-size: 11px; border: none;"
            f" padding: 0px 0px; text-align: left; }}"
            f"QPushButton:hover {{ color: {COLORS['text_dim']}; }}"
        )

    # ── Incoming text ─────────────────────────────────────────────────────────

    def append_text(self, delta: str) -> None:
        self._received += delta
        if not self._lerp_timer.isActive():
            self._lerp_timer.start()

    def replace_text(self, text: str) -> None:
        """Replace the full message body for mutable candidate-answer updates."""
        self._lerp_timer.stop()
        self._received = text
        self._displayed = text
        self._render_markdown(force=True)

    def get_text(self) -> str:
        """Return full received text (used by copy / chat send)."""
        return self._received

    def _streaming_markdown(self, text: str) -> str:
        return text

    def _render_markdown(self, force: bool = False) -> None:
        now = self._render_clock.elapsed()
        if not force and now - self._last_render_ms < self._MARKDOWN_RENDER_MS:
            return
        if not force and self._displayed == self._last_rendered:
            return

        self._markdown.set_markdown(self._streaming_markdown(self._displayed))
        self._last_rendered = self._displayed
        self._last_render_ms = now

    # ── Display tick ──────────────────────────────────────────────────────────

    def _lerp_tick(self) -> None:
        if self._displayed != self._received:
            self._displayed = self._received
        self._render_markdown()
        if self._last_rendered == self._displayed:
            self._lerp_timer.stop()

    def finalize(self) -> None:
        """Flush any pending text and force one complete rich-markdown render."""
        self._lerp_timer.stop()
        self._displayed = self._received
        self._render_markdown(force=True)

    # ── Copy button ───────────────────────────────────────────────────────────

    def _animate_copy(self, show: bool) -> None:
        del show

    def enterEvent(self, e):  # type: ignore[override]
        super().enterEvent(e)
        self._animate_copy(True)

    def leaveEvent(self, e):  # type: ignore[override]
        super().leaveEvent(e)
        self._animate_copy(False)

    def _copy_text(self) -> None:
        QtWidgets.QApplication.clipboard().setText(self._received)


# ???????????????????????????????????????????????????????????????????????????
#  ConversationDrawer — slide-in chat history overlay on the graph view
# ???????????????????????????????????????????????????????????????????????????

class _VerticalTabWidget(QtWidgets.QFrame):
    """Custom-painted tab strip: list icon + rotated 'HISTORY' + expand chevron.

    ``clicked``      — emitted on any left-click (opens the drawer stickily).
    ``icon_hovered`` — True/False when the mouse enters/leaves the 3-bar icon
                       zone at the top; used for temporary hover-open.
    """
    clicked      = Signal()
    icon_hovered = Signal(bool)

    _LABEL       = "HISTORY"
    _ICON_ZONE_H = 28   # top N pixels constitute the 3-bar icon zone

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("drawerTab")
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedWidth(28)
        self.setMouseTracking(True)
        self._in_icon = False

    def mousePressEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e):
        super().mouseMoveEvent(e)
        now = e.y() < self._ICON_ZONE_H
        if now != self._in_icon:
            self._in_icon = now
            self.icon_hovered.emit(now)

    def enterEvent(self, e):
        super().enterEvent(e)
        lp = self.mapFromGlobal(QtGui.QCursor.pos())
        now = lp.y() < self._ICON_ZONE_H
        self._in_icon = now
        if now:
            self.icon_hovered.emit(True)

    def leaveEvent(self, e):
        super().leaveEvent(e)
        if self._in_icon:
            self._in_icon = False
            self.icon_hovered.emit(False)

    def paintEvent(self, _e):
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        w, h = self.width(), self.height()

        # Background
        p.fillRect(self.rect(), QtGui.QColor(COLORS["bg_card_hi"]))

        # 1 px light-grey border on the right edge
        p.fillRect(w - 1, 0, 1, h, QtGui.QColor(COLORS["border_hi"]))

        # List icon: 3 short horizontal bars (light grey), top area
        bar_col = QtGui.QColor(COLORS["border_hi"])
        bar_w   = w - 10
        for by in [9, 14, 19]:
            p.fillRect(5, by, bar_w, 2, bar_col)

        # Rotated "HISTORY" label — reads bottom-to-top, vertically centred
        p.save()
        p.translate((w - 1) / 2, h / 2 + 12)
        p.rotate(-90)
        lf = QtGui.QFont()
        lf.setPixelSize(9)
        lf.setLetterSpacing(QtGui.QFont.SpacingType.AbsoluteSpacing, 2.0)
        lf.setWeight(QtGui.QFont.Weight.Medium)
        p.setFont(lf)
        p.setPen(QtGui.QColor(COLORS["text_mute"]))
        fm = QtGui.QFontMetrics(lf)
        tw = fm.horizontalAdvance(self._LABEL)
        p.drawText(-tw // 2, fm.ascent() // 2, self._LABEL)
        p.restore()

        # Expand chevron "›" near the bottom
        cf = QtGui.QFont()
        cf.setPixelSize(13)
        p.setFont(cf)
        p.setPen(QtGui.QColor(COLORS["text_mute"]))
        p.drawText(QtCore.QRect(0, h - 26, w - 1, 22), Qt.AlignCenter, "›")


class _SessionRowLabel(QtWidgets.QLabel):
    """Single-line session title that elides inside its assigned width."""

    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self._full_text = ""
        self.setMinimumWidth(0)
        self.setSizePolicy(
            QtWidgets.QSizePolicy.Ignored,
            QtWidgets.QSizePolicy.Preferred,
        )
        self.set_session_text(text)

    def set_session_text(self, text: str) -> None:
        self._full_text = text
        self.setToolTip(text)
        self._refresh_elision()

    def set_active(self, active: bool) -> None:
        if self.property("active") == active:
            return
        self.setProperty("active", active)
        self.style().unpolish(self)
        self.style().polish(self)
        self.update()

    def resizeEvent(self, event) -> None:  # type: ignore[override]
        super().resizeEvent(event)
        self._refresh_elision()

    def _refresh_elision(self) -> None:
        mode = getattr(getattr(Qt, "TextElideMode", Qt), "ElideRight")
        self.setText(
            self.fontMetrics().elidedText(
                self._full_text,
                mode,
                max(0, self.contentsRect().width()),
            )
        )


class _SessionRowWidget(QtWidgets.QWidget):
    hover_changed = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._hovered = False
        self.setMouseTracking(True)

    def track_hover_child(self, child: QtWidgets.QWidget) -> None:
        child.setMouseTracking(True)
        child.installEventFilter(self)

    def eventFilter(self, watched, event):  # type: ignore[override]
        if event.type() in (QtCore.QEvent.Enter, QtCore.QEvent.Leave):
            QtCore.QTimer.singleShot(0, self._sync_hover_from_cursor)
        return super().eventFilter(watched, event)

    def enterEvent(self, event) -> None:  # type: ignore[override]
        super().enterEvent(event)
        self._set_hovered(True)

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        super().leaveEvent(event)
        QtCore.QTimer.singleShot(0, self._sync_hover_from_cursor)

    def _sync_hover_from_cursor(self) -> None:
        try:
            point = self.mapFromGlobal(QtGui.QCursor.pos())
            self._set_hovered(self.rect().contains(point))
        except RuntimeError:
            pass

    def _set_hovered(self, hovered: bool) -> None:
        if hovered == self._hovered:
            return
        self._hovered = hovered
        self.hover_changed.emit(hovered)


class _SessionActionButton(QtWidgets.QToolButton):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._action_opacity = 0.0
        self._fade = QPropertyAnimation(self, b"action_opacity", self)
        self._fade.setDuration(MOTION_FAST_MS)
        self._fade.setEasingCurve(QEasingCurve.OutCubic)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)

    def _get_action_opacity(self) -> float:
        return self._action_opacity

    def _set_action_opacity(self, opacity: float) -> None:
        self._action_opacity = max(0.0, min(1.0, float(opacity)))
        self.update()

    action_opacity = Property(
        float, _get_action_opacity, _set_action_opacity
    )

    def set_revealed(self, revealed: bool, enabled: bool) -> None:
        target = 1.0 if revealed else 0.0
        self.setEnabled(enabled)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, not enabled)
        if not revealed:
            self._fade.stop()
            self._set_action_opacity(0.0)
            return
        if abs(self._action_opacity - target) < 0.001:
            return
        self._fade.stop()
        self._fade.setStartValue(self._action_opacity)
        self._fade.setEndValue(target)
        self._fade.start()


class _SessionRenameButton(_SessionActionButton):
    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setOpacity(self._action_opacity)

        color_key = "text" if self.isEnabled() and self.underMouse() else "text_mute"
        pen = QtGui.QPen(QtGui.QColor(COLORS[color_key]), 1.7)
        pen.setCapStyle(Qt.RoundCap)
        pen.setJoinStyle(Qt.RoundJoin)
        painter.setPen(pen)
        painter.setBrush(Qt.NoBrush)

        center = self.rect().center()
        _draw_pencil_glyph(
            painter,
            QtCore.QPointF(float(center.x()), float(center.y())),
        )


class _SessionDeleteButton(_SessionActionButton):
    def paintEvent(self, _event) -> None:  # type: ignore[override]
        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)
        painter.setOpacity(self._action_opacity)

        color_key = "failed" if self.isEnabled() and self.underMouse() else "text_mute"
        painter.setPen(Qt.NoPen)
        painter.setBrush(QtGui.QColor(COLORS[color_key]))

        cx = self.rect().center().x()
        top = self.rect().center().y() - 7
        painter.drawRoundedRect(QtCore.QRectF(cx - 2, top, 4, 2.5), 0.8, 0.8)
        painter.drawRoundedRect(QtCore.QRectF(cx - 6, top + 3, 12, 2.5), 0.8, 0.8)

        body = QtGui.QPainterPath()
        body.moveTo(cx - 5, top + 6)
        body.lineTo(cx + 5, top + 6)
        body.lineTo(cx + 4.2, top + 13)
        body.quadTo(cx + 4, top + 14, cx + 3, top + 14)
        body.lineTo(cx - 3, top + 14)
        body.quadTo(cx - 4, top + 14, cx - 4.2, top + 13)
        body.closeSubpath()
        painter.drawPath(body)


class ConversationDrawer(QtWidgets.QFrame):
    """Session-list panel overlaid on the left edge of the graph view.

    Interaction model
    -----------------
    * Hover the 3-bar icon (top of tab) → drawer opens fully, closes again when
      the mouse leaves the entire drawer frame.
    * Click anywhere on the tab → drawer opens and stays open (*sticky*).
    * Click anywhere outside the drawer while sticky → drawer closes.
    """

    session_selected = Signal(object)   # emits _SessionEntry
    session_rename_requested = Signal(object)
    session_delete_requested = Signal(object)

    _TAB_W  = 28    # always-visible tab width
    _FULL_W = 300   # fully-expanded panel width
    _ROW_H  = 36    # fixed session-row height keeps the list visually stable
    _MS     = MOTION_NORMAL_MS

    def __init__(self, graph_parent: QtWidgets.QWidget,
                 y_offset_widget: QtWidgets.QWidget = None):
        super().__init__(graph_parent)
        self.setObjectName("convDrawer")
        self._open            = False
        self._sticky          = False   # True = opened by click, stays open
        self._graph_parent    = graph_parent
        self._y_offset_widget = y_offset_widget  # drawer top = bottom of this widget
        self._session_rows = {}
        self._active_entry = None
        self._hovered_entry = None
        self._revealed_entries = set()

        # Event filter on the parent for resize events
        graph_parent.installEventFilter(self)
        # App-level filter to detect clicks outside the drawer
        QtWidgets.QApplication.instance().installEventFilter(self)

        self._build_ui()

        self._anim = QPropertyAnimation(self, b"geometry", self)
        self._anim.setDuration(self._MS)
        # Hide the panel after a close animation completes (not on stop/reverse)
        self._anim.finished.connect(self._on_anim_finished)

        # A short one-shot grace period prevents accidental close while moving
        # from the tab into the panel without continuously polling the cursor.
        self._hover_timer = QtCore.QTimer(self)
        self._hover_timer.setSingleShot(True)
        self._hover_timer.setInterval(120)
        self._hover_timer.timeout.connect(self._check_hover_close)

        self._place(animate=False)
        self.raise_()

    # ── Internal layout ───────────────────────────────────────────────────────

    def _build_ui(self) -> None:
        root = QtWidgets.QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._tab = _VerticalTabWidget()
        self._tab.clicked.connect(self._on_tab_click)
        self._tab.icon_hovered.connect(self._on_icon_hover)
        root.addWidget(self._tab)

        # Expanded panel — hidden when drawer is closed; shown just before the
        # open animation starts and hidden after the close animation finishes so
        # it reveals/hides with the drawer geometry rather than snapping.
        self._panel = QtWidgets.QFrame()
        self._panel.setObjectName("drawerPanel")
        # Fixed width (not min 0) so the panel content NEVER reflows / squashes
        # during the open/close animation.  The growing drawer frame clips the
        # panel (children are clipped to the parent), giving a clean horizontal
        # wipe instead of the content overlapping the always-visible tab while
        # the panel is narrower than the tab.
        self._panel.setFixedWidth(self._FULL_W)
        self._panel.setVisible(False)
        panel_lay = QtWidgets.QVBoxLayout(self._panel)
        panel_lay.setContentsMargins(0, 0, 0, 0)
        panel_lay.setSpacing(0)

        hdr = QtWidgets.QLabel("  SESSIONS")
        hdr.setObjectName("sectionHeader")
        panel_lay.addWidget(hdr)

        self._session_list = QtWidgets.QListWidget()
        self._session_list.setObjectName("sessionList")
        self._session_list.setFrameShape(QtWidgets.QFrame.NoFrame)
        self._session_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._session_list.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._session_list.setMouseTracking(True)
        self._session_list.viewport().setMouseTracking(True)
        self._session_list.itemClicked.connect(self._on_session_item_clicked)
        self._session_list.itemDoubleClicked.connect(
            self._on_session_item_double_clicked
        )

        self._content_stack = QtWidgets.QStackedWidget()
        self._content_stack.setObjectName("sessionContentStack")
        self._content_stack.setFrameShape(QtWidgets.QFrame.NoFrame)
        self._content_stack.setAutoFillBackground(False)
        self._content_stack.addWidget(self._session_list)

        self._loading_page = QtWidgets.QWidget()
        self._loading_page.setObjectName("sessionLoadingPage")
        self._loading_page.setAutoFillBackground(False)
        loading_lay = QtWidgets.QVBoxLayout(self._loading_page)
        loading_lay.setContentsMargins(16, 16, 16, 16)
        loading_lay.addStretch(1)
        loading_row = QtWidgets.QHBoxLayout()
        loading_row.setSpacing(8)
        loading_row.addStretch(1)
        self._loading_spinner = SpinnerLabel()
        loading_row.addWidget(self._loading_spinner)
        self._loading_label = QtWidgets.QLabel("Signing into server")
        self._loading_label.setObjectName("sessionLoadingLabel")
        loading_row.addWidget(self._loading_label)
        loading_row.addStretch(1)
        loading_lay.addLayout(loading_row)
        loading_lay.addStretch(1)
        self._content_stack.addWidget(self._loading_page)
        panel_lay.addWidget(self._content_stack, 1)

        # No stretch: the panel keeps its fixed width and is clipped by the
        # animating drawer frame, so it slides in/out as a clean wipe.
        root.addWidget(self._panel)
        # Tab paints last (on top) so the panel can never render over it.
        self._tab.raise_()

    # ── Public API ────────────────────────────────────────────────────────────

    def add_session(self, prompt: str, entry=None) -> None:
        """Insert a session row (newest first), storing the entry for restore."""
        self.insert_session(0, prompt, entry)
        self.set_active_session(entry)

    def set_loading(self, active: bool) -> None:
        self._loading_spinner.set_active(active)
        self._content_stack.setCurrentWidget(
            self._loading_page if active else self._session_list
        )
        self._sync_session_hover_from_cursor()

    def insert_session(self, row_index: int, prompt: str, entry=None) -> None:
        item = QtWidgets.QListWidgetItem()
        item.setToolTip(prompt)
        item.setData(Qt.UserRole, entry)
        row = _SessionRowWidget()
        row.setObjectName("sessionRow")
        row.setFixedHeight(self._ROW_H)
        row_lay = QtWidgets.QHBoxLayout(row)
        row_lay.setContentsMargins(18, 6, 14, 6)
        row_lay.setSpacing(2)
        label = _SessionRowLabel(prompt)
        label.setObjectName("sessionRowLabel")
        label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        row_lay.addWidget(label, 1, Qt.AlignVCenter)

        rename_btn = _SessionRenameButton()
        rename_btn.setObjectName("sessionRenameButton")
        rename_btn.setToolTip("Rename session")
        rename_btn.setAccessibleName("Rename session")
        rename_btn.setCursor(Qt.PointingHandCursor)
        rename_btn.setAutoRaise(True)
        rename_btn.setFixedSize(24, 24)
        rename_btn.setEnabled(False)
        rename_btn.clicked.connect(
            lambda _checked=False, target=entry:
                self.session_rename_requested.emit(target)
        )
        row_lay.addWidget(rename_btn, 0, Qt.AlignVCenter)

        delete_btn = _SessionDeleteButton()
        delete_btn.setObjectName("sessionDeleteButton")
        delete_btn.setToolTip("Delete session")
        delete_btn.setAccessibleName("Delete session")
        delete_btn.setCursor(Qt.PointingHandCursor)
        delete_btn.setAutoRaise(True)
        delete_btn.setFixedSize(26, 24)
        delete_btn.setEnabled(False)
        delete_btn.clicked.connect(
            lambda _checked=False, target=entry:
                self.session_delete_requested.emit(target)
        )
        row.hover_changed.connect(
            lambda hovered, target=entry:
                self._set_row_hover(target, hovered)
        )
        row_lay.addWidget(delete_btn, 0, Qt.AlignVCenter)
        for child in (label, rename_btn, delete_btn):
            row.track_hover_child(child)
        item.setSizeHint(QtCore.QSize(0, self._ROW_H))
        self._session_list.insertItem(row_index, item)
        self._session_list.setItemWidget(item, row)
        self._session_rows[entry] = {
            "item": item,
            "label": label,
            "rename_button": rename_btn,
            "delete_button": delete_btn,
            "row": row,
        }

    def remove_session(self, entry) -> int:
        if self._hovered_entry is entry:
            self._set_hovered_entry(None)
        self._revealed_entries.discard(entry)
        item = self._session_rows.pop(entry)["item"]
        row = self._session_list.row(item)
        self._session_list.takeItem(row)
        return row

    def set_session_title(self, entry, title: str) -> None:
        session_row = self._session_rows.get(entry)
        if session_row is None:
            return
        session_row["item"].setToolTip(title)
        session_row["label"].set_session_text(title)

    def set_active_session(self, entry) -> None:
        self._active_entry = entry
        for target, session_row in self._session_rows.items():
            session_row["label"].set_active(target is entry)
        self._sync_session_hover_from_cursor()
        active = self._session_rows.get(entry)
        if active is not None:
            self._session_list.setCurrentItem(active["item"])

    def _set_row_hover(self, entry, hovered: bool) -> None:
        if hovered:
            self._set_hovered_entry(entry)
        elif self._hovered_entry is entry:
            self._set_hovered_entry(None)

    def _set_hovered_entry(self, entry) -> None:
        previous = self._hovered_entry
        if previous is not entry:
            for revealed_entry in tuple(self._revealed_entries):
                if revealed_entry is entry:
                    continue
                revealed_row = self._session_rows.get(revealed_entry)
                if revealed_row is not None:
                    revealed_row["rename_button"].set_revealed(False, False)
                    revealed_row["delete_button"].set_revealed(False, False)
                self._revealed_entries.discard(revealed_entry)
            self._hovered_entry = entry

        session_row = self._session_rows.get(entry)
        if session_row is None or entry is None:
            return
        session_row["rename_button"].set_revealed(True, True)
        session_row["delete_button"].set_revealed(
            entry is not self._active_entry,
            entry is not self._active_entry,
        )
        self._revealed_entries.add(entry)

    def _sync_session_hover_from_cursor(self) -> None:
        if (
            not self._panel.isVisible()
            or self._content_stack.currentWidget() is not self._session_list
        ):
            self._set_hovered_entry(None)
            return
        viewport = self._session_list.viewport()
        point = viewport.mapFromGlobal(QtGui.QCursor.pos())
        if not viewport.rect().contains(point):
            self._set_hovered_entry(None)
            return
        item = self._session_list.itemAt(point)
        self._set_hovered_entry(item.data(Qt.UserRole) if item is not None else None)

    def _on_session_item_clicked(self, item: QtWidgets.QListWidgetItem) -> None:
        entry = item.data(Qt.UserRole)
        if entry is not None and not entry.network_only:
            self.session_selected.emit(entry)

    def _on_session_item_double_clicked(
        self, item: QtWidgets.QListWidgetItem
    ) -> None:
        entry = item.data(Qt.UserRole)
        if entry is not None and entry.network_only:
            self.session_selected.emit(entry)

    def close_drawer(self) -> None:
        """Force-close regardless of sticky state."""
        self._sticky = False
        self._hover_timer.stop()
        self._set_hovered_entry(None)
        if self._open:
            self._open = False
            self._place(animate=True)

    # ── Tab interaction ───────────────────────────────────────────────────────

    def _on_tab_click(self) -> None:
        """Click on the tab — toggle sticky open/close."""
        self._hover_timer.stop()
        if self._open and self._sticky:
            self._sticky = False
            self._open   = False
            self._set_hovered_entry(None)
        else:
            self._sticky = True
            self._open   = True
        self._place(animate=True)

    def _on_icon_hover(self, entered: bool) -> None:
        """Mouse entered/left the 3-bar icon zone — temporary open."""
        if self._sticky:
            return
        if entered:
            self._hover_timer.stop()
            if not self._open:
                self._open = True
                self._place(animate=True)
        elif self._open:
            self._hover_timer.start()

    def _check_hover_close(self) -> None:
        """Close a hover-open drawer once the pointer is outside it."""
        if self._sticky or not self._open:
            return
        cursor = self.mapFromGlobal(QtGui.QCursor.pos())
        if not self.rect().contains(cursor):
            self._open = False
            self._set_hovered_entry(None)
            self._place(animate=True)

    # ── Geometry helpers ──────────────────────────────────────────────────────

    def _on_anim_finished(self) -> None:
        """Hide the panel only after a completed close animation."""
        if not self._open:
            self._set_hovered_entry(None)
            self._panel.setVisible(False)

    def _place(self, animate: bool = True) -> None:
        gp  = self._graph_parent
        y   = (self._y_offset_widget.height() + 1) if self._y_offset_widget else 0
        h   = gp.height() - y - 1
        if h <= 0:
            return
        w      = (self._TAB_W + self._FULL_W) if self._open else self._TAB_W
        target = QtCore.QRect(1, y, w, h)
        # Show panel before the open animation so it wipes in from the start.
        # It stays visible during close and is hidden by _on_anim_finished.
        if self._open:
            self._panel.setVisible(True)
        if animate and self.isVisible():
            self._anim.stop()
            self._anim.setEasingCurve(
                QEasingCurve.OutCubic if self._open else QEasingCurve.InCubic
            )
            self._anim.setStartValue(self.geometry())
            self._anim.setEndValue(target)
            self._anim.start()
        else:
            self._anim.stop()
            self.setGeometry(target)
            # Non-animated (parent resize / show): sync visibility immediately.
            self._panel.setVisible(self._open)

    def enterEvent(self, event) -> None:  # type: ignore[override]
        self._hover_timer.stop()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        super().leaveEvent(event)
        self._set_hovered_entry(None)
        if self._open and not self._sticky:
            self._hover_timer.start()

    def resizeEvent(self, e) -> None:  # type: ignore[override]
        super().resizeEvent(e)
        # Panel visibility is managed by _place() and _on_anim_finished().

    def showEvent(self, event: QtCore.QEvent) -> None:  # type: ignore[override]
        super().showEvent(event)
        self._place(animate=False)

    def eventFilter(self, obj: QtCore.QObject, event: QtCore.QEvent) -> bool:  # type: ignore[override]
        # Resize of graph parent → reposition
        if obj is self._graph_parent:
            if event.type() == QtCore.QEvent.Resize:
                self._place(animate=False)
            return False

        event_type = event.type()
        hover_move = getattr(QtCore.QEvent, "HoverMove", None)
        if (
            (
                event_type == QtCore.QEvent.MouseMove
                or (hover_move is not None and event_type == hover_move)
            )
            and self._panel.isVisible()
        ):
            self._sync_session_hover_from_cursor()

        # Global mouse press — close if sticky and click is outside the drawer
        if (event_type == QtCore.QEvent.MouseButtonPress
                and self._open and self._sticky):
            gpos = event.globalPos()
            drawer_global = QtCore.QRect(
                self.mapToGlobal(QtCore.QPoint(0, 0)), self.size()
            )
            if not drawer_global.contains(gpos):
                self.close_drawer()

        return False


# ???????????????????????????????????????????????????????????????????????????
#  Elided label — single-line text that truncates with '…'
# ???????????????????????????????????????????????????????????????????????????

class _ElidedLabel(QtWidgets.QLabel):
    """Single-line QLabel that elides its text with '…' when too narrow.

    Newlines and runs of whitespace in the source text are collapsed to single
    spaces, so the label never grows past one line — keeping its host toolbar a
    static height. The full untruncated text is exposed as the tooltip.

    Horizontal size policy is Ignored so a long prompt never dictates the
    toolbar width (and never squeezes the neighbouring buttons); the label
    simply fills whatever space the layout grants it and elides to fit.
    """

    def __init__(self, text: str = "", parent=None):
        super().__init__(parent)
        self._full = ""
        self.setSizePolicy(QtWidgets.QSizePolicy.Ignored,
                           QtWidgets.QSizePolicy.Fixed)
        self.setText(text)

    def setText(self, text: str) -> None:  # type: ignore[override]
        self._full = " ".join((text or "").split())
        self.setToolTip(self._full)
        self._update_elision()

    def text(self) -> str:  # type: ignore[override]
        return self._full

    def resizeEvent(self, e) -> None:  # type: ignore[override]
        super().resizeEvent(e)
        self._update_elision()

    def _update_elision(self) -> None:
        fm = self.fontMetrics()
        # contentsRect() excludes any QSS padding/border so the '…' lands inside
        # the visible text area rather than clipping into the padding.
        avail = max(0, self.contentsRect().width())
        elided = fm.elidedText(self._full, Qt.ElideRight, avail)
        super().setText(elided)


# ???????????????????????????????????????????????????????????????????????????
#  Resize grip — themed corner handle for frameless windows
# ???????????????????????????????????????????????????????????????????????????

class _ResizeGrip(QtWidgets.QSizeGrip):
    """QSizeGrip with a subtle triangular dot pattern matching the dark theme.

    Draws 6 dots in a staircase — the standard bottom-right resize affordance —
    in ``COLORS['border_hi']`` so it's visible but unobtrusive.
    """
    def paintEvent(self, _e) -> None:
        p = QtGui.QPainter(self)
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QtGui.QColor(COLORS["border_hi"]))
        w, h = self.width(), self.height()
        for row in range(3):
            for col in range(3 - row):   # 3, 2, 1 dots → triangle
                cx = w - 3 - col * 4
                cy = h - 3 - row * 4
                p.drawEllipse(QtCore.QPointF(cx, cy), 1.2, 1.2)


# ???????????????????????????????????????????????????????????????????????????
#  Graph/log splitter — thin divider line with a centred dotted grip
# ???????????????????????????????????????????????????????????????????????????

class _SplitterHandle(QtWidgets.QSplitterHandle):
    """Splitter handle that reads as the log box's own left edge.

    The handle would otherwise sit as a contrasting strip just left of the log
    panel — lighter than the dark chat-input row, so it looked like a bar poking
    out to the left. Instead it blends per-region: it fills with the chat-area
    background (bg_elev) where it sits beside the chat thread, and with the
    input-row background (bg_card) where it sits beside the chat-input row, with
    that row's top border continued across it. The result is a seamless 1px
    divider line on the left, with three small grip dots as the drag affordance.
    """

    def __init__(self, orientation, parent):
        super().__init__(orientation, parent)
        self._hover = False

    def enterEvent(self, e):  # type: ignore[override]
        self._hover = True
        self.update()
        super().enterEvent(e)

    def leaveEvent(self, e):  # type: ignore[override]
        self._hover = False
        self.update()
        super().leaveEvent(e)

    def paintEvent(self, _e) -> None:  # type: ignore[override]
        p = QtGui.QPainter(self)
        w, h = self.width(), self.height()

        # Find where the chat-input row begins, in this handle's coordinates, so
        # the fill below that line matches the row and the fill above matches the
        # chat area — no contrasting strip at any vertical level.
        split_y = h
        row = getattr(self.splitter(), "input_row", None)
        if row is not None and row.isVisible():
            try:
                split_y = self.mapFromGlobal(row.mapToGlobal(QtCore.QPoint(0, 0))).y()
            except Exception:
                split_y = h
            split_y = max(0, min(h, split_y))

        if split_y > 0:
            p.fillRect(0, 0, w, split_y, QtGui.QColor(COLORS["bg_elev"]))
        if split_y < h:
            p.fillRect(0, split_y, w, h - split_y, QtGui.QColor(COLORS["bg_card"]))
            # Continue the input row's top border across the handle.
            p.fillRect(0, split_y, w, 1, QtGui.QColor(COLORS["border_hi"]))

        # 1px divider line on the left edge — the visible separator.
        line_col = QtGui.QColor(COLORS["text_mute"] if self._hover else COLORS["border_hi"])
        p.fillRect(0, 0, 1, h, line_col)

        # Grip dots — centred within the chat-area portion (above the input row).
        p.setRenderHint(QtGui.QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QtGui.QColor(COLORS["text_mute"]))
        cx = w / 2.0
        cy = (split_y / 2.0) if split_y > 24 else (h / 2.0)
        for i in (-1, 0, 1):
            p.drawEllipse(QtCore.QPointF(cx, cy + i * 5.0), 1.2, 1.2)


class _MainSplitter(QtWidgets.QSplitter):
    """QSplitter that uses _SplitterHandle for its draggable dividers.

    ``input_row`` is set by AnalysisDialog to the chat-input QFrame so the
    handle can blend its fill to match that row's background at the bottom.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.input_row = None

    def createHandle(self):  # type: ignore[override]
        return _SplitterHandle(self.orientation(), self)


# ???????????????????????????????????????????????????????????????????????????
#  Session entry — lightweight per-session state record
# ???????????????????????????????????????????????????????????????????????????

class _SessionEntry:
    """Records the UI state of one analysis session for later restoration.

    ``messages`` is a plain-text log: each element is (role, text) where
    role is ``"You"`` or ``"AI"``.  Workers are kept alive by the polling
    loop even after analysis ends so the user can still send follow-up
    messages; we reconnect signals when switching to a session.
    """
    __slots__ = (
        "prompt", "display_name", "worker", "messages", "is_done", "toolbar_info",
        "network_only", "history_loaded", "graph_nodes", "session_status",
    )

    def __init__(self, prompt: str, worker, network_only: bool = False) -> None:
        self.prompt       = prompt
        self.display_name = prompt
        self.worker       = worker
        self.messages: list = []       # [(role, text), …]
        self.is_done: bool  = False
        self.toolbar_info: tuple = ()  # (target_name, ea_str, prompt_summary)
        self.network_only = network_only
        self.history_loaded = not network_only
        self.graph_nodes: dict = {}
        self.session_status = "done" if network_only else "running"


# ???????????????????????????????????????????????????????????????????????????
#  Main analysis dialog
# ???????????????????????????????????????????????????????????????????????????

class AnalysisDialog(RoundedDialogMixin, QtWidgets.QDialog):
    """Compact prompt that animates into a full analysis view."""

    sig_shutdown_complete = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._use_native_rounded_mask = False
        self.setObjectName("analysisDialog")
        self.setWindowTitle(PLUGIN_NAME)
        self.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setAttribute(Qt.WA_NoSystemBackground, True)
        self.setAutoFillBackground(False)
        self.setStyleSheet(main_qss())

        self._active_entry: Optional[_SessionEntry] = None
        self._all_entries: list = []   # local sessions plus names-only server history
        self._ea: Optional[int] = None
        self._current_view: dict = {"address": ""}
        self._expanded = False
        self._starting_analysis = False
        self._start_ts: Optional[QtCore.QElapsedTimer] = None
        self._current_working: Optional[WorkingWidget] = None
        self._current_log_pane: Optional[WorkingLogPane] = None
        self._final_answer_log_pane: Optional[WorkingLogPane] = None
        self._streaming_widget: Optional[StreamingChatMessageWidget] = None
        self._waiting_for_first_node = False
        self._browser_auth_thread = None
        self._browser_auth_worker = None
        self._auth_verify_thread = None
        self._auth_verify_worker = None
        self._update_check_thread = None
        self._update_check_worker = None
        self._update_install_thread = None
        self._update_install_worker = None
        self._available_update_version = ""
        self._session_rename_jobs = {}
        self._session_delete_jobs = {}
        self._session_detail_jobs = {}
        self._session_names_thread = None
        self._session_names_worker = None
        self._session_names_account_id = ""
        self._session_names_loading_account_id = ""
        self._usage_thread = None
        self._usage_worker = None
        self._usage_loading_account_id = ""
        self._chat_send_jobs = {}
        self._shutting_down = False
        self._final_close = False
        self._reopen_requested = False
        self._shutdown_timer = QtCore.QTimer(self)
        self._shutdown_timer.setInterval(100)
        self._shutdown_timer.timeout.connect(self._finish_shutdown_if_ready)

        self._build_ui()
        self._view_refresh_timer = QtCore.QTimer(self)
        self._view_refresh_timer.setInterval(500)
        self._view_refresh_timer.timeout.connect(self._refresh_target)
        self._view_refresh_timer.start()
        self._usage_refresh_timer = QtCore.QTimer(self)
        self._usage_refresh_timer.setInterval(30_000)
        self._usage_refresh_timer.timeout.connect(self._refresh_usage)
        self._usage_refresh_timer.start()
        self._update_check_timer = QtCore.QTimer(self)
        self._update_check_timer.setInterval(
            updater.UPDATE_CHECK_INTERVAL_SECONDS * 1000
        )
        self._update_check_timer.timeout.connect(self._start_update_check)
        self._update_check_timer.start()
        self._refresh_target()
        self._refresh_auth_profile()
        self._verify_saved_sign_in()
        self._start_update_check()
        self.resize(COMPACT_SIZE)
        # Compact minimum height must clear: title bar (40) + margins (42) +
        # target row (~28) + prompt min (140) + 2×spacing (28) + button (~38)
        # ≈ 316, so 330 keeps the Analyse button off the prompt box.
        self.setMinimumSize(440, 330)   # compact minimum; expanded updates this

    # ─── UI construction ─────────────────────────────────────────────────
    def _build_ui(self):
        dlg_lay = QtWidgets.QVBoxLayout(self)
        dlg_lay.setContentsMargins(1, 1, 1, 1)
        dlg_lay.setSpacing(0)

        self.root_surface = _RoundedAnalysisSurface()
        self.root_surface.setObjectName("analysisRootSurface")
        dlg_lay.addWidget(self.root_surface)

        root_layout = QtWidgets.QVBoxLayout(self.root_surface)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)
        self.root_content = _RoundedAnalysisContent()
        root_layout.addWidget(self.root_content)

        outer = QtWidgets.QVBoxLayout(self.root_content)
        outer.setContentsMargins(1, 1, 1, 1)
        outer.setSpacing(0)

        # Title bar
        self.title_bar = TitleBar()
        self.title_bar.sig_close.connect(self.close)
        self.title_bar.sig_settings.connect(self._open_settings)
        self.title_bar.sig_sign_in.connect(self._sign_in_with_browser)
        self.title_bar.sig_account.connect(self._open_account_settings)
        self.title_bar.sig_update.connect(self._install_available_update)
        outer.addWidget(self.title_bar)

        # ── Compact body ────────────────────────────────────────────────
        self.compact_body = QtWidgets.QWidget()
        self.compact_body.setObjectName("compactBody")
        cb = QtWidgets.QVBoxLayout(self.compact_body)
        cb.setContentsMargins(44, 20, 24, 22)  # 44 = 28px tab + 16px breathing room
        cb.setSpacing(14)

        tgt_row = QtWidgets.QHBoxLayout()
        self.target_pill = TargetPill()
        self.target_pill.sig_refresh.connect(self._refresh_target)
        tgt_row.addWidget(self.target_pill)
        tgt_row.addStretch(1)

        # Model tier combo — shown in the compact view
        self.cmb_model_tier = QtWidgets.QComboBox()
        for label, _value in _MODEL_TIER_OPTIONS:
            self.cmb_model_tier.addItem(label)
        self.cmb_model_tier.setCurrentIndex(
            _tier_label_for(g_settings.get("model_tier", "fast"))
        )
        self.cmb_model_tier.currentIndexChanged.connect(self._on_model_tier_changed)
        self.cmb_model_tier.setToolTip(
            "LLM tier for this analysis.\n"
            "Fast: fast model throughout.\n"
            "Dynamic: fast model for reversal, smart model for the final answer.\n"
            "Smart: smart model throughout."
        )
        tgt_row.addWidget(self.cmb_model_tier)
        cb.addLayout(tgt_row)

        self.prompt_input = QtWidgets.QTextEdit()
        self.prompt_input.setObjectName("promptInput")
        self.prompt_input.setPlaceholderText(
            "What do you want to know about this binary?"
        )
        self.prompt_input.setMinimumHeight(140)
        cb.addWidget(self.prompt_input, 1)

        btn_row = QtWidgets.QHBoxLayout()
        self.btn_analyse = OutlinedButton("▶  Analyse", primary=True, variant="subtle")
        self.btn_analyse.clicked.connect(self._start_analysis)
        btn_row.addWidget(self.btn_analyse, 1)
        cb.addLayout(btn_row)

        outer.addWidget(self.compact_body, 1)

        # ── Expanded toolbar ────────────────────────────────────────────
        self.toolbar = QtWidgets.QFrame()
        self.toolbar.setObjectName("expandedToolbar")
        tb = QtWidgets.QHBoxLayout(self.toolbar)
        # Left margin must clear the ConversationDrawer tab (1 px offset + _TAB_W).
        # Top/bottom margins are 9 (was 12) — trims 6px off the header height.
        tb.setContentsMargins(ConversationDrawer._TAB_W + 10, 9, 14, 9)
        tb.setSpacing(12)

        self.tb_target_name = QtWidgets.QLabel("")
        self.tb_target_name.setObjectName("targetName")
        self.tb_target_ea = QtWidgets.QLabel("")
        self.tb_target_ea.setObjectName("targetEA")
        tb.addWidget(self.tb_target_name)
        tb.addWidget(self.tb_target_ea)

        # Vertical divider between the EA and the prompt — a dedicated widget so
        # its height is independent of the (short) label height; centred in the
        # row, it stands taller than the old label border-left did.
        self._tb_divider = QtWidgets.QFrame()
        self._tb_divider.setObjectName("toolbarDivider")
        self._tb_divider.setFixedWidth(1)
        self._tb_divider.setFixedHeight(24)
        tb.addWidget(self._tb_divider)

        # Elided single-line label — truncates with '…' when it runs out of
        # room next to the buttons, and collapses newlines so it stays 1 line.
        self.tb_prompt_summary = _ElidedLabel("")
        self.tb_prompt_summary.setObjectName("promptSummary")
        tb.addWidget(self.tb_prompt_summary, 1)

        self.btn_cancel = OutlinedButton("✕  Cancel", primary=False, variant="danger")
        self.btn_cancel.clicked.connect(self._stop_analysis)

        # Fixed size so the action buttons never shrink/grow with the prompt.
        for _btn in (self.btn_cancel,):
            _btn.setSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)

        tb.addWidget(self.btn_cancel)

        # Static height — the prompt summary elides to one line rather than
        # wrapping, so the header never grows to fit a long/multi-line prompt.
        # Derived from the button height + the 9px top/bottom margins (18 total)
        # so it never clips on systems with a taller default font.
        self.toolbar.setFixedHeight(self.btn_cancel.sizeHint().height() + 18)

        self.toolbar.hide()
        outer.addWidget(self.toolbar)

        # ── Expanded body: graph + log, split by a draggable divider ─────
        self.expanded_body = QtWidgets.QWidget()
        self.expanded_body.setObjectName("expandedBody")
        self.expanded_body.hide()
        ex = QtWidgets.QHBoxLayout(self.expanded_body)
        ex.setContentsMargins(0, 0, 0, 0)
        ex.setSpacing(0)

        # Horizontal splitter lets the user drag the graph/log boundary.
        # _MainSplitter paints a thin 1px divider with a centred dotted grip,
        # so the handle reads like the old static border (not a thick bar).
        self._main_splitter = _MainSplitter(Qt.Horizontal)
        self._main_splitter.setObjectName("mainSplitter")
        self._main_splitter.setHandleWidth(7)
        self._main_splitter.setChildrenCollapsible(False)
        ex.addWidget(self._main_splitter)

        self.graph_view = FunctionGraphView()
        self.graph_view.set_left_inset(ConversationDrawer._TAB_W)
        self._main_splitter.addWidget(self.graph_view)

        # Keep the drawer in the clipped content layer so it overlays both
        # views without escaping the rounded window surface.
        # y_offset_widget=title_bar keeps the drawer below the title bar.
        self.conv_drawer = ConversationDrawer(
            self.root_content,
            y_offset_widget=self.title_bar,
        )
        self.conv_drawer.session_selected.connect(self._restore_session)
        self.conv_drawer.session_rename_requested.connect(
            self._request_rename_session
        )
        self.conv_drawer.session_delete_requested.connect(
            self._request_delete_session
        )
        self._session_loading_overlay = _SessionLoadingOverlay(
            self.root_content, self.conv_drawer._tab
        )

        # ── Right panel: log on top, chat on bottom (Layout B) ────────────
        # NB: chat-scroll + working-log scrollbars are styled in main_qss()
        # (scoped by object name).  Styling a QAbstractScrollArea's scrollbar
        # by calling setStyleSheet() on the bare scrollbar widget leaves the
        # handle unrendered — the rules must cascade from an ancestor sheet.
        self.log_panel = QtWidgets.QFrame()
        self.log_panel.setObjectName("logPanel")
        # Dynamically sized via the splitter — keep a sensible floor so the
        # chat thread stays readable, but let the user widen/narrow it freely.
        self.log_panel.setMinimumWidth(280)
        lp = QtWidgets.QVBoxLayout(self.log_panel)
        lp.setContentsMargins(0, 0, 0, 0)
        lp.setSpacing(0)

        # ── Chat thread scroll area ────────────────────────────────────────
        self._chat_scroll = QtWidgets.QScrollArea()
        self._chat_scroll.setObjectName("chatScroll")
        self._chat_scroll.setWidgetResizable(True)
        self._chat_scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._chat_scroll.setFrameShape(QtWidgets.QFrame.NoFrame)
        self._chat_follow_output = True
        self._chat_scroll_pending = False
        self._chat_scroll_programmatic = False
        chat_scrollbar = self._chat_scroll.verticalScrollBar()
        chat_scrollbar.valueChanged.connect(self._on_chat_scroll_value_changed)
        chat_scrollbar.rangeChanged.connect(self._on_chat_scroll_range_changed)

        self._chat_container = QtWidgets.QWidget()
        self._chat_container.setObjectName("chatContainer")
        self._thread_lay = QtWidgets.QVBoxLayout(self._chat_container)
        self._thread_lay.setContentsMargins(0, 8, 0, 8)
        self._thread_lay.setSpacing(2)
        self._thread_lay.addStretch(1)   # pushes messages to top initially

        self._chat_scroll.setWidget(self._chat_container)
        lp.addWidget(self._chat_scroll, 1)

        # ── Always-visible input row ───────────────────────────────────────
        _input_frame = QtWidgets.QFrame()
        _input_frame.setObjectName("chatInputRow")
        _if_lay = QtWidgets.QHBoxLayout(_input_frame)
        _if_lay.setContentsMargins(8, 8, 8, 8)
        _if_lay.setSpacing(6)
        self.chat_input = QtWidgets.QLineEdit()
        self.chat_input.setObjectName("chatInput")
        self.chat_input.setPlaceholderText("Ask a question…")
        self.chat_input.installEventFilter(self)
        self.chat_input.setEnabled(False)
        self.btn_send_chat = OutlinedButton("Send", primary=True)
        self.btn_send_chat.clicked.connect(self._send_chat_message)
        self.btn_send_chat.setEnabled(False)
        self.usage_limit = UsageLimitWidget()
        self.usage_limit.setEnabled(True)
        _if_lay.addWidget(self.chat_input, 1)
        _if_lay.addWidget(self.btn_send_chat)
        _if_lay.addWidget(self.usage_limit)
        lp.addWidget(_input_frame)

        # Let the splitter handle blend its lower portion into this row so the
        # row's dark box reads as flush to the divider (no left-poking strip).
        self._main_splitter.input_row = _input_frame

        self._main_splitter.addWidget(self.log_panel)
        # Graph soaks up extra width on resize; the log keeps its dragged size.
        self._main_splitter.setStretchFactor(0, 1)
        self._main_splitter.setStretchFactor(1, 0)
        # Initial split: graph ~700, log ~400 (matches the old fixed width).
        self._main_splitter.setSizes([700, 400])
        outer.addWidget(self.expanded_body, 1)

        # ── Keyboard shortcuts ─────────────────────────────────────────
        QShortcut(QtGui.QKeySequence("Ctrl+Return"), self, activated=self._start_analysis)
        QShortcut(QtGui.QKeySequence("Ctrl+Enter"),  self, activated=self._start_analysis)
        QShortcut(QtGui.QKeySequence("Esc"),         self, activated=self._on_esc)

        # ── Resize grip ────────────────────────────────────────────────
        # Frameless windows have no OS resize border; QSizeGrip provides it.
        # Positioned and kept at the bottom-right corner via resizeEvent.
        self._grip = _ResizeGrip(self)
        self._grip.setFixedSize(16, 16)
        self._root_border_overlay = _RoundedBorderOverlay(
            self.root_surface,
            self,
        )
        self._sync_root_border_overlay()

    def _sync_root_border_overlay(self) -> None:
        overlay = getattr(self, "_root_border_overlay", None)
        root = getattr(self, "root_surface", None)
        if overlay is None or root is None:
            return
        overlay.sync_geometry()

    # ─── Target & settings ───────────────────────────────────────────────
    def _on_model_tier_changed(self, idx: int):
        if 0 <= idx < len(_MODEL_TIER_OPTIONS):
            _label, value = _MODEL_TIER_OPTIONS[idx]
            g_settings["model_tier"] = value
            save_settings()

    def _refresh_target(self):
        view = get_current_view()
        self._current_view = dict(view)
        address = str(view.get("address", "") or "")
        try:
            viewed_ea = int(address, 16)
        except (TypeError, ValueError):
            viewed_ea = None
        function_address = str(view.get("function_address", "") or "")
        try:
            function_ea = int(function_address, 16)
        except (TypeError, ValueError):
            function_ea = None

        if viewed_ea is None:
            self._ea = None
            self.target_pill.set_target("", None)
            self.btn_analyse.setEnabled(False)
            return

        self._ea = function_ea if function_ea is not None else viewed_ea
        name = str(view.get("function_name", "") or "")
        display_name = name if name else "Address"
        display_ea = function_ea if function_ea is not None else viewed_ea
        self.target_pill.set_target(display_name, display_ea)
        self.tb_target_name.setText(display_name)
        self.tb_target_ea.setText(f"{display_ea:#x}")
        self.btn_analyse.setEnabled(True)

    def _refresh_auth_profile(self):
        prof = auth_state.profile()
        signed_in = bool(prof["verified"] and prof["name"])
        self.title_bar.set_profile(signed_in, prof["name"], prof["avatar_url"])
        self.usage_limit.hide()
        if signed_in:
            self._refresh_usage()
        if not signed_in and self._session_names_account_id:
            self._clear_network_session_names()
            self._session_names_account_id = ""

    def _refresh_usage(self) -> None:
        account_id = auth_state.active_account_id()
        if self._shutting_down or not account_id or self._usage_thread is not None:
            return
        thread = QtCore.QThread()
        worker = _LoadUsageWorker(account_id)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._usage_loaded)
        worker.sig_finished.connect(thread.quit)
        worker.sig_finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._usage_load_finished)
        self._usage_thread = thread
        self._usage_worker = worker
        self._usage_loading_account_id = account_id
        thread.start()

    def _usage_loaded(self, account_id: str, percent: float) -> None:
        if account_id != auth_state.active_account_id():
            return
        value = max(0.0, min(100.0, float(percent)))
        self.usage_limit.set_usage(value / 100.0, f"{round(value):.0f}%")
        self.usage_limit.show()

    def _usage_load_finished(self) -> None:
        requested_account_id = self._usage_loading_account_id
        self._usage_thread = None
        self._usage_worker = None
        self._usage_loading_account_id = ""
        active_account_id = auth_state.active_account_id()
        if active_account_id and active_account_id != requested_account_id:
            self._refresh_usage()

    def _verify_saved_sign_in(self):
        self.conv_drawer.set_loading(True)
        thread = QtCore.QThread(self)
        worker = _VerifySignInWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._verify_sign_in_done)
        worker.sig_done.connect(thread.quit)
        worker.sig_done.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._verify_sign_in_finished)
        self._auth_verify_thread = thread
        self._auth_verify_worker = worker
        thread.start()

    def _verify_sign_in_done(self, _profile: dict):
        self._refresh_auth_profile()
        if auth_state.profile().get("verified"):
            self._load_network_session_names()
        else:
            self.conv_drawer.set_loading(False)

    def _verify_sign_in_finished(self):
        self._auth_verify_thread = None
        self._auth_verify_worker = None
        if self._session_names_thread is None:
            self.conv_drawer.set_loading(False)

    def _sign_in_with_browser(self):
        self.title_bar.btn_account.setEnabled(False)
        self.title_bar.btn_account.setText("Signing in...")
        thread = QtCore.QThread(self)
        worker = _BrowserSignInWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._browser_sign_in_done)
        worker.sig_error.connect(self._browser_sign_in_error)
        worker.sig_finished.connect(thread.quit)
        worker.sig_finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._browser_sign_in_finished)
        self._browser_auth_thread = thread
        self._browser_auth_worker = worker
        thread.start()

    def _browser_sign_in_done(self, result: dict):
        if self._shutting_down:
            return
        refresh_token = str(result.get("refresh_token", "") or "")
        if not refresh_token:
            self._browser_sign_in_error("Browser sign-in did not return a refresh token.")
            return
        account_id = auth_state.account_id_for_data(result)
        server_url = str(
            result.get("server_url", "") or g_settings.get("server_url", "")
        )
        try:
            secret_store.save_refresh_token(
                refresh_token, account_id, server_url
            )
        except secret_store.CredentialStoreUnavailable as e:
            self._browser_sign_in_error(str(e))
            return
        reset_shared_auth_context(account_id, server_url)
        auth_state.save_signed_in_profile(result, verified=True, account_id=account_id)
        self._refresh_auth_profile()
        self._load_network_session_names()

    def _browser_sign_in_error(self, message: str):
        if self._shutting_down:
            return
        self._refresh_auth_profile()
        QtWidgets.QMessageBox.critical(self, "Browser sign-in failed", message)

    def _browser_sign_in_finished(self):
        if not self._shutting_down:
            self.title_bar.btn_account.setEnabled(True)
        self._browser_auth_thread = None
        self._browser_auth_worker = None

    def _load_network_session_names(self) -> None:
        account_id = auth_state.active_account_id()
        if not account_id or self._session_names_account_id == account_id:
            return
        if self._session_names_thread is not None:
            return
        thread = QtCore.QThread(self)
        worker = _LoadSessionNamesWorker(account_id)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._network_session_names_loaded)
        worker.sig_done.connect(thread.quit)
        worker.sig_error.connect(thread.quit)
        worker.sig_done.connect(worker.deleteLater)
        worker.sig_error.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._session_names_load_finished)
        self._session_names_thread = thread
        self._session_names_worker = worker
        self._session_names_loading_account_id = account_id
        self.conv_drawer.set_loading(True)
        self._clear_network_session_names()
        thread.start()

    def _network_session_names_loaded(self, account_id: str, sessions: list) -> None:
        if account_id != auth_state.active_account_id():
            return
        self._session_names_account_id = account_id
        existing_ids = {
            getattr(entry.worker, "session_id", "")
            for entry in self._all_entries
        }
        for item in sessions:
            if not isinstance(item, dict):
                continue
            session_id = str(item.get("id", "") or "").strip()
            if not session_id or session_id in existing_ids:
                continue
            name = str(item.get("name", "") or "").strip() or session_id
            entry = _SessionEntry(
                name,
                NetworkHistorySession(session_id, account_id),
                network_only=True,
            )
            entry.is_done = True
            self._all_entries.append(entry)
            self.conv_drawer.insert_session(
                len(self._all_entries) - 1, name, entry
            )
            existing_ids.add(session_id)

    def _clear_network_session_names(self) -> None:
        active_was_network = bool(
            self._active_entry and self._active_entry.network_only
        )
        for entry in list(self._all_entries):
            if not entry.network_only:
                continue
            self.conv_drawer.remove_session(entry)
            self._all_entries.remove(entry)
        if active_was_network:
            self._active_entry = None
            self.graph_view.reset()
            while self._thread_lay.count() > 1:
                item = self._thread_lay.takeAt(0)
                if item and item.widget():
                    item.widget().deleteLater()
            self._set_chat_controls_enabled(False)

    def _session_names_load_finished(self) -> None:
        requested_account_id = self._session_names_loading_account_id
        self._session_names_thread = None
        self._session_names_worker = None
        self._session_names_loading_account_id = ""
        self.conv_drawer.set_loading(False)
        active_account_id = auth_state.active_account_id()
        if (
            active_account_id
            and requested_account_id != active_account_id
            and self._session_names_account_id != active_account_id
        ):
            self._load_network_session_names()

    def _start_update_check(self) -> None:
        if self._shutting_down or self._update_check_thread is not None:
            return
        thread = QtCore.QThread(self)
        worker = _UpdateCheckWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._update_check_done)
        worker.sig_finished.connect(thread.quit)
        worker.sig_finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._update_check_finished)
        self._update_check_thread = thread
        self._update_check_worker = worker
        thread.start()

    def _update_check_done(self, info) -> None:
        if self._shutting_down or not isinstance(info, updater.UpdateInfo):
            return
        self._available_update_version = info.version
        self.title_bar.set_update_available(info.version)

    def _update_check_finished(self) -> None:
        self._update_check_thread = None
        self._update_check_worker = None

    def _install_available_update(self) -> None:
        if (
            self._shutting_down
            or not self._available_update_version
            or self._update_install_thread is not None
        ):
            return
        self.title_bar.set_update_busy(True)
        thread = QtCore.QThread(self)
        worker = _UpdateInstallWorker()
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._update_install_done)
        worker.sig_error.connect(self._update_install_error)
        worker.sig_finished.connect(thread.quit)
        worker.sig_finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._update_install_finished)
        self._update_install_thread = thread
        self._update_install_worker = worker
        thread.start()

    def _update_install_done(self, result) -> None:
        if self._shutting_down or not isinstance(result, updater.InstallResult):
            return
        self._available_update_version = ""
        self.title_bar.set_update_available("")
        QtWidgets.QMessageBox.information(
            self,
            "Update installed",
            f"Decompile.re {result.version} was installed successfully.\n\n"
            "Restart IDA Pro before continuing.",
        )

    def _update_install_error(self, error) -> None:
        if self._shutting_down:
            return
        self.title_bar.set_update_available(self._available_update_version)
        message = str(error) or "The update could not be installed."
        if isinstance(error, updater.InstallerRequiredError):
            message += (
                "\n\nThe Decompile.re setup wizard is required to complete "
                "this update. Open its official download page now?"
            )
            answer = QtWidgets.QMessageBox.question(
                self,
                "Setup wizard required",
                message,
                QtWidgets.QMessageBox.StandardButton.Yes
                | QtWidgets.QMessageBox.StandardButton.No,
                QtWidgets.QMessageBox.StandardButton.Yes,
            )
            if answer == QtWidgets.QMessageBox.StandardButton.Yes:
                webbrowser.open(
                    SETUP_WIZARD_RELEASE_URL,
                    new=1,
                    autoraise=True,
                )
            return
        QtWidgets.QMessageBox.warning(self, "Update failed", message)

    def _update_install_finished(self) -> None:
        self._update_install_thread = None
        self._update_install_worker = None
        if self._available_update_version:
            self.title_bar.set_update_busy(False)

    def _open_account_settings(self):
        url = browser_auth.dashboard_url_for()
        webbrowser.open(f"{url}/app/account", new=1, autoraise=True)

    def _open_settings(self):
        dlg = SettingsDialog(self)
        dlg.exec()
        self._refresh_auth_profile()
        if auth_state.profile().get("verified"):
            self._load_network_session_names()

    # ─── Start & stop ─────────────────────────────────────────────────────
    def _start_analysis(self):
        if self._starting_analysis:
            return
        _cur_worker = self._active_entry.worker if self._active_entry else None
        if self._expanded and _cur_worker and _cur_worker.isRunning():
            return

        if not REQUESTS_AVAILABLE:
            QtWidgets.QMessageBox.critical(
                self, "Missing dependency",
                "The 'requests' library is not installed in IDA's Python env.\n\n"
                "Fix:  pip install requests\n(use the Python interpreter that IDA uses)"
            )
            return

        prompt = self.prompt_input.toPlainText().strip()
        if not prompt:
            QtWidgets.QMessageBox.warning(self, "Empty prompt", "Please enter an analysis prompt.")
            return
        if not self._ea:
            QtWidgets.QMessageBox.warning(self, "No target", "Place the cursor at an address in the IDB first.")
            return

        server_url = g_settings.get("server_url", "https://api.decompile.re")
        if not server_url:
            QtWidgets.QMessageBox.warning(self, "No server", "Server URL is not configured.")
            return

        if not secret_store.load_refresh_token(server_url=server_url) and not is_loopback_server_url(server_url):
            QtWidgets.QMessageBox.warning(
                self, "Not signed in",
                "Sign in with your browser before starting an analysis.",
            )
            return

        # Prepare expanded view — full prompt; the label elides for display
        # and keeps the untruncated text as its hover tooltip.
        self._starting_analysis = True
        self.tb_prompt_summary.setText("'" + prompt + "'")
        # Clear previous chat thread (keep only the trailing stretch)
        while self._thread_lay.count() > 1:
            item = self._thread_lay.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()
        self.graph_view.reset()
        self.title_bar.set_dot_color("analyzing")
        self.title_bar.set_title("Decompile.re — running")

        self._animate_to_expanded()

        # Detach the previous session's worker from the UI (it keeps polling
        # in the background so the user can come back to it later).
        if self._active_entry is not None:
            self._disconnect_worker(self._active_entry.worker)

        model_tier = g_settings.get("model_tier", "fast")
        current_view = dict(self._current_view)
        worker = AnalysisWorker(
            self._ea,
            prompt,
            model_tier=model_tier,
            current_view=current_view,
        )
        entry = _SessionEntry(prompt, worker)
        entry.toolbar_info = (
            self.tb_target_name.text(),
            self.tb_target_ea.text(),
            "'" + prompt + "'",
        )
        entry.messages.append(("You", prompt))
        self._active_entry = entry
        self._all_entries.append(entry)
        self._connect_worker(worker)

        # Seed the chat thread with the user's prompt + a new working indicator
        self._add_thread_widget(ChatMessageWidget("You", prompt))
        self.conv_drawer.add_session(prompt, entry)
        self._waiting_for_first_node = True
        self._add_working_widget("reversing")

        self._start_ts = QtCore.QElapsedTimer()
        self._start_ts.start()
        self._starting_analysis = False
        worker.start()

    def _stop_analysis(self):
        if self._active_entry:
            self._active_entry.worker.cancel()
        self.title_bar.set_dot_color("failed")

    def _on_esc(self):
        _w = self._active_entry.worker if self._active_entry else None
        if self._expanded and _w and _w.isRunning():
            self._stop_analysis()
        else:
            self.close()

    # ─── Expand animation ─────────────────────────────────────────────────
    def _animate_to_expanded(self, on_ready=None):
        if self._expanded:
            if on_ready:
                on_ready()
            return
        self._expanded = True
        # Raise the expanded minimum so the layout panels have room to breathe.
        # log_panel is 400px fixed; graph needs at least ~280px beside it.
        self.setMinimumSize(680, 420)

        self.toolbar.show()
        self.expanded_body.show()
        self.compact_body.hide()
        self.conv_drawer.raise_()   # keep drawer above the graph view
        self._grip.setEnabled(False)

        for w in (self.toolbar, self.expanded_body):
            eff = QtWidgets.QGraphicsOpacityEffect(w)
            eff.setOpacity(0.0)
            w.setGraphicsEffect(eff)

        start_rect = self.geometry()
        screen = self.screen()
        available = (
            screen.availableGeometry()
            if screen is not None
            else QtWidgets.QApplication.primaryScreen().availableGeometry()
        )
        cx = start_rect.center().x()
        cy = start_rect.center().y()
        end_w = min(EXPANDED_SIZE.width(), max(680, available.width() - 40))
        end_h = min(EXPANDED_SIZE.height(), max(420, available.height() - 40))
        end_rect = QtCore.QRect(0, 0, end_w, end_h)
        end_rect.moveCenter(QPoint(cx, cy))
        end_rect.moveLeft(max(
            available.left() + 20,
            min(end_rect.left(), available.right() - end_rect.width() - 19),
        ))
        end_rect.moveTop(max(
            available.top() + 20,
            min(end_rect.top(), available.bottom() - end_rect.height() - 19),
        ))

        group = QtCore.QParallelAnimationGroup(self)
        size_anim = QPropertyAnimation(self, b"geometry")
        size_anim.setDuration(ANIM_DURATION)
        size_anim.setStartValue(start_rect)
        size_anim.setEndValue(end_rect)
        size_anim.setEasingCurve(QEasingCurve.OutCubic)
        group.addAnimation(size_anim)

        panels = (self.toolbar, self.expanded_body)
        for i, w in enumerate(panels):
            eff = w.graphicsEffect()
            sequence = QtCore.QSequentialAnimationGroup()
            if i:
                sequence.addPause(40)
            anim = QPropertyAnimation(eff, b"opacity")
            anim.setDuration(MOTION_NORMAL_MS)
            anim.setStartValue(0.0)
            anim.setEndValue(1.0)
            anim.setEasingCurve(QEasingCurve.OutCubic)
            sequence.addAnimation(anim)
            group.addAnimation(sequence)

        def _on_expand_done() -> None:
            for panel in panels:
                panel.setGraphicsEffect(None)
            self._grip.setEnabled(True)
            if on_ready:
                on_ready()
            group.deleteLater()
            self._expand_group = None

        group.finished.connect(_on_expand_done)
        self._expand_group = group
        group.start()

    # ─── Log & progress ───────────────────────────────────────────────────
    def _append_log(self, level: str, msg: str) -> None:
        ts = datetime.datetime.now().astimezone().strftime("%H:%M:%S")
        normalised = msg.replace("\r\n", "\n").replace("\r", "\n")
        stripped   = normalised.strip()
        if not stripped or not self._current_working or not self._current_log_pane:
            return
        self._route_to_working(ts, level, stripped)

    def _route_to_working(self, ts: str, level: str, msg: str) -> None:
        """Route a curated log line to the active WorkingLogPane."""
        w  = self._current_working
        lp = self._current_log_pane
        if not w or not lp:
            return

        level = level if level in {
            "thinking", "result", "info", "success", "warn", "error"
        } else "info"

        mode = getattr(w, "_mode", "")
        if (
            (
                mode == "reversing"
                or (
                    mode in {"preparing_answer", "answering"}
                    and lp.has_reversal_activity
                )
            )
            and level not in {"warn", "error"}
        ):
            return

        if mode == "thinking":
            _clean = re.sub(r'^[^\w\s→]+\s*', '', msg).strip()
            if _clean:
                w.set_status(_clean)
            lp.append_log(level, f"{ts}  {msg}")
            return

        lp.append_log(level, f"{ts}  {msg}")

    def _on_reversal_activity(self, activity) -> None:
        if (
            not isinstance(activity, dict)
            or not self._current_working
            or not self._current_log_pane
            or self._current_working._mode
            not in {"reversing", "preparing_answer", "answering"}
        ):
            return
        self._current_log_pane.queue_reversal_activity(activity)

    def _flush_reversal_activity(self) -> None:
        pane = self._current_log_pane
        if pane is not None:
            pane.flush_pending_reversal_activities(drain=True)


    def _on_answer_preparing(self) -> None:
        """Move from binary reversal to final-answer preparation."""
        if self._current_working and self._current_working._mode == "preparing_answer":
            return
        self._final_answer_log_pane = None
        self._flush_reversal_activity()
        if (
            self._current_working
            and self._current_working._mode == "reversing"
            and (
                self._current_log_pane is None
                or not self._current_log_pane.has_activity
            )
        ):
            self._remove_current_working_stage()
        else:
            if self._current_working and self._start_ts:
                self._current_working.mark_done(self._start_ts.elapsed())
            if self._current_log_pane:
                self._current_log_pane.set_expanded(False)
            self._current_working = None
            self._current_log_pane = None
        self._add_working_widget("preparing_answer")
        self._start_ts = QtCore.QElapsedTimer()
        self._start_ts.start()

    def _on_agent_thinking_start(self) -> None:
        """Compatibility handler for older servers using the agent-start event."""
        self._on_answer_preparing()

    def _on_agent_turn_start(self, turn: int) -> None:
        if self._current_working:
            self._current_working.set_status("Reviewing evidence…")
        if self._current_log_pane:
            self._current_log_pane.start_agent_turn(turn)

    def _on_agent_turn_note(self, turn: int, note: str) -> None:
        if self._current_log_pane:
            self._current_log_pane.append_agent_note(turn, note)
            self._schedule_scroll_to_bottom()

    def _on_agent_reversal_note(self, turn: int, note: str) -> None:
        if self._current_log_pane:
            self._current_log_pane.move_agent_note_to_reversal(turn, note)
            self._schedule_scroll_to_bottom()

    def _on_agent_turn_chunk(self, turn: int, delta: str) -> None:
        if self._current_log_pane:
            self._current_log_pane.append_agent_chunk(turn, delta)
            self._schedule_scroll_to_bottom()

    def _on_agent_turn_end(self, turn: int, status: str) -> None:
        if self._current_log_pane:
            self._current_log_pane.end_agent_turn(turn, status)
        terminal_status = str(status or "").strip().lower()
        if terminal_status in {"draft", "final"}:
            self._final_answer_log_pane = self._current_log_pane
        if terminal_status == "final":
            if self._current_working and self._start_ts:
                self._current_working.mark_done(self._start_ts.elapsed())
            if self._current_log_pane:
                self._current_log_pane.set_expanded(False)
            self._schedule_scroll_to_bottom()

    def _on_answer_audit(self, activity) -> None:
        if not isinstance(activity, dict):
            return
        pane = self._final_answer_log_pane or self._current_log_pane
        if pane is None:
            return

        event_type = str(activity.get("type", "") or "").strip()
        answer = str(activity.get("report", "") or "")
        edit_count = max(0, int(activity.get("edit_count", 0) or 0))
        if event_type == "answer_audit_start":
            pane.start_answer_audit(answer)
            if self._current_working:
                self._current_working.set_status("Auditing answer...")
        elif event_type == "answer_audit_running":
            pane.update_answer_audit("running", answer, edit_count)
            if self._current_working:
                self._current_working.set_status("Auditing answer...")
        elif event_type == "answer_audit_skipped":
            pane.update_answer_audit("skipped", answer, edit_count)
        elif event_type == "answer_audit_complete":
            pane.update_answer_audit("complete", answer, edit_count)
        elif event_type == "answer_audit_failed":
            pane.update_answer_audit("failed", answer, edit_count)
        else:
            return
        self._schedule_scroll_to_bottom()

    @staticmethod
    def _join_agent_read_labels(labels: list[str]) -> str:
        if not labels:
            return ""
        if len(labels) == 1:
            return labels[0]
        if len(labels) == 2:
            return f"{labels[0]} and {labels[1]}"
        return f"{', '.join(labels[:-1])} and {labels[-1]}"

    def _on_agent_reading(self, activity) -> None:
        if not self._current_working or not self._current_log_pane:
            return
        if isinstance(activity, dict):
            turn = int(activity.get("turn", 0) or 0)
            reads = activity.get("reads", [])
            actions = activity.get("actions", [])
        else:
            turn = 0
            reads = activity
            actions = []

        if isinstance(actions, list) and actions:
            self._current_log_pane.append_agent_actions(turn, actions)
            descriptions = []
            for action in actions:
                if not isinstance(action, dict):
                    continue
                label = str(action.get("label", "") or "").strip()
                detail = str(action.get("detail", "") or "").strip()
                if label:
                    descriptions.append(f"{label}: {detail}" if detail else label)
            if descriptions:
                self._current_working.set_status(descriptions[-1])
                self._schedule_scroll_to_bottom()
            return

        labels = []
        seen = set()
        for read in reads if isinstance(reads, list) else []:
            if not isinstance(read, dict):
                continue
            kind = str(read.get("kind", "") or "")
            name = str(read.get("name", "") or "").strip()
            address = str(read.get("address", "") or "").strip()
            size = int(read.get("size", 0) or 0)
            if kind == "function" and name:
                label = name
            elif kind == "memory" and address:
                label = (
                    f"{size} bytes from {address}"
                    if size > 0 else f"memory from {address}"
                )
            elif kind == "value" and name:
                label = f"value from {name}"
            else:
                continue
            key = (kind, label)
            if key in seen:
                continue
            seen.add(key)
            labels.append(label)
            self._current_log_pane.append_agent_read(kind, label, turn)
        joined = self._join_agent_read_labels(labels)
        if joined:
            self._current_working.set_status(f"Reading {joined}")
            self._schedule_scroll_to_bottom()

    def _on_tree_node_added(
        self, parent_ea, ea, name: str, duplicate: bool
    ) -> None:
        self.graph_view.add_node(parent_ea, ea, name, duplicate)
        if not self._waiting_for_first_node:
            return
        self._waiting_for_first_node = False
        if self._current_working and self._current_working._mode == "reversing":
            self._current_working.set_status("Reversing...")

    def _on_tree_nodes_added(self, nodes) -> None:
        for parent_ea, ea, name, duplicate in nodes:
            self._on_tree_node_added(parent_ea, ea, name, duplicate)

    def _on_stream_start(self) -> None:
        """Server started streaming the response — transition WorkingWidget and
        create the streaming text widget."""
        self._flush_reversal_activity()
        if self._current_working and self._start_ts:
            self._current_working.mark_done(self._start_ts.elapsed())
        if self._current_log_pane:
            self._current_log_pane.set_expanded(False)
        self._current_working  = None
        self._current_log_pane = None

        self._streaming_widget = StreamingChatMessageWidget()
        self._add_thread_widget(self._streaming_widget)

    def _on_stream_chunk(self, delta: str) -> None:
        """Append a streamed token to the active streaming widget."""
        if self._streaming_widget:
            self._streaming_widget.append_text(delta)
            self._schedule_scroll_to_bottom()

    def _on_candidate_answer_replace(self, revision: int, text: str) -> None:
        """Replace the visible mutable answer draft with the server candidate."""
        del revision
        if not self._streaming_widget:
            self._flush_reversal_activity()
            if self._current_working and self._start_ts:
                self._current_working.mark_done(self._start_ts.elapsed())
            self._current_working = None
            self._current_log_pane = None
            self._streaming_widget = StreamingChatMessageWidget()
            self._add_thread_widget(self._streaming_widget)
        self._streaming_widget.replace_text(text)
        self._schedule_scroll_to_bottom()

    def _on_answer_final(self, revision: int) -> None:
        """Server marked the current mutable answer draft as final."""
        del revision
        if self._streaming_widget:
            self._streaming_widget.finalize()

    def _on_done(self, report: str):
        if self._shutting_down:
            return
        self._flush_reversal_activity()
        self.title_bar.set_dot_color("done")
        self.title_bar.set_title("Decompile.re — done")
        self.btn_cancel.hide()

        clean_report = report.strip() or "Analysis complete — see IDA for applied changes."

        if self._streaming_widget:
            # Streaming already rendered the report. If the one-shot attempt
            # fell back after emitting partial text, replace that partial body
            # with the authoritative completed report before rendering it.
            if self._streaming_widget.get_text().strip() != clean_report:
                self._streaming_widget.replace_text(clean_report)
            self._streaming_widget.finalize()
            self._streaming_widget = None
        else:
            # No streaming (non-streaming backend or cancelled) — stamp timing,
            # clear working indicator, add a regular AI bubble.
            if self._current_working and self._start_ts:
                self._current_working.mark_done(self._start_ts.elapsed())
            self._current_working  = None
            self._current_log_pane = None
            self._add_thread_widget(ChatMessageWidget("AI", clean_report))

        self._final_answer_log_pane = None

        # Record for session restore
        if self._active_entry:
            self._active_entry.messages.append(("AI", clean_report))
            self._active_entry.is_done = True
            self._active_entry.session_status = "done"

        self._show_chat_panel()
        self._refresh_usage()

    def _on_error(self, err: str):
        if self._shutting_down:
            return
        self._final_answer_log_pane = None
        self._flush_reversal_activity()
        self.title_bar.set_dot_color("failed")
        self.title_bar.set_title("Decompile.re — failed")
        self.btn_cancel.hide()
        if self._active_entry:
            self._active_entry.is_done = True
            self._active_entry.session_status = "error"

        tailored = self._billing_copy_for(err)
        body = tailored or err

        # Stamp working indicator and auto-expand to show the error
        if self._current_working and self._start_ts:
            self._current_working.mark_done(self._start_ts.elapsed())
        if self._current_log_pane:
            self._current_log_pane.append_log("error", body[:400])
            if not self._current_log_pane._expanded:
                self._current_log_pane.toggle_expand()
        self._current_working  = None
        self._current_log_pane = None

        self._refresh_usage()
        QtWidgets.QMessageBox.critical(
            self, "Analysis Error",
            body[:600] + ("…" if len(body) > 600 else "")
        )

    # ─── Chat thread helpers ──────────────────────────────────────────────────

    def _set_chat_controls_enabled(self, enabled: bool) -> None:
        self.chat_input.setEnabled(enabled)
        self.btn_send_chat.setEnabled(enabled)
        self.usage_limit.setEnabled(True)

    def _show_chat_panel(self) -> None:
        """Enable the chat input (always visible; just unlock it)."""
        self._set_chat_controls_enabled(True)
        self.chat_input.setFocus()

    def _add_working_widget(self, mode: str) -> None:
        """Create a WorkingWidget + companion WorkingLogPane and add both to the
        thread.  The header widget never changes size; only the sibling log pane
        animates, so the header stays completely stationary during expand/collapse."""
        w  = WorkingWidget(mode=mode)
        lp = WorkingLogPane(header=w)   # also sets w._log_pane_ref = lp
        w.sig_toggle.connect(lp.toggle_expand)
        self._current_working  = w
        self._current_log_pane = lp
        idx = self._thread_lay.count() - 1   # stretch is always the last item
        self._thread_lay.insertWidget(idx,     w)
        self._thread_lay.insertWidget(idx + 1, lp)
        self._schedule_scroll_to_bottom()

    def _remove_current_working_stage(self) -> None:
        working = self._current_working
        pane = self._current_log_pane
        self._current_working = None
        self._current_log_pane = None

        if working is not None:
            working._log_pane_ref = None
        for widget in (working, pane):
            if widget is None:
                continue
            self._thread_lay.removeWidget(widget)
            widget.setParent(None)
            widget.deleteLater()

    def _add_thread_widget(self, widget: QtWidgets.QWidget) -> None:
        """Insert a widget before the bottom stretch in the chat thread."""
        idx = self._thread_lay.count() - 1   # stretch is always the last item
        self._thread_lay.insertWidget(idx, widget)
        self._schedule_scroll_to_bottom()

    def _on_chat_scroll_value_changed(self, value: int) -> None:
        if self._chat_scroll_programmatic:
            return
        sb = self._chat_scroll.verticalScrollBar()
        self._chat_follow_output = sb.maximum() - value <= 24

    def _on_chat_scroll_range_changed(
        self, _minimum: int, _maximum: int
    ) -> None:
        self._schedule_scroll_to_bottom()

    def _schedule_scroll_to_bottom(self, force: bool = False) -> None:
        if force:
            self._chat_follow_output = True
        if not self._chat_follow_output or self._chat_scroll_pending:
            return
        self._chat_scroll_pending = True
        QtCore.QTimer.singleShot(0, self._scroll_to_bottom)

    def _scroll_to_bottom(self) -> None:
        self._chat_scroll_pending = False
        if not self._chat_follow_output:
            return
        sb = self._chat_scroll.verticalScrollBar()
        self._chat_scroll_programmatic = True
        try:
            sb.setValue(sb.maximum())
        finally:
            self._chat_scroll_programmatic = False

    def _on_chat_response(self, message: str) -> None:
        """Receive an AI chat response. With streaming the text is already
        displayed via stream_chunk; we just record it and re-enable input."""
        if self._shutting_down:
            return
        if self._current_working and self._start_ts:
            # Fallback: no stream_start arrived — stamp and clear working widget
            self._current_working.mark_done(self._start_ts.elapsed())
        self._current_working  = None
        self._current_log_pane = None

        if self._streaming_widget:
            # Streaming already rendered the text — flush + render markdown
            self._streaming_widget.finalize()
            self._streaming_widget = None
        else:
            self._add_thread_widget(ChatMessageWidget("AI", message))

        # Record for session restore
        if self._active_entry and message:
            self._active_entry.messages.append(("AI", message))

        self._set_chat_controls_enabled(True)
        self._refresh_usage()

    def _send_chat_message(self) -> None:
        msg = self.chat_input.text().strip()
        if msg:
            self.chat_input.clear()
            self._do_send_chat(msg)

    def _do_send_chat(self, msg: str) -> None:
        if not msg or not self._active_entry:
            return
        entry = self._active_entry
        if entry in self._chat_send_jobs:
            return
        self._set_chat_controls_enabled(False)

        # Record before sending so the message is captured even on error
        entry.messages.append(("You", msg))

        # User bubble + new working indicator
        self._add_thread_widget(ChatMessageWidget("You", msg))
        self._add_working_widget("answering")

        # Reset task timer for "Worked for Xs" on this follow-up
        self._start_ts = QtCore.QElapsedTimer()
        self._start_ts.start()

        thread = QtCore.QThread(self)
        worker = _SendChatWorker(entry, msg, dict(self._current_view))
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_error.connect(self._chat_send_failed)
        worker.sig_finished.connect(thread.quit)
        worker.sig_finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda target=entry: self._chat_send_jobs.pop(target, None)
        )
        self._chat_send_jobs[entry] = (thread, worker)
        thread.start()

    def _chat_send_failed(self, entry: _SessionEntry, message: str) -> None:
        if self._shutting_down or entry is not self._active_entry:
            return
        if self._current_working:
            self._current_working.mark_done(0)
        if self._current_log_pane:
            self._current_log_pane.append_log("error", f"Send error: {message}")
            self._current_log_pane.toggle_expand()
        self._current_working = None
        self._current_log_pane = None
        self._set_chat_controls_enabled(True)

    def eventFilter(self, obj: QtCore.QObject, event: QtCore.QEvent) -> bool:  # type: ignore[override]
        """Send chat message on Enter; let Shift+Enter pass through."""
        if obj is self.chat_input and event.type() == QtCore.QEvent.KeyPress:
            key = event.key()
            if key in (QtCore.Qt.Key_Return, QtCore.Qt.Key_Enter):
                if not (event.modifiers() & QtCore.Qt.ShiftModifier):
                    self._send_chat_message()
                    return True  # consume event
        return super().eventFilter(obj, event)

    # ─── Worker signal plumbing ───────────────────────────────────────────────

    def _connect_worker(self, worker) -> None:
        worker.sig_log.connect(self._append_log)
        worker.sig_done.connect(self._on_done)
        worker.sig_error.connect(self._on_error)
        worker.sig_tree_node_added.connect(self._on_tree_node_added)
        worker.sig_tree_nodes_added.connect(self._on_tree_nodes_added)
        worker.sig_tree_node_updated.connect(self.graph_view.update_node)
        worker.sig_chat_response.connect(self._on_chat_response)
        worker.sig_stream_start.connect(self._on_stream_start)
        worker.sig_stream_chunk.connect(self._on_stream_chunk)
        worker.sig_candidate_answer_replace.connect(self._on_candidate_answer_replace)
        worker.sig_answer_final.connect(self._on_answer_final)
        worker.sig_answer_preparing.connect(self._on_answer_preparing)
        worker.sig_agent_thinking_start.connect(self._on_agent_thinking_start)
        worker.sig_agent_turn_start.connect(self._on_agent_turn_start)
        worker.sig_agent_turn_note.connect(self._on_agent_turn_note)
        worker.sig_agent_reversal_note.connect(self._on_agent_reversal_note)
        worker.sig_agent_turn_chunk.connect(self._on_agent_turn_chunk)
        worker.sig_agent_turn_end.connect(self._on_agent_turn_end)
        worker.sig_agent_reading.connect(self._on_agent_reading)
        worker.sig_answer_audit.connect(self._on_answer_audit)
        worker.sig_reversal_activity.connect(self._on_reversal_activity)

    def _disconnect_worker(self, worker) -> None:
        for sig, slot in [
            (worker.sig_log,              self._append_log),
            (worker.sig_done,             self._on_done),
            (worker.sig_error,            self._on_error),
            (worker.sig_tree_node_added,  self._on_tree_node_added),
            (worker.sig_tree_nodes_added, self._on_tree_nodes_added),
            (worker.sig_tree_node_updated, self.graph_view.update_node),
            (worker.sig_chat_response,    self._on_chat_response),
            (worker.sig_stream_start,     self._on_stream_start),
            (worker.sig_stream_chunk,     self._on_stream_chunk),
            (worker.sig_candidate_answer_replace, self._on_candidate_answer_replace),
            (worker.sig_answer_final,      self._on_answer_final),
            (worker.sig_answer_preparing,  self._on_answer_preparing),
            (worker.sig_agent_thinking_start, self._on_agent_thinking_start),
            (worker.sig_agent_turn_start, self._on_agent_turn_start),
            (worker.sig_agent_turn_note, self._on_agent_turn_note),
            (worker.sig_agent_reversal_note, self._on_agent_reversal_note),
            (worker.sig_agent_turn_chunk, self._on_agent_turn_chunk),
            (worker.sig_agent_turn_end, self._on_agent_turn_end),
            (worker.sig_agent_reading, self._on_agent_reading),
            (worker.sig_answer_audit, self._on_answer_audit),
            (worker.sig_reversal_activity, self._on_reversal_activity),
        ]:
            try:
                sig.disconnect(slot)
            except (RuntimeError, TypeError):
                pass  # already disconnected or C++ object deleted

    # ─── Session restore ──────────────────────────────────────────────────────

    def _restore_session(self, entry: _SessionEntry) -> None:
        """Switch the dialog to a previously recorded session."""
        if entry.network_only and not entry.history_loaded:
            self._load_network_session(entry)
            return
        if entry is self._active_entry and self._expanded:
            return  # already displaying this session

        # Detach current worker so live signals don't corrupt the restored view
        if self._active_entry is not None and entry is not self._active_entry:
            if not self._active_entry.network_only:
                self._disconnect_worker(self._active_entry.worker)

        self._active_entry = entry
        if not entry.network_only:
            self._connect_worker(entry.worker)
        self.conv_drawer.set_active_session(entry)

        # Update toolbar labels
        if entry.toolbar_info:
            name, ea_str, summary = entry.toolbar_info
            self.tb_target_name.setText(name)
            self.tb_target_ea.setText(ea_str)
            self.tb_prompt_summary.setText(summary)

        if not self._expanded:
            # Animate compact → expanded; populate thread once visible
            self._animate_to_expanded(
                on_ready=lambda: self._populate_thread_from_entry(entry)
            )
        else:
            self._populate_thread_from_entry(entry)

    def _load_network_session(self, entry: _SessionEntry) -> None:
        if entry in self._session_detail_jobs:
            return
        self._session_loading_overlay.set_active(True)
        thread = QtCore.QThread(self)
        worker = _LoadSessionDetailWorker(entry)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.sig_done.connect(self._network_session_loaded)
        worker.sig_error.connect(self._network_session_load_error)
        worker.sig_done.connect(thread.quit)
        worker.sig_error.connect(thread.quit)
        worker.sig_done.connect(worker.deleteLater)
        worker.sig_error.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda target=entry: self._session_detail_jobs.pop(target, None)
        )
        self._session_detail_jobs[entry] = (thread, worker)
        thread.start()

    def _network_session_loaded(self, entry: _SessionEntry, detail: dict) -> None:
        self._session_loading_overlay.set_active(False)
        if entry not in self._all_entries or not isinstance(detail, dict):
            return
        stored_name = str(detail.get("name", "") or "").strip()
        if stored_name:
            entry.display_name = stored_name
            self.conv_drawer.set_session_title(entry, stored_name)
        prompt = str(detail.get("user_prompt", "") or entry.prompt)
        report = str(detail.get("final_report", "") or "")
        messages = []
        if prompt:
            messages.append(("You", prompt))
        if report:
            messages.append(("AI", report))
        for turn in detail.get("chat_turns", []):
            if not isinstance(turn, dict):
                continue
            content = str(turn.get("content", "") or "")
            if content:
                role = "You" if turn.get("role") == "user" else "AI"
                messages.append((role, content))

        call_tree = detail.get("call_tree", {})
        entry.prompt = prompt
        entry.messages = messages
        entry.graph_nodes = call_tree if isinstance(call_tree, dict) else {}
        entry.session_status = str(detail.get("status", "done") or "done")
        entry.is_done = entry.session_status != "running"
        entry.history_loaded = True

        root_ea = str(detail.get("root_ea", "") or "")
        root_node = entry.graph_nodes.get(root_ea, {})
        root_name = (
            str(root_node.get("name", "") or root_ea)
            if isinstance(root_node, dict)
            else root_ea
        )
        entry.toolbar_info = (root_name, root_ea, "'" + prompt + "'")
        self._restore_session(entry)

    def _network_session_load_error(
        self, entry: _SessionEntry, message: str
    ) -> None:
        self._session_loading_overlay.set_active(False)
        if not self._shutting_down and entry in self._all_entries:
            QtWidgets.QMessageBox.critical(
                self, "Could not open session", message[:600]
            )

    def _populate_thread_from_entry(self, entry: _SessionEntry) -> None:
        """Clear the chat thread and replay the recorded messages for entry."""
        self._current_working = None
        self._streaming_widget = None

        # Clear existing widgets (keep the trailing stretch item)
        while self._thread_lay.count() > 1:
            item = self._thread_lay.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

        self.graph_view.reset()

        if entry.graph_nodes:
            self._populate_graph_from_entry(entry)

        for role, text in entry.messages:
            w = ChatMessageWidget(role, text)
            self._thread_lay.insertWidget(self._thread_lay.count() - 1, w)

        self._schedule_scroll_to_bottom(force=True)

        if entry.is_done:
            failed = entry.session_status in ("error", "failed", "cancelled")
            self.title_bar.set_dot_color("failed" if failed else "done")
            self.title_bar.set_title(
                "Decompile.re — " + (entry.session_status or "done")
            )
            self.btn_cancel.hide()
            if entry.network_only:
                self._set_chat_controls_enabled(False)
            else:
                self._show_chat_panel()
        else:
            # Analysis still in progress — keep input locked
            self._set_chat_controls_enabled(False)

    def _populate_graph_from_entry(self, entry: _SessionEntry) -> None:
        pending = {
            str(ea): node for ea, node in entry.graph_nodes.items()
            if str(ea) not in ("", "0", "0x0") and isinstance(node, dict)
        }
        added = set()
        while pending:
            progressed = False
            for ea, node in list(pending.items()):
                parent_ea = str(node.get("parent_ea", "0x0") or "0x0")
                if parent_ea not in ("0", "0x0") and parent_ea not in added:
                    continue
                try:
                    ea_value = int(ea, 0)
                    parent_value = int(parent_ea, 0)
                except (TypeError, ValueError):
                    del pending[ea]
                    progressed = True
                    continue
                name = str(node.get("name", "") or ea)
                self.graph_view.add_node(parent_value, ea_value, name, False)
                self.graph_view.update_node(
                    ea_value,
                    name,
                    "done",
                    str(node.get("notes", "") or ""),
                    str(node.get("summary", "") or ""),
                )
                added.add(ea)
                del pending[ea]
                progressed = True
            if not progressed:
                break

    def _request_rename_session(self, entry: _SessionEntry) -> None:
        if (
            entry is None
            or entry in self._session_rename_jobs
            or entry in self._session_delete_jobs
        ):
            return

        name, accepted = QtWidgets.QInputDialog.getText(
            self,
            "Rename session",
            "Session name:",
            QtWidgets.QLineEdit.Normal,
            entry.display_name,
        )
        if not accepted:
            return
        name = name.strip()
        if not name:
            QtWidgets.QMessageBox.warning(
                self,
                "Rename session",
                "Session name must not be empty.",
            )
            return
        if len(name.encode("utf-8")) > 256:
            QtWidgets.QMessageBox.warning(
                self,
                "Rename session",
                "Session name must not exceed 256 bytes.",
            )
            return
        if name == entry.display_name:
            return

        previous_name = entry.display_name
        entry.display_name = name
        self.conv_drawer.set_session_title(entry, name)

        thread = QtCore.QThread(self)
        rename_worker = _RenameHistoryWorker(entry, name)
        rename_worker.moveToThread(thread)
        thread.started.connect(rename_worker.run)
        rename_worker.sig_done.connect(thread.quit)
        rename_worker.sig_error.connect(thread.quit)
        rename_worker.sig_done.connect(self._session_rename_succeeded)
        rename_worker.sig_error.connect(
            lambda target, message, old=previous_name, attempted=name:
                self._session_rename_failed(target, old, attempted, message)
        )
        rename_worker.sig_done.connect(rename_worker.deleteLater)
        rename_worker.sig_error.connect(rename_worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda target=entry: self._session_rename_jobs.pop(target, None)
        )
        self._session_rename_jobs[entry] = (thread, rename_worker)
        thread.start()

    def _session_rename_succeeded(
        self, entry: _SessionEntry, persisted_name: str
    ) -> None:
        if entry not in self._all_entries:
            return
        persisted_name = persisted_name.strip()
        if persisted_name:
            entry.display_name = persisted_name
            self.conv_drawer.set_session_title(entry, persisted_name)

    def _session_rename_failed(
        self,
        entry: _SessionEntry,
        previous_name: str,
        attempted_name: str,
        message: str,
    ) -> None:
        if entry in self._all_entries and entry.display_name == attempted_name:
            entry.display_name = previous_name
            self.conv_drawer.set_session_title(entry, previous_name)
        if self._shutting_down:
            return
        QtWidgets.QMessageBox.critical(
            self,
            "Could not rename session",
            message or "The session could not be renamed.",
        )

    def _request_delete_session(self, entry: _SessionEntry) -> None:
        if (
            entry is self._active_entry
            or entry in self._session_delete_jobs
            or entry in self._session_rename_jobs
        ):
            return
        answer = QtWidgets.QMessageBox.question(
            self,
            "Delete session",
            "Permanently delete this completed session and its stored history?",
            QtWidgets.QMessageBox.StandardButton.Yes
            | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        if answer != QtWidgets.QMessageBox.StandardButton.Yes:
            return

        history_index = self._all_entries.index(entry)
        drawer_row = self.conv_drawer.remove_session(entry)
        self._all_entries.pop(history_index)

        thread = QtCore.QThread(self)
        delete_worker = _DeleteHistoryWorker(entry.worker)
        delete_worker.moveToThread(thread)
        thread.started.connect(delete_worker.run)
        delete_worker.sig_done.connect(thread.quit)
        delete_worker.sig_error.connect(thread.quit)
        delete_worker.sig_done.connect(
            lambda target=entry: self._session_delete_succeeded(target)
        )
        delete_worker.sig_error.connect(
            lambda message, target=entry, index=history_index, row=drawer_row:
                self._session_delete_failed(target, index, row, message)
        )
        delete_worker.sig_done.connect(delete_worker.deleteLater)
        delete_worker.sig_error.connect(delete_worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(
            lambda target=entry: self._session_delete_jobs.pop(target, None)
        )
        self._session_delete_jobs[entry] = (thread, delete_worker)
        thread.start()

    def _session_delete_succeeded(self, entry: _SessionEntry) -> None:
        pass

    def _session_delete_failed(
        self,
        entry: _SessionEntry,
        history_index: int,
        drawer_row: int,
        message: str,
    ) -> None:
        self._all_entries.insert(history_index, entry)
        self.conv_drawer.insert_session(drawer_row, entry.display_name, entry)
        self.conv_drawer.set_active_session(self._active_entry)
        if self._shutting_down:
            return
        QtWidgets.QMessageBox.critical(
            self,
            "Could not delete session",
            message or "The session could not be deleted.",
        )

    @staticmethod
    def _billing_copy_for(err: str) -> str:
        for reason, copy in _BILLING_REASON_COPY.items():
            if f"reason={reason}" in err:
                return copy
        return ""

    def resizeEvent(self, e):  # type: ignore[override]
        super().resizeEvent(e)   # RoundedDialogMixin re-applies the rounded mask
        self._sync_root_border_overlay()
        # Tuck the visible grip into the physical corner so it does not overlap
        # the bottom-row usage indicator.
        g = self._grip
        g.move(self.width() - g.width() - 5, self.height() - g.height() - 5)

    def closeEvent(self, ev):
        if self._final_close:
            super().closeEvent(ev)
            return

        ev.ignore()
        if self._shutting_down:
            return

        self._shutting_down = True
        self._usage_refresh_timer.stop()
        self.hide()

        if self._browser_auth_worker is not None:
            self._browser_auth_worker.cancel()
        if self._update_check_worker is not None:
            self._update_check_worker.cancel()
        if self._update_install_worker is not None:
            self._update_install_worker.cancel()
        for entry in self._all_entries:
            worker = entry.worker
            if worker and worker.isRunning():
                worker.cancel()

        self._shutdown_timer.start()
        self._finish_shutdown_if_ready()

    def is_shutting_down(self) -> bool:
        return self._shutting_down

    def request_reopen_after_shutdown(self) -> None:
        self._reopen_requested = True

    def take_reopen_request(self) -> bool:
        reopen = self._reopen_requested
        self._reopen_requested = False
        return reopen

    def _background_threads(self) -> list:
        threads = [
            self._browser_auth_thread,
            self._auth_verify_thread,
            self._session_names_thread,
            self._usage_thread,
            self._update_check_thread,
            self._update_install_thread,
        ]
        threads.extend(
            entry.worker
            for entry in self._all_entries
            if entry.worker is not None
        )
        for jobs in (
            self._chat_send_jobs,
            self._session_detail_jobs,
            self._session_rename_jobs,
            self._session_delete_jobs,
        ):
            threads.extend(thread for thread, _worker in jobs.values())

        unique = []
        seen = set()
        for thread in threads:
            if thread is None or id(thread) in seen:
                continue
            seen.add(id(thread))
            unique.append(thread)
        return unique

    def _finish_shutdown_if_ready(self) -> None:
        if not self._shutting_down:
            return
        if any(thread.isRunning() for thread in self._background_threads()):
            return
        self._shutdown_timer.stop()
        self._final_close = True
        self.close()
        self.sig_shutdown_complete.emit()
