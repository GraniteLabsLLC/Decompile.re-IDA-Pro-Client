"""Host-independent scrollbars for IDA's PyQt5 and PySide6 runtimes."""

from __future__ import annotations

from ..compat.qt import QtCore, QtGui, QtWidgets, Qt
from .styles import COLORS


_QT_SCROLLBARS_AVAILABLE = all(
    hasattr(QtWidgets, name)
    for name in ("QProxyStyle", "QScrollBar", "QStyle", "QStyleOptionSlider")
)
_ProxyStyleBase = getattr(QtWidgets, "QProxyStyle", object)
_ScrollBarBase = getattr(QtWidgets, "QScrollBar", object)


def _style_enum(group: str, name: str):
    direct = getattr(QtWidgets.QStyle, name, None)
    if direct is not None:
        return direct
    return getattr(getattr(QtWidgets.QStyle, group), name)


if _QT_SCROLLBARS_AVAILABLE:
    _CC_SCROLLBAR = _style_enum("ComplexControl", "CC_ScrollBar")
    _SC_NONE = _style_enum("SubControl", "SC_None")
    _SC_GROOVE = _style_enum("SubControl", "SC_ScrollBarGroove")
    _SC_SLIDER = _style_enum("SubControl", "SC_ScrollBarSlider")
    _SC_SUB_PAGE = _style_enum("SubControl", "SC_ScrollBarSubPage")
    _SC_ADD_PAGE = _style_enum("SubControl", "SC_ScrollBarAddPage")
    _PM_EXTENT = _style_enum("PixelMetric", "PM_ScrollBarExtent")
    _PM_SLIDER_MIN = _style_enum("PixelMetric", "PM_ScrollBarSliderMin")
else:  # Lightweight non-Qt test shims never instantiate these classes.
    _CC_SCROLLBAR, _SC_NONE, _SC_GROOVE, _SC_SLIDER = range(4)
    _SC_SUB_PAGE, _SC_ADD_PAGE, _PM_EXTENT, _PM_SLIDER_MIN = range(4, 8)


class _ScrollbarGeometryStyle(_ProxyStyleBase):
    """Give Qt's built-in interaction logic the same geometry we paint."""

    EXTENT = 10
    END_INSET = 4
    MIN_THUMB_LENGTH = 36

    def pixelMetric(self, metric, option=None, widget=None):  # type: ignore[override]
        if metric == _PM_EXTENT:
            return self.EXTENT
        if metric == _PM_SLIDER_MIN:
            return self.MIN_THUMB_LENGTH
        return super().pixelMetric(metric, option, widget)

    @classmethod
    def _groove(cls, option) -> QtCore.QRect:
        rect = QtCore.QRect(option.rect)
        if option.orientation == Qt.Vertical:
            return rect.adjusted(0, cls.END_INSET, 0, -cls.END_INSET)
        return rect.adjusted(cls.END_INSET, 0, -cls.END_INSET, 0)

    @classmethod
    def _slider(cls, option) -> QtCore.QRect:
        groove = cls._groove(option)
        length = groove.height() if option.orientation == Qt.Vertical else groove.width()
        if length <= 0:
            return QtCore.QRect()

        value_range = max(0, int(option.maximum) - int(option.minimum))
        page_step = max(0, int(option.pageStep))
        total = value_range + page_step
        thumb_length = length if total <= 0 else round(length * page_step / total)
        thumb_length = min(length, max(cls.MIN_THUMB_LENGTH, thumb_length))
        travel = max(0, length - thumb_length)
        position = QtWidgets.QStyle.sliderPositionFromValue(
            int(option.minimum),
            int(option.maximum),
            int(option.sliderPosition),
            travel,
            bool(option.upsideDown),
        )

        if option.orientation == Qt.Vertical:
            return QtCore.QRect(
                groove.left(),
                groove.top() + position,
                groove.width(),
                thumb_length,
            )
        return QtCore.QRect(
            groove.left() + position,
            groove.top(),
            thumb_length,
            groove.height(),
        )

    @classmethod
    def _page_rects(cls, option) -> tuple[QtCore.QRect, QtCore.QRect]:
        groove = cls._groove(option)
        slider = cls._slider(option)
        if option.orientation == Qt.Vertical:
            before = QtCore.QRect(
                groove.left(), groove.top(), groove.width(),
                max(0, slider.top() - groove.top()),
            )
            after_top = slider.bottom() + 1
            after = QtCore.QRect(
                groove.left(), after_top, groove.width(),
                max(0, groove.bottom() - after_top + 1),
            )
        else:
            before = QtCore.QRect(
                groove.left(), groove.top(),
                max(0, slider.left() - groove.left()), groove.height(),
            )
            after_left = slider.right() + 1
            after = QtCore.QRect(
                after_left, groove.top(),
                max(0, groove.right() - after_left + 1), groove.height(),
            )
        if option.upsideDown:
            return after, before
        return before, after

    def subControlRect(self, control, option, sub_control, widget=None):  # type: ignore[override]
        if control != _CC_SCROLLBAR:
            return super().subControlRect(control, option, sub_control, widget)
        if sub_control == _SC_GROOVE:
            return self._groove(option)
        if sub_control == _SC_SLIDER:
            return self._slider(option)
        sub_page, add_page = self._page_rects(option)
        if sub_control == _SC_SUB_PAGE:
            return sub_page
        if sub_control == _SC_ADD_PAGE:
            return add_page
        return QtCore.QRect()

    def hitTestComplexControl(self, control, option, position, widget=None):  # type: ignore[override]
        if control != _CC_SCROLLBAR:
            return super().hitTestComplexControl(control, option, position, widget)
        for sub_control in (_SC_SLIDER, _SC_SUB_PAGE, _SC_ADD_PAGE):
            if self.subControlRect(control, option, sub_control, widget).contains(position):
                return sub_control
        return _SC_NONE

    def drawComplexControl(self, control, option, painter, widget=None):  # type: ignore[override]
        # _PolishedScrollBar paints the complete control itself.
        if control != _CC_SCROLLBAR:
            super().drawComplexControl(control, option, painter, widget)


class _PolishedScrollBar(_ScrollBarBase):
    _THUMB_INSET = 2
    _RADIUS = 3.0

    def __init__(self, orientation, background_role: str, parent=None):
        super().__init__(orientation, parent)
        self._background_role = background_role
        self.setMouseTracking(True)
        self.setAutoFillBackground(False)
        self.setAttribute(Qt.WA_OpaquePaintEvent, True)
        self._geometry_style = _ScrollbarGeometryStyle()
        self._geometry_style.setParent(self)
        self.setStyle(self._geometry_style)

    def sizeHint(self):  # type: ignore[override]
        hint = super().sizeHint()
        if self.orientation() == Qt.Vertical:
            hint.setWidth(_ScrollbarGeometryStyle.EXTENT)
        else:
            hint.setHeight(_ScrollbarGeometryStyle.EXTENT)
        return hint

    def minimumSizeHint(self):  # type: ignore[override]
        return self.sizeHint()

    def enterEvent(self, event) -> None:  # type: ignore[override]
        super().enterEvent(event)
        self.update()

    def leaveEvent(self, event) -> None:  # type: ignore[override]
        super().leaveEvent(event)
        self.update()

    def mousePressEvent(self, event) -> None:  # type: ignore[override]
        super().mousePressEvent(event)
        self.update()

    def mouseReleaseEvent(self, event) -> None:  # type: ignore[override]
        super().mouseReleaseEvent(event)
        self.update()

    @staticmethod
    def _color(role: str, alpha: float = 1.0) -> QtGui.QColor:
        color = QtGui.QColor(COLORS[role])
        color.setAlphaF(alpha)
        return color

    def paintEvent(self, event) -> None:  # type: ignore[override]
        option = QtWidgets.QStyleOptionSlider()
        self.initStyleOption(option)
        thumb = self._geometry_style.subControlRect(
            _CC_SCROLLBAR, option, _SC_SLIDER, self
        )

        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing, True)
        painter.fillRect(self.rect(), self._color(self._background_role))

        if thumb.isEmpty():
            return
        if self.orientation() == Qt.Vertical:
            thumb.adjust(self._THUMB_INSET, 0, -self._THUMB_INSET, 0)
        else:
            thumb.adjust(0, self._THUMB_INSET, 0, -self._THUMB_INSET)

        if self.isSliderDown():
            color = self._color("accent", 0.92)
        elif self.underMouse():
            color = self._color("text_dim", 0.90)
        else:
            color = self._color("text_mute", 0.72)
        painter.setPen(Qt.NoPen)
        painter.setBrush(color)
        painter.drawRoundedRect(QtCore.QRectF(thumb), self._RADIUS, self._RADIUS)


def install_scrollbars(scroll_area, background_role: str) -> None:
    """Install deterministic vertical and horizontal bars on a scroll area."""
    if not _QT_SCROLLBARS_AVAILABLE:
        return
    scroll_area.setVerticalScrollBar(
        _PolishedScrollBar(Qt.Vertical, background_role, scroll_area)
    )
    scroll_area.setHorizontalScrollBar(
        _PolishedScrollBar(Qt.Horizontal, background_role, scroll_area)
    )
