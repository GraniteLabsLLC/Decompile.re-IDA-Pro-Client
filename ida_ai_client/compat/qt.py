"""Expose one Qt interface across IDA's PySide6 and PyQt5 runtimes."""

QT_AVAILABLE = False
QT_BINDING = ""

try:
    from PySide6 import QtCore, QtGui, QtWidgets
    try:
        from PySide6 import QtNetwork
    except ImportError:
        QtNetwork = None

    Signal = QtCore.Signal
    Property = QtCore.Property
    QT_BINDING = "PySide6"
    QT_AVAILABLE = True
except ImportError:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
        try:
            from PyQt5 import QtNetwork
        except ImportError:
            QtNetwork = None

        Signal = QtCore.pyqtSignal
        Property = QtCore.pyqtProperty
        QT_BINDING = "PyQt5"
        QT_AVAILABLE = True
    except ImportError:
        QtCore = None
        QtGui = None
        QtNetwork = None
        QtWidgets = None
        Signal = None
        Property = None


def _enum_scope(owner, name):
    if not hasattr(owner, name):
        try:
            setattr(owner, name, owner)
        except (AttributeError, TypeError):
            pass


if QT_AVAILABLE:
    Qt = QtCore.Qt
    QThread = QtCore.QThread
    QPoint = QtCore.QPoint
    QPointF = QtCore.QPointF
    QRectF = QtCore.QRectF
    QSize = QtCore.QSize
    QPropertyAnimation = QtCore.QPropertyAnimation
    QEasingCurve = QtCore.QEasingCurve
    QShortcut = QtGui.QShortcut if QT_BINDING == "PySide6" else QtWidgets.QShortcut

    if QT_BINDING == "PyQt5":
        for enum_name in (
            "AspectRatioMode",
            "ImageConversionFlag",
            "PenStyle",
            "TransformationMode",
            "TextFormat",
        ):
            _enum_scope(QtCore.Qt, enum_name)

        for owner, enum_names in (
            (QtCore.QAbstractAnimation, ("DeletionPolicy",)),
            (QtGui.QFont, ("SpacingType", "StyleHint", "Weight")),
            (QtGui.QImage, ("Format",)),
            (QtGui.QPainter, ("RenderHint",)),
            (QtGui.QTextOption, ("WrapMode",)),
            (QtWidgets.QGraphicsItem, ("GraphicsItemFlag",)),
            (
                QtWidgets.QGraphicsView,
                ("DragMode", "ViewportAnchor", "ViewportUpdateMode"),
            ),
            (QtWidgets.QMessageBox, ("StandardButton",)),
            (QtWidgets.QTextEdit, ("LineWrapMode",)),
        ):
            for enum_name in enum_names:
                _enum_scope(owner, enum_name)

        if not hasattr(QtWidgets.QDialog, "exec"):
            QtWidgets.QDialog.exec = QtWidgets.QDialog.exec_
else:
    Qt = None
    QThread = None
    QPoint = None
    QPointF = None
    QRectF = None
    QSize = None
    QPropertyAnimation = None
    QEasingCurve = None
    QShortcut = None
