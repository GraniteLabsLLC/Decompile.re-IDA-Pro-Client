"""Requests-compatible bounded transport backed by IDA's Qt network stack."""

from __future__ import annotations

import threading

from ..compat.qt import QtCore, QtNetwork


_MAX_RESPONSE_BYTES = 64 * 1024 * 1024


class _CaseInsensitiveHeaders(dict):
    def get(self, key, default=None):
        return super().get(str(key).lower(), default)


class QtNetworkResponse:
    def __init__(self, status_code: int, headers: dict[str, str], data: bytes):
        self.status_code = status_code
        self.headers = headers
        self._data = data

    def iter_content(self, chunk_size: int = 64 * 1024):
        for offset in range(0, len(self._data), chunk_size):
            yield self._data[offset:offset + chunk_size]

    def close(self) -> None:
        return


class QtNetworkSession:
    """Provide the small requests.Session surface used by GitHubReleaseClient."""

    def __init__(self, cancel_event: threading.Event | None = None):
        if QtNetwork is None:
            raise RuntimeError("Qt networking is unavailable")
        self._cancel_event = cancel_event
        self._manager = QtNetwork.QNetworkAccessManager()

    @staticmethod
    def _network_enum(owner, scope: str, name: str):
        nested = getattr(owner, scope, owner)
        value = getattr(nested, name, None)
        if value is not None:
            return value
        return getattr(owner, name)

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        stream: bool = True,
        allow_redirects: bool = False,
        timeout=None,
    ) -> QtNetworkResponse:
        del stream, allow_redirects, timeout
        request = QtNetwork.QNetworkRequest(QtCore.QUrl(url))
        for name, value in (headers or {}).items():
            request.setRawHeader(name.encode("ascii"), value.encode("utf-8"))

        try:
            redirect_attribute = self._network_enum(
                QtNetwork.QNetworkRequest,
                "Attribute",
                "RedirectPolicyAttribute",
            )
            manual_redirect = self._network_enum(
                QtNetwork.QNetworkRequest,
                "RedirectPolicy",
                "ManualRedirectPolicy",
            )
            request.setAttribute(redirect_attribute, manual_redirect)
        except AttributeError:
            pass
        if hasattr(request, "setTransferTimeout"):
            request.setTransferTimeout(20_000)

        reply = self._manager.get(request)
        loop = QtCore.QEventLoop()
        data = bytearray()
        exceeded = [False]

        def read_available() -> None:
            chunk = bytes(reply.readAll())
            if not chunk:
                return
            data.extend(chunk)
            if len(data) > _MAX_RESPONSE_BYTES:
                exceeded[0] = True
                reply.abort()

        def check_progress(_received: int, total: int) -> None:
            if total > _MAX_RESPONSE_BYTES:
                exceeded[0] = True
                reply.abort()

        cancel_timer = QtCore.QTimer()
        cancel_timer.setInterval(100)

        def check_cancelled() -> None:
            if self._cancel_event is not None and self._cancel_event.is_set():
                reply.abort()

        cancel_timer.timeout.connect(check_cancelled)
        cancel_timer.start()
        reply.readyRead.connect(read_available)
        reply.downloadProgress.connect(check_progress)
        reply.finished.connect(loop.quit)
        execute = getattr(loop, "exec", None) or getattr(loop, "exec_")
        execute()
        cancel_timer.stop()
        read_available()

        try:
            if exceeded[0]:
                return QtNetworkResponse(0, {}, b"")
            status_attribute = self._network_enum(
                QtNetwork.QNetworkRequest,
                "Attribute",
                "HttpStatusCodeAttribute",
            )
            status = reply.attribute(status_attribute)
            try:
                status_code = int(status or 0)
            except (TypeError, ValueError):
                status_code = 0
            response_headers = _CaseInsensitiveHeaders(
                {
                    bytes(name).decode("latin-1").lower():
                        bytes(value).decode("latin-1")
                    for name, value in reply.rawHeaderPairs()
                }
            )
            return QtNetworkResponse(status_code, response_headers, bytes(data))
        finally:
            reply.deleteLater()
