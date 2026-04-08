"""WebSocket transport。"""

from __future__ import annotations

from typing import Any

from ..core.errors import MissingDependencyError, TransportCapabilityError, TransportConfigError
from .base import BaseTransport


class WebSocketTransport(BaseTransport):
    """基于同步 WebSocket 客户端的 transport。"""

    def __init__(self, target: object, spec: object) -> None:
        super().__init__(target, spec)
        self._socket: Any = None

    def _open(self) -> None:
        if self.target.ws_url is None:
            raise TransportConfigError("WebSocketTransport 需要 target.ws_url。")

        connection_factory = self.spec.metadata.get("connection_factory")
        if connection_factory is not None:
            self._socket = self._build_from_factory(connection_factory)
            return

        try:
            from websockets.sync.client import connect
        except Exception as exc:  # pragma: no cover
            raise MissingDependencyError(
                "WebSocketTransport 需要 websockets，请安装：pip install websockets"
            ) from exc

        self._socket = connect(
            self.target.ws_url,
            additional_headers=dict(self.spec.headers) or None,
            open_timeout=self.spec.connect_timeout or self.spec.timeout,
        )

    def _build_from_factory(self, connection_factory: object) -> Any:
        if not callable(connection_factory):
            raise TransportConfigError("connection_factory 必须是可调用对象。")
        return connection_factory(self.target, self.spec)

    def _close(self) -> None:
        if self._socket is not None and hasattr(self._socket, "close"):
            self._socket.close()
        self._socket = None

    @property
    def raw(self) -> Any:
        return self._socket

    def send(self, data: bytes) -> None:
        self.send_message(data)

    def sendline(self, data: bytes) -> None:
        self.send_message(data + self.spec.delimiter)

    def recv(self, n: int = 4096) -> bytes:
        message = self.recv_message()
        if isinstance(message, bytes):
            return message[:n]
        return message.encode()[:n]

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        payload = self.recv()
        index = payload.find(delim)
        if index < 0:
            return payload
        end = index if drop else index + len(delim)
        return payload[:end]

    def interactive(self) -> None:
        raise TransportCapabilityError("WebSocketTransport 暂不提供 interactive()。")

    def send_message(self, message: str | bytes) -> None:
        self._require_open()
        self._socket.send(message)

    def recv_message(self) -> str | bytes:
        self._require_open()
        return self._socket.recv()


__all__ = ["WebSocketTransport"]
