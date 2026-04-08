"""Blind reconnect transport。"""

from __future__ import annotations

from typing import Any, Callable, TypeVar

from ..core.errors import TransportCapabilityError, TransportConfigError
from .base import BaseTransport

T = TypeVar("T")


class BlindReconnectTransport(BaseTransport):
    """每次交互都通过工厂创建新连接的 transport。"""

    def __init__(self, target: object, spec: object) -> None:
        super().__init__(target, spec)
        self._last_raw: Any = None

    def _open(self) -> None:
        connection_factory = self.spec.metadata.get("connection_factory")
        if not callable(connection_factory):
            raise TransportConfigError(
                "BlindReconnectTransport 需要 connection_factory。"
            )

    def _close(self) -> None:
        if self._last_raw is not None and hasattr(self._last_raw, "close"):
            self._last_raw.close()
        self._last_raw = None

    @property
    def raw(self) -> Any:
        return self._last_raw

    def send(self, data: bytes) -> None:
        self.exchange(data)

    def sendline(self, data: bytes) -> None:
        self.exchange(data, newline=True)

    def recv(self, n: int = 4096) -> bytes:
        raise TransportCapabilityError(
            "BlindReconnectTransport 不支持脱离交互上下文的 recv()，请使用 exchange() 或 run()。"
        )

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        raise TransportCapabilityError(
            "BlindReconnectTransport 不支持脱离交互上下文的 recvuntil()，请使用 exchange() 或 run()。"
        )

    def interactive(self) -> None:
        raise TransportCapabilityError(
            "BlindReconnectTransport 不支持 interactive()。"
        )

    def _spawn_connection(self) -> tuple[Any, Callable[[], None]]:
        self._require_open()
        connection_factory = self.spec.metadata["connection_factory"]
        created = connection_factory()

        if hasattr(created, "open") and hasattr(created, "close") and hasattr(created, "raw"):
            created.open()
            raw = created.raw

            def _closer() -> None:
                created.close()

            return raw, _closer

        raw = created

        def _closer() -> None:
            if hasattr(raw, "close"):
                raw.close()

        return raw, _closer

    def run(self, operation: Callable[[Any], T]) -> T:
        """在一次性连接上下文内运行任意操作。"""
        raw, closer = self._spawn_connection()
        self._last_raw = raw
        try:
            return operation(raw)
        finally:
            closer()
            self._last_raw = None

    def exchange(
        self,
        payload: bytes,
        *,
        receive: Callable[[Any], bytes | None] | None = None,
        newline: bool = False,
    ) -> bytes | None:
        """完成一次 blind 场景中的“建连 -> 发送 -> 收取 -> 关闭”。"""

        def _operation(raw: Any) -> bytes | None:
            if newline:
                if hasattr(raw, "sendline"):
                    raw.sendline(payload)
                elif hasattr(raw, "send"):
                    raw.send(payload + self.spec.delimiter)
                else:
                    raise TransportCapabilityError("底层连接不支持 sendline/send。")
            else:
                if not hasattr(raw, "send"):
                    raise TransportCapabilityError("底层连接不支持 send。")
                raw.send(payload)

            if receive is not None:
                return receive(raw)

            if hasattr(raw, "recv"):
                return raw.recv()
            return None

        return self.run(_operation)


__all__ = ["BlindReconnectTransport"]
