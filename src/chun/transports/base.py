"""Transport 抽象基类。"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..core.errors import TransportCapabilityError, TransportClosedError
from ..core.models import TargetSpec, TransportSpec


class BaseTransport(ABC):
    """所有 transport 的公共生命周期骨架。"""

    def __init__(self, target: TargetSpec, spec: TransportSpec) -> None:
        self.target = target
        self.spec = spec
        self._is_open = False

    @property
    def is_open(self) -> bool:
        return self._is_open

    def open(self) -> None:
        """打开 transport。"""
        if self._is_open:
            return
        self._open()
        self._is_open = True

    def close(self) -> None:
        """关闭 transport。"""
        if not self._is_open:
            return
        try:
            self._close()
        finally:
            self._is_open = False

    def reconnect(self) -> None:
        """默认的重连策略：先关后开。"""
        self.close()
        self.open()

    def _require_open(self) -> None:
        if not self._is_open:
            raise TransportClosedError(f"{self.__class__.__name__} 尚未打开。")

    @abstractmethod
    def _open(self) -> None:
        """子类实现实际打开逻辑。"""

    @abstractmethod
    def _close(self) -> None:
        """子类实现实际关闭逻辑。"""

    @property
    @abstractmethod
    def raw(self) -> Any:
        """返回底层原始对象。"""

    def send(self, data: bytes) -> None:
        raise TransportCapabilityError(f"{self.__class__.__name__} 不支持 send()。")

    def sendline(self, data: bytes) -> None:
        raise TransportCapabilityError(f"{self.__class__.__name__} 不支持 sendline()。")

    def sendafter(self, delim: bytes, data: bytes) -> None:
        raise TransportCapabilityError(
            f"{self.__class__.__name__} 不支持 sendafter()。"
        )

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        raise TransportCapabilityError(
            f"{self.__class__.__name__} 不支持 sendlineafter()。"
        )

    def recv(self, n: int = 4096) -> bytes:
        raise TransportCapabilityError(f"{self.__class__.__name__} 不支持 recv()。")

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        raise TransportCapabilityError(
            f"{self.__class__.__name__} 不支持 recvuntil()。"
        )

    def interactive(self) -> None:
        raise TransportCapabilityError(
            f"{self.__class__.__name__} 不支持 interactive()。"
        )


__all__ = ["BaseTransport"]
