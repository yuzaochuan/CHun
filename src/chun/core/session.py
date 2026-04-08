"""CHun 顶层会话对象。"""

from __future__ import annotations

from dataclasses import dataclass

from .models import TargetSpec, TransportSpec


@dataclass(slots=True)
class CHunSession:
    """第一阶段最小可用会话对象。

    当前阶段只落地 transport 相关骨架，因此会话先收敛为：
    - `target`：目标描述
    - `transport_spec`：transport 配置
    - `transport`：实际 transport 实例
    """

    target: TargetSpec
    transport_spec: TransportSpec
    transport: object

    def open(self) -> "CHunSession":
        """显式打开 transport。"""
        self.transport.open()
        return self

    def close(self) -> None:
        """关闭 transport。"""
        self.transport.close()

    def reconnect(self) -> None:
        """重建 transport。"""
        self.transport.reconnect()

    @property
    def io(self) -> object:
        """提供统一 runtime 入口，并在首次访问时延迟打开 transport。"""
        if not self.transport.is_open:
            self.transport.open()
        return self.transport

    @property
    def raw(self) -> object:
        """返回底层 transport 的原始对象。"""
        return self.io.raw

    def __enter__(self) -> "CHunSession":
        return self.open()

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


Session = CHunSession


__all__ = ["CHunSession", "Session"]
