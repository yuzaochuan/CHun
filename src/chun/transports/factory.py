"""Transport 实例工厂。"""

from __future__ import annotations

from ..core.errors import TransportConfigError
from ..core.models import TargetSpec, TransportSpec
from .base import BaseTransport
from .blind_reconnect import BlindReconnectTransport
from .httpx_client import HttpxTransport
from .pwntools_tube import PwntoolsTubeTransport
from .websocket import WebSocketTransport


def build_transport(target: TargetSpec, spec: TransportSpec) -> BaseTransport:
    """根据 spec 构建对应 transport。"""
    if spec.kind == "pwntools-tube":
        if target.kind not in {"process", "remote", "ssh"}:
            raise TransportConfigError(
                f"目标类型 {target.kind} 不能使用 pwntools-tube transport。"
            )
        return PwntoolsTubeTransport(target, spec)

    if spec.kind == "httpx":
        if target.kind != "http":
            raise TransportConfigError("httpx transport 只能绑定 http target。")
        return HttpxTransport(target, spec)

    if spec.kind == "websocket":
        if target.kind != "websocket":
            raise TransportConfigError(
                "websocket transport 只能绑定 websocket target。"
            )
        return WebSocketTransport(target, spec)

    if spec.kind == "blind-reconnect":
        return BlindReconnectTransport(target, spec)

    raise TransportConfigError(f"未知 transport 类型：{spec.kind}")


__all__ = ["build_transport"]
