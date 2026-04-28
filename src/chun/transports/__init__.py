"""Transport 模块导出。"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_BASE_EXPORTS = {"BaseTransport"}
_BLIND_EXPORTS = {"BlindReconnectTransport"}
_HTTP_EXPORTS = {"HttpxTransport"}
_PWN_EXPORTS = {"PwntoolsTubeTransport"}
_WS_EXPORTS = {"WebSocketTransport"}
_FACTORY_EXPORTS = {"build_transport"}

__all__ = [
    "BaseTransport",
    "BlindReconnectTransport",
    "HttpxTransport",
    "PwntoolsTubeTransport",
    "WebSocketTransport",
    "build_transport",
]


def __getattr__(name: str) -> Any:
    if name in _BASE_EXPORTS:
        return getattr(import_module(".base", __name__), name)
    if name in _BLIND_EXPORTS:
        return getattr(import_module(".blind_reconnect", __name__), name)
    if name in _HTTP_EXPORTS:
        return getattr(import_module(".httpx_client", __name__), name)
    if name in _PWN_EXPORTS:
        return getattr(import_module(".pwntools_tube", __name__), name)
    if name in _WS_EXPORTS:
        return getattr(import_module(".websocket", __name__), name)
    if name in _FACTORY_EXPORTS:
        return getattr(import_module(".factory", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
