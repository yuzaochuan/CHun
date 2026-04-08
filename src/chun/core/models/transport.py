"""TransportSpec：描述 transport 行为与生命周期配置。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


TransportKind = Literal[
    "pwntools-tube",
    "httpx",
    "websocket",
    "blind-reconnect",
]


@dataclass(slots=True)
class TransportSpec:
    """统一描述 transport 配置。"""

    kind: TransportKind
    timeout: float | None = None
    connect_timeout: float | None = None
    headers: dict[str, str] = field(default_factory=dict)
    follow_redirects: bool = True
    verify: bool = True
    delimiter: bytes = b"\n"
    metadata: dict[str, object] = field(default_factory=dict)


__all__ = ["TransportKind", "TransportSpec"]
