"""TargetSpec：描述目标与运行上下文。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


TargetKind = Literal[
    "process",
    "remote",
    "ssh",
    "http",
    "websocket",
    "blind",
    "qemu",
]


@dataclass(slots=True)
class TargetSpec:
    """统一描述 CHun 会话面向的目标。"""

    kind: TargetKind
    binary: str | None = None
    libc: str | None = None
    ld: str | None = None
    host: str | None = None
    port: int | None = None
    base_url: str | None = None
    ws_url: str | None = None
    argv: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str | None = None
    ssh_host: str | None = None
    ssh_port: int = 22
    ssh_user: str | None = None
    ssh_password: str | None = None
    ssh_keyfile: str | None = None
    ssh_key_password: str | None = None
    metadata: dict[str, object] = field(default_factory=dict)


__all__ = ["TargetKind", "TargetSpec"]
