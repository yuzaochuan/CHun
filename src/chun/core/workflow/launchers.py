"""workflow launcher 抽象。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Protocol, Sequence

from ...facade import CHun, DEFAULT_TERMINAL
from ..session import CHunSession


class WorkflowLauncher(Protocol):
    """负责“怎么拿到 session”。"""

    def launch(self, primitive: object | None = None) -> CHunSession: ...


@dataclass(slots=True)
class ProcessLauncher:
    """本地 process launcher。"""

    binary: str
    argv: Sequence[str] | None = None
    libc: str | None = None
    ld: str | None = None
    env: Mapping[str, str] | None = None
    cwd: str | None = None
    log_level: str = "info"
    terminal: Sequence[str] | None = None

    def launch(self, primitive: object | None = None) -> CHunSession:
        return CHun.process(
            self.binary,
            argv=self.argv,
            libc=self.libc,
            ld=self.ld,
            env=dict(self.env or {}),
            cwd=self.cwd,
            log_level=self.log_level,
            terminal=self.terminal or DEFAULT_TERMINAL,
        )


__all__ = ["ProcessLauncher", "WorkflowLauncher"]
