"""workflow launcher 抽象。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol, Sequence

from ... import _compat
from ...facade import CHun, DEFAULT_TERMINAL
from ..session import CHunSession

ELF = _compat.ELF


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
        session = CHun.process(
            self.binary,
            argv=self.argv,
            libc=self.libc,
            ld=self.ld,
            env=dict(self.env or {}),
            cwd=self.cwd,
            log_level=self.log_level,
            terminal=self.terminal or DEFAULT_TERMINAL,
        )
        if isinstance(session, CHunSession):
            self._bind_runtime_binaries(session)
        return session

    def _bind_runtime_binaries(self, session: CHunSession) -> None:
        elf_obj = self._load_elf(self.binary)
        libc_obj = self._load_elf(self.libc)
        if libc_obj is None:
            libc_obj = self._infer_libc_from_elf(elf_obj)
        if elf_obj is None and libc_obj is None:
            return
        session.bind_binaries(elf=elf_obj, libc_elf=libc_obj, source="workflow.launch")

    def _load_elf(self, path: str | None) -> object | None:
        if not path:
            return None
        resolved = self._resolve_path(path)
        if not resolved.exists():
            return None
        try:
            return ELF(str(resolved), checksec=False)
        except Exception as exc:
            _compat.log.warning(f"workflow launcher 无法加载 ELF: {resolved} ({exc})")
            return None

    def _resolve_path(self, path: str) -> Path:
        raw = Path(path)
        if raw.is_absolute():
            return raw
        if self.cwd is not None:
            return Path(self.cwd) / raw
        return raw.resolve()

    def _infer_libc_from_elf(self, elf_obj: object | None) -> object | None:
        if elf_obj is None:
            return None
        try:
            libc_obj = getattr(elf_obj, "libc", None)
        except Exception:
            return None
        libc_path = getattr(libc_obj, "path", None)
        if isinstance(libc_path, str) and libc_path:
            self.libc = libc_path
            return libc_obj
        return None


__all__ = ["ProcessLauncher", "WorkflowLauncher"]
