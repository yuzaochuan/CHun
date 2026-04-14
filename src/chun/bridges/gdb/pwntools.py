"""基于 pwntools 的交互式 GDB bridge。"""

from __future__ import annotations

import re
from typing import Any, Callable

from ..._compat import gdb
from ...core.errors import DebuggerBridgeError
from ...core.models import (
    ArtifactKind,
    ContextKind,
    ObservationKind,
    RecordDomain,
    TargetSpec,
)
from ...core.registry import EvidenceRegistry


class PwntoolsGdbBridge:
    """负责 attach / gdbscript / 交互式命令执行。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        target: TargetSpec,
        io_provider: Callable[[], object],
        attach_fn: Callable[..., object] | None = None,
    ) -> None:
        self.registry = registry
        self.target = target
        self._io_provider = io_provider
        self._attach_fn = attach_fn or gdb.attach
        self._gdb_pid: object | None = None
        self._controller: object | None = None
        self._command_index = 0

    def attach(
        self,
        io: object | None = None,
        script: str | None = None,
        *,
        api: bool = True,
    ) -> object:
        """attach 到当前 process / tube，并可选启用 GDB Python API。"""
        target_io = io if io is not None else self._io_provider()
        result = self._attach_fn(
            target_io,
            gdbscript=script or "",
            exe=self.target.binary,
            api=api,
        )
        if api and isinstance(result, tuple) and len(result) == 2:
            self._gdb_pid, self._controller = result
        else:
            self._gdb_pid = result
            self._controller = None

        self.registry.set_context(
            "debugger.attached",
            True,
            kind=ContextKind.SESSION,
            domain=RecordDomain.DEBUGGER,
        )
        self.registry.set_context(
            "debugger.attach.pid",
            self._gdb_pid,
            kind=ContextKind.SESSION,
            domain=RecordDomain.DEBUGGER,
        )
        if script:
            self.registry.record_artifact(
                "debugger.gdbscript",
                script,
                kind=ArtifactKind.SCRIPT,
                domain=RecordDomain.DEBUGGER,
                source="pwntools-gdb",
                tags=["gdb", "script"],
                overwrite=True,
            )
        self.registry.record_observation(
            f"debugger.attach.{id(self)}",
            {
                "pid": self._gdb_pid,
                "api": api,
                "binary": self.target.binary,
            },
            kind=ObservationKind.DEBUGGER_OUTPUT,
            domain=RecordDomain.DEBUGGER,
            source="pwntools-gdb",
            tags=["gdb", "attach"],
        )
        return result

    def continue_and_wait(self) -> None:
        """继续运行目标，直到下一次 stop。"""
        if self._controller is None or not hasattr(
            self._controller, "continue_and_wait"
        ):
            raise DebuggerBridgeError(
                "当前 PwntoolsGdbBridge 没有可用的 continue_and_wait 控制器。"
            )
        self._controller.continue_and_wait()

    def run_post_attach(self, command: str) -> str | None:
        """执行 attach 完成后的首条控制命令。"""
        normalized = command.strip().lower()
        if normalized in {"c", "continue"}:
            self.continue_and_wait()
            return None
        if normalized in {"n", "next"}:
            return self.execute("next")
        if normalized in {"ni", "nexti"}:
            return self.execute("nexti")
        raise DebuggerBridgeError(f"不支持的 GDB post-attach 命令：{command}")

    def _controller_execute(self, command: str) -> str:
        if self._controller is None or not hasattr(self._controller, "execute"):
            raise DebuggerBridgeError(
                "当前 PwntoolsGdbBridge 没有可用的 GDB API 控制器。"
            )
        result = self._controller.execute(command)
        return "" if result is None else str(result)

    def execute(self, command: str) -> str:
        """执行一条基本 GDB 命令。"""
        output = self._controller_execute(command)
        self._command_index += 1
        self.registry.record_observation(
            f"debugger.command.{self._command_index}",
            output,
            kind=ObservationKind.DEBUGGER_OUTPUT,
            domain=RecordDomain.DEBUGGER,
            source="pwntools-gdb",
            tags=["gdb", "command"],
            metadata={"command": command},
        )
        return output

    def breakpoint(self, location: str) -> str:
        """设置断点。"""
        return self.execute(f"break {location}")

    def snapshot_regs(self) -> dict[str, int]:
        """通过 `info registers` 获取寄存器快照。"""
        output = self.execute("info registers")
        registers: dict[str, int] = {}
        for line in output.splitlines():
            match = re.match(
                r"^([a-zA-Z][a-zA-Z0-9]+)\s+0x([0-9a-fA-F]+)", line.strip()
            )
            if not match:
                continue
            registers[match.group(1)] = int(match.group(2), 16)
        self.registry.record_observation(
            "debugger.registers",
            registers,
            kind=ObservationKind.SNAPSHOT,
            domain=RecordDomain.DEBUGGER,
            source="pwntools-gdb",
            tags=["gdb", "registers"],
            overwrite=True,
        )
        return registers

    def snapshot_maps(self) -> list[dict[str, object]]:
        """通过 `info proc mappings` 获取映射快照。"""
        output = self.execute("info proc mappings")
        mappings: list[dict[str, object]] = []
        for line in output.splitlines():
            parts = line.split()
            if (
                len(parts) < 5
                or not parts[0].startswith("0x")
                or not parts[1].startswith("0x")
            ):
                continue
            entry = {
                "start": int(parts[0], 16),
                "end": int(parts[1], 16),
                "size": parts[2],
                "offset": parts[3],
                "objfile": parts[-1],
            }
            mappings.append(entry)
        self.registry.record_observation(
            "debugger.maps",
            mappings,
            kind=ObservationKind.SNAPSHOT,
            domain=RecordDomain.DEBUGGER,
            source="pwntools-gdb",
            tags=["gdb", "maps"],
            overwrite=True,
        )
        return mappings

    def parse_file(self, addr: int) -> dict[str, object]:
        """查询地址对应的符号信息。"""
        output = self.execute(f"info symbol 0x{addr:x}")
        result = {"addr": addr, "output": output}
        self.registry.record_observation(
            f"debugger.symbol.0x{addr:x}",
            result,
            kind=ObservationKind.DEBUGGER_OUTPUT,
            domain=RecordDomain.DEBUGGER,
            source="pwntools-gdb",
            tags=["gdb", "symbol"],
            overwrite=True,
        )
        return result


__all__ = ["PwntoolsGdbBridge"]
