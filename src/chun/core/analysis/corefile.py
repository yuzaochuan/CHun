"""Corefile / crash 分析。"""

from __future__ import annotations

from typing import Any

from ..._compat import Corefile, cyclic_find
from ..errors import CrashAnalysisError
from ..models import (
    ContextKind,
    CrashAnalysisResult,
    FactKind,
    ObservationKind,
    RecordDomain,
)
from ..registry import EvidenceRegistry


class CorefileAnalyzer:
    """读取 core dump 并把 crash 上下文写回 registry。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        *,
        corefile_factory: type | None = None,
        cyclic_finder: Any = None,
    ) -> None:
        self.registry = registry
        self.corefile_factory = corefile_factory or Corefile
        self.cyclic_finder = cyclic_finder or cyclic_find

    def _load_corefile(self, core: object) -> object:
        if isinstance(core, (str, bytes)):
            return self.corefile_factory(core)
        return core

    @staticmethod
    def _get_registers(core: object) -> dict[str, int]:
        registers = getattr(core, "registers", {}) or {}
        return {str(name): int(value) for name, value in registers.items()}

    @staticmethod
    def _pick_register(core: object, registers: dict[str, int], *names: str) -> int | None:
        for name in names:
            if hasattr(core, name):
                value = getattr(core, name)
                if value is not None:
                    return int(value)
            if name in registers:
                return int(registers[name])
        return None

    @staticmethod
    def _extract_maps(core: object) -> list[dict[str, object]]:
        mappings = getattr(core, "maps", None) or []
        result: list[dict[str, object]] = []
        for entry in mappings:
            if isinstance(entry, dict):
                result.append(dict(entry))
                continue
            item: dict[str, object] = {}
            for attr in ("start", "end", "flags", "path", "page_offset"):
                if hasattr(entry, attr):
                    item[attr] = getattr(entry, attr)
            if item:
                result.append(item)
        return result

    def analyze(
        self,
        core: object,
        *,
        offset_subseq: object | None = None,
    ) -> CrashAnalysisResult:
        corefile = self._load_corefile(core)
        registers = self._get_registers(corefile)
        pc = self._pick_register(corefile, registers, "pc", "rip", "eip")
        sp = self._pick_register(corefile, registers, "sp", "rsp", "esp")
        fault_addr = getattr(corefile, "fault_addr", None)
        fault_addr = int(fault_addr) if fault_addr is not None else None
        signal = getattr(corefile, "signal", None)
        maps = self._extract_maps(corefile)
        core_path = getattr(corefile, "path", None)

        cyclic_offset: int | None = None
        subseq = pc if offset_subseq is None else offset_subseq
        if subseq is not None:
            try:
                found = self.cyclic_finder(subseq)
                if found is not None and int(found) >= 0:
                    cyclic_offset = int(found)
            except Exception:
                cyclic_offset = None

        result = CrashAnalysisResult(
            core_path=None if core_path is None else str(core_path),
            signal=signal,
            fault_addr=fault_addr,
            pc=pc,
            sp=sp,
            registers=registers,
            maps=maps,
            cyclic_offset=cyclic_offset,
        )

        self.registry.record_observation(
            "crash.registers",
            registers,
            kind=ObservationKind.SNAPSHOT,
            domain=RecordDomain.CRASH,
            source="corefile",
            tags=["crash", "registers"],
            overwrite=True,
        )
        self.registry.record_observation(
            "crash.maps",
            maps,
            kind=ObservationKind.SNAPSHOT,
            domain=RecordDomain.CRASH,
            source="corefile",
            tags=["crash", "maps"],
            overwrite=True,
        )
        self.registry.record_observation(
            "crash.summary",
            {
                "fault_addr": fault_addr,
                "pc": pc,
                "sp": sp,
                "signal": signal,
            },
            kind=ObservationKind.DEBUGGER_OUTPUT,
            domain=RecordDomain.CRASH,
            source="corefile",
            tags=["crash", "summary"],
            overwrite=True,
        )
        if pc is not None:
            self.registry.record_fact(
                "crash.pc",
                pc,
                kind=FactKind.ADDRESS,
                domain=RecordDomain.CRASH,
                source="corefile",
                tags=["crash", "pc"],
                overwrite=True,
            )
        if sp is not None:
            self.registry.record_fact(
                "crash.sp",
                sp,
                kind=FactKind.ADDRESS,
                domain=RecordDomain.CRASH,
                source="corefile",
                tags=["crash", "sp"],
                overwrite=True,
            )
        if fault_addr is not None:
            self.registry.record_fact(
                "crash.fault_addr",
                fault_addr,
                kind=FactKind.ADDRESS,
                domain=RecordDomain.CRASH,
                source="corefile",
                tags=["crash", "fault"],
                overwrite=True,
            )
        if cyclic_offset is not None:
            self.registry.record_fact(
                "crash.cyclic_offset",
                cyclic_offset,
                kind=FactKind.OFFSET,
                domain=RecordDomain.CRASH,
                source="corefile",
                tags=["crash", "offset"],
                overwrite=True,
            )

        self.registry.set_context(
            "crash.core.path",
            result.core_path,
            kind=ContextKind.ENVIRONMENT,
            domain=RecordDomain.CRASH,
            overwrite=True,
        )
        self.registry.set_context(
            "crash.signal",
            signal,
            kind=ContextKind.ENVIRONMENT,
            domain=RecordDomain.CRASH,
            overwrite=True,
        )
        self.registry.set_context(
            "crash.maps.count",
            len(maps),
            kind=ContextKind.ENVIRONMENT,
            domain=RecordDomain.CRASH,
            overwrite=True,
        )
        return result


__all__ = ["CorefileAnalyzer"]
