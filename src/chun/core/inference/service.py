"""最小 inference 服务。"""

from __future__ import annotations

from ..errors import InferenceInputError
from ..models import BaseInferenceResult, FactKind, RecordDomain
from ..registry import EvidenceRegistry


class InferenceService:
    """第二阶段最小可用 inference 入口。"""

    def __init__(self, registry: EvidenceRegistry, page_size: int = 0x1000) -> None:
        self.registry = registry
        self.page_size = page_size

    def _infer_base_from_symbol_leak(
        self,
        observation_name: str,
        symbol_offset: int,
        *,
        fact_name: str,
        domain: RecordDomain,
    ) -> BaseInferenceResult:
        observation = self.registry.get_observation(observation_name)
        if observation is None:
            raise InferenceInputError(f"缺少 observation：{observation_name}")

        if not isinstance(observation.value, int):
            raise InferenceInputError("symbol leak observation 必须是整数地址。")

        if symbol_offset < 0:
            raise InferenceInputError("symbol_offset 不能为负数。")

        raw_base = observation.value - symbol_offset
        aligned_base = raw_base - (raw_base % self.page_size)

        stored_fact = self.registry.record_fact(
            fact_name,
            aligned_base,
            kind=FactKind.BASE_ADDRESS,
            domain=domain,
            source="inference",
            confidence=observation.confidence,
            evidence=[observation.name],
            tags=["base", domain.value],
            metadata={
                "raw_base": raw_base,
                "aligned_base": aligned_base,
                "symbol_offset": symbol_offset,
                "observation": observation.name,
            },
            overwrite=True,
        )
        return BaseInferenceResult(
            fact_name=fact_name,
            observation_name=observation.name,
            symbol_offset=symbol_offset,
            raw_base=raw_base,
            aligned_base=aligned_base,
            stored_fact=stored_fact,
        )

    def libc_base_from_symbol_leak(
        self,
        observation_name: str,
        *,
        symbol_offset: int,
        fact_name: str = "libc.base",
    ) -> BaseInferenceResult:
        return self._infer_base_from_symbol_leak(
            observation_name,
            symbol_offset,
            fact_name=fact_name,
            domain=RecordDomain.LIBC,
        )

    def pie_base_from_symbol_leak(
        self,
        observation_name: str,
        *,
        symbol_offset: int,
        fact_name: str = "elf.base",
    ) -> BaseInferenceResult:
        return self._infer_base_from_symbol_leak(
            observation_name,
            symbol_offset,
            fact_name=fact_name,
            domain=RecordDomain.ELF,
        )


__all__ = ["InferenceService"]
