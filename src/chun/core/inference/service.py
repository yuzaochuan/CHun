"""最小 inference 服务。"""

from __future__ import annotations

from ..catalog import LibcCatalogService
from ..errors import InferenceInputError
from ..models import ArtifactKind, BaseInferenceResult, FactKind, RecordDomain
from ..models.catalog import LibcSearchResult
from ..registry import EvidenceRegistry


class InferenceService:
    """第二阶段最小可用 inference 入口。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        page_size: int = 0x1000,
        *,
        libc_catalog: LibcCatalogService | None = None,
    ) -> None:
        self.registry = registry
        self.page_size = page_size
        self.libc_catalog = libc_catalog

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

    def libc_candidates_from_leaks(
        self,
        leaks: dict[str, int],
        *,
        arch: str | None = "amd64",
        require_all: bool = True,
        min_match_count: int | None = None,
        limit: int = 50,
        artifact_name: str = "libc.candidates",
    ) -> LibcSearchResult:
        """从多条泄漏中检索 libc 候选并回写 registry。"""
        if self.libc_catalog is None:
            raise InferenceInputError("缺少 libc_catalog 依赖。")

        result = self.libc_catalog.find_candidates(
            leaks,
            arch=arch,
            require_all=require_all,
            min_match_count=min_match_count,
            limit=limit,
        )
        self.registry.record_artifact(
            artifact_name,
            result,
            kind=ArtifactKind.CATALOG_RESULT,
            domain=RecordDomain.LIBC,
            source="sqlite-catalog",
            metadata={
                "query_mode": result.query_mode,
                "exact_match": result.exact_match,
                "candidate_count": len(result.candidates),
            },
            overwrite=True,
        )
        if len(result.candidates) == 1:
            only = result.candidates[0]
            self.registry.record_fact(
                "libc.version",
                only.name,
                kind=FactKind.VERSION,
                domain=RecordDomain.LIBC,
                source="sqlite-catalog",
                evidence=list(leaks.keys()),
                metadata={
                    "libc_id": only.libc_id,
                    "build_id": only.build_id,
                    "arch": only.arch,
                },
                overwrite=True,
            )
        return result


__all__ = ["InferenceService"]
