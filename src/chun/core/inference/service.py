"""最小 inference 服务。"""

from __future__ import annotations

from typing import Iterable

from ..catalog import LibcCatalogService
from ..errors import InferenceInputError
from ..models import ArtifactKind, BaseInferenceResult, FactKind, ObservationKind, RecordDomain
from ..models.catalog import LibcCandidate, LibcSearchResult
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
        index: int | None = None,
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
        target_candidate = self._select_target_candidate(
            result.candidates,
            index=index,
        )
        if target_candidate is not None:
            self.registry.record_fact(
                "libc.version",
                target_candidate.name,
                kind=FactKind.VERSION,
                domain=RecordDomain.LIBC,
                source="sqlite-catalog",
                evidence=list(leaks.keys()),
                metadata={
                    "libc_id": target_candidate.libc_id,
                    "build_id": target_candidate.build_id,
                    "arch": target_candidate.arch,
                },
                overwrite=True,
            )
            self._auto_record_libc_base(target_candidate.libc_id, leaks)
        elif len(result.candidates) > 1:
            self._print_candidates(result.candidates)
        return result

    def _select_target_candidate(
        self,
        candidates: Iterable[LibcCandidate],
        *,
        index: int | None,
    ) -> LibcCandidate | None:
        candidate_list = tuple(candidates)
        if index is not None:
            if index < 0 or index >= len(candidate_list):
                raise InferenceInputError(f"候选索引越界：index={index}")
            return candidate_list[index]
        if len(candidate_list) == 1:
            return candidate_list[0]
        return None

    def _auto_record_libc_base(self, libc_id: int, leaks: dict[str, int]) -> None:
        """根据已确认 libc 与任一泄漏自动写回 libc.base。"""
        if self.libc_catalog is None:
            raise InferenceInputError("缺少 libc_catalog 依赖。")
        if not leaks:
            raise InferenceInputError("缺少可用于推导 libc.base 的 leak。")

        symbol_name, leaked_addr = next(iter(leaks.items()))
        offset = self.libc_catalog.get_offset(libc_id, symbol_name)
        base_addr = leaked_addr - offset
        self.registry.record_fact(
            "libc.base",
            base_addr,
            kind=FactKind.BASE_ADDRESS,
            domain=RecordDomain.LIBC,
            source="sqlite-catalog",
            evidence=[symbol_name],
            metadata={
                "symbol": symbol_name,
                "symbol_offset": offset,
                "libc_id": libc_id,
                "leaked_addr": leaked_addr,
            },
            overwrite=True,
        )

    @staticmethod
    def _print_candidates(candidates: Iterable[LibcCandidate]) -> None:
        """在多候选场景下输出候选列表，便于外部爆破逻辑选取。"""
        print("libc candidates:")
        for candidate in candidates:
            print(
                f"- id={candidate.libc_id} name={candidate.name} "
                f"arch={candidate.arch} matched={candidate.matched_count}"
            )

    def search_libc(
        self,
        *,
        arch: str | None = "amd64",
        require_all: bool = True,
        min_match_count: int | None = None,
        limit: int = 50,
        artifact_name: str = "libc.candidates",
        index: int | None = None,
    ) -> LibcSearchResult:
        """自动扫描 registry 中的 libc 泄漏并检索候选。"""
        observations = self.registry.find_observations(
            domain=RecordDomain.LIBC,
            kind=ObservationKind.SYMBOL_LEAK,
        )
        selected: dict[str, tuple[int, float]] = {}
        for observation in observations:
            if not isinstance(observation.value, int):
                continue
            symbol_name = str(observation.metadata.get("symbol", observation.name))
            current = selected.get(symbol_name)
            if current is None or observation.confidence >= current[1]:
                selected[symbol_name] = (observation.value, observation.confidence)

        if not selected:
            raise InferenceInputError("事实层中没有找到任何可用的 LIBC symbol leak。")

        leaks = {symbol_name: value for symbol_name, (value, _) in selected.items()}
        return self.libc_candidates_from_leaks(
            leaks,
            arch=arch,
            require_all=require_all,
            min_match_count=min_match_count,
            limit=limit,
            artifact_name=artifact_name,
            index=index,
        )


__all__ = ["InferenceService"]
