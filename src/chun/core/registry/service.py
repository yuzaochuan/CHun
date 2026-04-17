"""Evidence registry 主实现。"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable, TypeVar

from ..errors import RegistryConflictError
from ..models import (
    Artifact,
    ArtifactKind,
    ContextEntry,
    ContextKind,
    Fact,
    FactKind,
    Observation,
    ObservationKind,
    RecordDomain,
)

T = TypeVar("T", Observation, Fact, Artifact, ContextEntry)


class EvidenceRegistry:
    """统一管理 observation / fact / artifact / context 的事实层。"""

    def __init__(self) -> None:
        self.observations: dict[str, Observation] = {}
        self.facts: dict[str, Fact] = {}
        self.artifacts: dict[str, Artifact] = {}
        self.context: dict[str, ContextEntry] = {}

    def _store(self, bucket: dict[str, T], record: T, *, overwrite: bool) -> T:
        if not overwrite and record.name in bucket:
            raise RegistryConflictError(f"记录已存在且禁止覆盖：{record.name}")
        bucket[record.name] = record
        return record

    def record_observation(
        self,
        name: str,
        value: object,
        *,
        kind: ObservationKind = ObservationKind.SCALAR,
        domain: RecordDomain = RecordDomain.CORE,
        source: str = "manual",
        confidence: float = 0.50,
        tags: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        overwrite: bool = True,
    ) -> Observation:
        record = Observation(
            name=name,
            value=value,
            kind=kind,
            domain=domain,
            source=source,
            confidence=confidence,
            tags=list(tags or []),
            metadata=dict(metadata or {}),
        )
        return self._store(self.observations, record, overwrite=overwrite)

    def record_symbol_leak(
        self,
        symbol: str,
        leak: int,
        *,
        domain: RecordDomain = RecordDomain.LIBC,
        source: str = "manual",
        confidence: float = 0.70,
        tags: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        overwrite: bool = True,
    ) -> Observation:
        payload = dict(metadata or {})
        payload.setdefault("symbol", symbol)
        return self.record_observation(
            symbol,
            leak,
            kind=ObservationKind.SYMBOL_LEAK,
            domain=domain,
            source=source,
            confidence=confidence,
            tags=tags,
            metadata=payload,
            overwrite=overwrite,
        )

    def record_fact(
        self,
        name: str,
        value: object,
        *,
        kind: FactKind = FactKind.DERIVED,
        domain: RecordDomain = RecordDomain.CORE,
        source: str = "derived",
        confidence: float = 0.80,
        evidence: list[str] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        overwrite: bool = True,
    ) -> Fact:
        record = Fact(
            name=name,
            value=value,
            kind=kind,
            domain=domain,
            source=source,
            confidence=confidence,
            evidence=list(evidence or []),
            tags=list(tags or []),
            metadata=dict(metadata or {}),
        )
        return self._store(self.facts, record, overwrite=overwrite)

    def record_artifact(
        self,
        name: str,
        value: object,
        *,
        kind: ArtifactKind = ArtifactKind.GENERIC,
        domain: RecordDomain = RecordDomain.CORE,
        source: str = "manual",
        tags: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        overwrite: bool = True,
    ) -> Artifact:
        record = Artifact(
            name=name,
            value=value,
            kind=kind,
            domain=domain,
            source=source,
            tags=list(tags or []),
            metadata=dict(metadata or {}),
        )
        return self._store(self.artifacts, record, overwrite=overwrite)

    def set_context(
        self,
        name: str,
        value: object,
        *,
        kind: ContextKind = ContextKind.SESSION,
        domain: RecordDomain = RecordDomain.CORE,
        source: str = "session",
        tags: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        overwrite: bool = True,
    ) -> ContextEntry:
        entry = ContextEntry(
            name=name,
            value=value,
            kind=kind,
            domain=domain,
            source=source,
            tags=list(tags or []),
            metadata=dict(metadata or {}),
        )
        return self._store(self.context, entry, overwrite=overwrite)

    def get_observation(self, name: str) -> Observation | None:
        return self.observations.get(name)

    def get_fact(self, name: str) -> Fact | None:
        return self.facts.get(name)

    def get_artifact(self, name: str) -> Artifact | None:
        return self.artifacts.get(name)

    def get_context(self, name: str) -> ContextEntry | None:
        return self.context.get(name)

    def require_observation(self, name: str) -> Observation:
        record = self.get_observation(name)
        if record is None:
            raise KeyError(f"observation 不存在：{name}")
        return record

    def require_fact(self, name: str) -> Fact:
        record = self.get_fact(name)
        if record is None:
            raise KeyError(f"fact 不存在：{name}")
        return record

    def require_artifact(self, name: str) -> Artifact:
        record = self.get_artifact(name)
        if record is None:
            raise KeyError(f"artifact 不存在：{name}")
        return record

    def require_context(self, name: str) -> ContextEntry:
        record = self.get_context(name)
        if record is None:
            raise KeyError(f"context 不存在：{name}")
        return record

    def require_int_observation(self, name: str) -> int:
        record = self.require_observation(name)
        if not isinstance(record.value, int):
            raise TypeError(f"observation[{name}] 不是 int：{type(record.value).__name__}")
        return record.value

    def require_int_fact(self, name: str) -> int:
        record = self.require_fact(name)
        if not isinstance(record.value, int):
            raise TypeError(f"fact[{name}] 不是 int：{type(record.value).__name__}")
        return record.value

    def require_str_fact(self, name: str) -> str:
        record = self.require_fact(name)
        if not isinstance(record.value, str):
            raise TypeError(f"fact[{name}] 不是 str：{type(record.value).__name__}")
        return record.value

    @staticmethod
    def _match_record(
        record: Observation | Fact | Artifact | ContextEntry,
        *,
        domain: RecordDomain | None = None,
        kind: object | None = None,
        tag: str | None = None,
        source: str | None = None,
    ) -> bool:
        if domain is not None and record.domain != domain:
            return False
        if kind is not None and record.kind != kind:
            return False
        if tag is not None and tag not in record.tags:
            return False
        if source is not None and record.source != source:
            return False
        return True

    def _find(
        self,
        bucket: Iterable[T],
        *,
        domain: RecordDomain | None = None,
        kind: object | None = None,
        tag: str | None = None,
        source: str | None = None,
    ) -> list[T]:
        return [
            item
            for item in bucket
            if self._match_record(item, domain=domain, kind=kind, tag=tag, source=source)
        ]

    def find_observations(
        self,
        *,
        domain: RecordDomain | None = None,
        kind: ObservationKind | None = None,
        tag: str | None = None,
        source: str | None = None,
    ) -> list[Observation]:
        return self._find(
            self.observations.values(),
            domain=domain,
            kind=kind,
            tag=tag,
            source=source,
        )

    def find_facts(
        self,
        *,
        domain: RecordDomain | None = None,
        kind: FactKind | None = None,
        tag: str | None = None,
        source: str | None = None,
    ) -> list[Fact]:
        return self._find(
            self.facts.values(),
            domain=domain,
            kind=kind,
            tag=tag,
            source=source,
        )

    def find_artifacts(
        self,
        *,
        domain: RecordDomain | None = None,
        kind: ArtifactKind | None = None,
        tag: str | None = None,
        source: str | None = None,
    ) -> list[Artifact]:
        return self._find(
            self.artifacts.values(),
            domain=domain,
            kind=kind,
            tag=tag,
            source=source,
        )

    def find_context(
        self,
        *,
        domain: RecordDomain | None = None,
        kind: ContextKind | None = None,
        tag: str | None = None,
        source: str | None = None,
    ) -> list[ContextEntry]:
        return self._find(
            self.context.values(),
            domain=domain,
            kind=kind,
            tag=tag,
            source=source,
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "observations": {name: asdict(item) for name, item in self.observations.items()},
            "facts": {name: asdict(item) for name, item in self.facts.items()},
            "artifacts": {name: asdict(item) for name, item in self.artifacts.items()},
            "context": {name: asdict(item) for name, item in self.context.items()},
        }

__all__ = ["EvidenceRegistry"]
