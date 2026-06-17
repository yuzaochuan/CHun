"""Evidence registry 主实现。"""

from __future__ import annotations

import logging
from dataclasses import asdict
from enum import Enum
from typing import Any, Callable, Iterable, Literal, TypeVar, cast

from ..replay import (
    ReplayCheckpoint,
    ReplayEvent,
    ReplayEventKind,
    ReplayExecutor,
    ReplayRecorder,
    VerificationResult,
)

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
RegistryRecord = Observation | Fact | Artifact | ContextEntry
RegistryLayer = Literal["context", "observations", "facts", "artifacts"]
RegistryDetail = Literal["compact", "standard", "verbose"]
RegistryEmit = Literal["debug", "info", "warning"]
RegistryArtifactMode = Literal["summary", "repr", "skip"]
ReplayPayloadMode = Literal["repr", "hex"]

_LAYER_ORDER: tuple[RegistryLayer, ...] = ("context", "observations", "facts", "artifacts")
_LAYER_LABELS: dict[RegistryLayer, str] = {
    "context": "Context",
    "observations": "Observations",
    "facts": "Facts",
    "artifacts": "Artifacts",
}
_LAYER_ABBR: dict[RegistryLayer, str] = {
    "context": "ctx",
    "observations": "obs",
    "facts": "facts",
    "artifacts": "arts",
}
_DETAIL_VALUES = {"compact", "standard", "verbose"}
_EMIT_VALUES = {"debug", "info", "warning"}
_ARTIFACT_MODE_VALUES = {"summary", "repr", "skip"}
_REPLAY_PAYLOAD_MODE_VALUES = {"repr", "hex"}
_LOG = logging.getLogger("chun")
log = _LOG


class EvidenceRegistry:
    """统一管理 observation / fact / artifact / context 的事实层。"""

    def __init__(self) -> None:
        self.observations: dict[str, Observation] = {}
        self.facts: dict[str, Fact] = {}
        self.artifacts: dict[str, Artifact] = {}
        self.context: dict[str, ContextEntry] = {}
        self.replay: ReplayRecorder = ReplayRecorder()

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

    @staticmethod
    def _normalize_layers(layers: Iterable[RegistryLayer] | RegistryLayer) -> tuple[RegistryLayer, ...]:
        if isinstance(layers, str):
            values = (cast(RegistryLayer, layers),)
        else:
            values = tuple(layers)
        if not values:
            raise ValueError("layers 不能为空")
        invalid = [value for value in values if value not in _LAYER_ORDER]
        if invalid:
            allowed = ", ".join(_LAYER_ORDER)
            raise ValueError(f"未知 layers：{', '.join(invalid)}，可选值：{allowed}")
        deduped: list[RegistryLayer] = []
        for value in values:
            if value not in deduped:
                deduped.append(value)
        return tuple(deduped)

    @staticmethod
    def _normalize_detail(detail: RegistryDetail) -> RegistryDetail:
        if detail not in _DETAIL_VALUES:
            allowed = ", ".join(sorted(_DETAIL_VALUES))
            raise ValueError(f"未知 detail：{detail}，可选值：{allowed}")
        return detail

    @staticmethod
    def _normalize_emit(emit: RegistryEmit) -> RegistryEmit:
        if emit not in _EMIT_VALUES:
            allowed = ", ".join(sorted(_EMIT_VALUES))
            raise ValueError(f"未知 emit：{emit}，可选值：{allowed}")
        return emit

    @staticmethod
    def _normalize_artifact_mode(artifact_mode: RegistryArtifactMode) -> RegistryArtifactMode:
        if artifact_mode not in _ARTIFACT_MODE_VALUES:
            allowed = ", ".join(sorted(_ARTIFACT_MODE_VALUES))
            raise ValueError(f"未知 artifact_mode：{artifact_mode}，可选值：{allowed}")
        return artifact_mode

    def _bucket_for_layer(self, layer: RegistryLayer) -> Iterable[RegistryRecord]:
        if layer == "context":
            return self.context.values()
        if layer == "observations":
            return self.observations.values()
        if layer == "facts":
            return self.facts.values()
        return self.artifacts.values()

    @staticmethod
    def _format_scalar(value: object) -> str:
        if isinstance(value, bool):
            return str(value)
        if isinstance(value, int):
            return f"{value:#014x}" if value > 0xFFFFFFFF else f"{value:#010x}"
        if isinstance(value, str):
            return value
        if isinstance(value, (bytes, bytearray, memoryview)):
            return repr(bytes(value))
        return repr(value)

    @staticmethod
    def _truncate(text: str, *, limit: int = 96) -> str:
        if len(text) <= limit:
            return text
        if limit <= 3:
            return text[:limit]
        return text[: limit - 3] + "..."

    @staticmethod
    def _safe_len(value: object) -> int | None:
        try:
            return len(value)  # type: ignore[arg-type]
        except Exception:
            return None

    def _summarize_artifact(self, value: object) -> str:
        if isinstance(value, (bool, int)):
            return self._format_scalar(value)
        if isinstance(value, (bytes, bytearray, memoryview)):
            raw = bytes(value)
            preview = self._truncate(repr(raw), limit=48)
            return f"bytes[len={len(raw)}] {preview}"
        if isinstance(value, str):
            preview = self._truncate(repr(value), limit=48)
            return f"str[len={len(value)}] {preview}"
        if isinstance(value, dict):
            return f"dict[len={len(value)}]"
        if isinstance(value, list):
            return f"list[len={len(value)}]"
        if isinstance(value, tuple):
            return f"tuple[len={len(value)}]"
        if isinstance(value, set):
            return f"set[len={len(value)}]"
        size = self._safe_len(value)
        if size is not None:
            return f"{type(value).__name__}[len={size}]"
        return type(value).__name__

    def _format_value(
        self,
        record: RegistryRecord,
        *,
        artifact_mode: RegistryArtifactMode,
    ) -> str | None:
        if isinstance(record, Artifact):
            if artifact_mode == "skip":
                return None
            if artifact_mode == "summary":
                return self._summarize_artifact(record.value)
        return self._truncate(self._format_scalar(record.value))

    @staticmethod
    def _enum_value(value: object) -> str:
        if isinstance(value, Enum):
            return str(value.value)
        return str(value)

    def snapshot(
        self,
        *,
        layers: Iterable[RegistryLayer] | RegistryLayer = _LAYER_ORDER,
        domain: RecordDomain | None = None,
        source: str | None = None,
        tag: str | None = None,
        limit: int | None = None,
    ) -> dict[str, object]:
        """返回按层分组的 registry 快照。

        `limit` 按层生效，用于裁剪每一层输出的记录数量。
        """
        selected_layers = self._normalize_layers(layers)
        if limit is not None and limit < 0:
            raise ValueError("limit 不能小于 0")

        layer_map: dict[RegistryLayer, list[RegistryRecord]] = {}
        summary: dict[str, int] = {}
        total = 0

        for layer in selected_layers:
            records = self._find(
                self._bucket_for_layer(layer),
                domain=domain,
                tag=tag,
                source=source,
            )
            typed_records = cast(list[RegistryRecord], records)
            if limit is not None:
                typed_records = typed_records[:limit]
            layer_map[layer] = typed_records
            count = len(typed_records)
            summary[layer] = count
            total += count

        summary["total"] = total
        return {"layers": layer_map, "summary": summary}

    def _render_record(
        self,
        record: RegistryRecord,
        *,
        detail: RegistryDetail,
        artifact_mode: RegistryArtifactMode,
    ) -> list[str]:
        value_text = self._format_value(record, artifact_mode=artifact_mode)
        if value_text is None:
            return []

        if detail == "compact":
            return [f"{record.name:<32} {value_text}"]

        if detail == "standard":
            extras = [
                f"kind={self._enum_value(record.kind)}",
                f"domain={self._enum_value(record.domain)}",
                f"src={record.source}",
            ]
            if isinstance(record, Observation | Fact):
                extras.append(f"conf={record.confidence:.2f}")
            return [f"{record.name:<32} {value_text} {' '.join(extras)}"]

        lines = [
            f"name        {record.name}",
            f"value       {value_text}",
            f"kind        {self._enum_value(record.kind)}",
            f"domain      {self._enum_value(record.domain)}",
            f"source      {record.source}",
        ]
        if isinstance(record, Observation | Fact):
            lines.append(f"confidence  {record.confidence:.2f}")
        if isinstance(record, Fact) and record.evidence:
            lines.append(f"evidence    {', '.join(record.evidence)}")
        if record.tags:
            lines.append(f"tags        {', '.join(record.tags)}")
        if record.metadata:
            lines.append(f"metadata    {self._truncate(repr(record.metadata), limit=120)}")
        lines.append(f"ts          {record.ts.isoformat()}")
        return lines

    def render(
        self,
        *,
        layers: Iterable[RegistryLayer] | RegistryLayer = _LAYER_ORDER,
        detail: RegistryDetail = "standard",
        domain: RecordDomain | None = None,
        source: str | None = None,
        tag: str | None = None,
        limit: int | None = None,
        artifact_mode: RegistryArtifactMode = "summary",
    ) -> list[str]:
        """把 registry 快照渲染为文本行。"""
        normalized_layers = self._normalize_layers(layers)
        normalized_detail = self._normalize_detail(detail)
        normalized_artifact_mode = self._normalize_artifact_mode(artifact_mode)
        data = self.snapshot(
            layers=normalized_layers,
            domain=domain,
            source=source,
            tag=tag,
            limit=limit,
        )
        layer_map = cast(dict[RegistryLayer, list[RegistryRecord]], data["layers"])
        rendered_layers: dict[RegistryLayer, list[str]] = {}
        rendered_counts: dict[RegistryLayer, int] = {}
        rendered_total = 0
        for layer in normalized_layers:
            layer_lines: list[str] = []
            visible_count = 0
            for record in layer_map[layer]:
                record_lines = self._render_record(
                    record,
                    detail=normalized_detail,
                    artifact_mode=normalized_artifact_mode,
                )
                if not record_lines:
                    continue
                if normalized_detail == "verbose" and layer_lines:
                    layer_lines.append("-" * 56)
                layer_lines.extend(record_lines)
                visible_count += 1
            rendered_layers[layer] = layer_lines
            rendered_counts[layer] = visible_count
            rendered_total += visible_count

        summary_text = " ".join(
            f"{_LAYER_ABBR[layer]}={rendered_counts[layer]}" for layer in normalized_layers
        )
        lines = [f"[Registry] {summary_text} total={rendered_total}"]
        if rendered_total == 0:
            lines.append("当前 Registry 还没有匹配记录。")
            return lines

        for layer in normalized_layers:
            layer_lines = rendered_layers[layer]
            if not layer_lines:
                continue
            lines.append(f"[{_LAYER_LABELS[layer]}]")
            lines.extend(layer_lines)
        return lines

    @staticmethod
    def _resolve_emitter(level: RegistryEmit) -> Callable[[str], None]:
        if level == "debug":
            return log.debug
        if level == "warning":
            return log.warning
        return log.info

    def show(
        self,
        *,
        layers: Iterable[RegistryLayer] | RegistryLayer = _LAYER_ORDER,
        detail: RegistryDetail = "standard",
        emit: RegistryEmit = "info",
        domain: RecordDomain | None = None,
        source: str | None = None,
        tag: str | None = None,
        limit: int | None = None,
        artifact_mode: RegistryArtifactMode = "summary",
    ) -> list[str]:
        """输出 registry 快照，并返回已输出的文本行。"""
        normalized_emit = self._normalize_emit(emit)
        lines = self.render(
            layers=layers,
            detail=detail,
            domain=domain,
            source=source,
            tag=tag,
            limit=limit,
            artifact_mode=artifact_mode,
        )
        emitter = self._resolve_emitter(normalized_emit)
        for line in lines:
            emitter(line)
        return lines

    @staticmethod
    def _normalize_replay_payload_mode(mode: ReplayPayloadMode) -> ReplayPayloadMode:
        if mode not in _REPLAY_PAYLOAD_MODE_VALUES:
            allowed = ", ".join(sorted(_REPLAY_PAYLOAD_MODE_VALUES))
            raise ValueError(f"未知 payload_mode：{mode}，可选值：{allowed}")
        return mode

    def render_replay(
        self,
        *,
        from_checkpoint: str | None = None,
        end_seq_exclusive: int | None = None,
        limit: int | None = 20,
        include_payload: bool = False,
        payload_mode: ReplayPayloadMode = "repr",
    ) -> list[str]:
        """把 replay trace 渲染为可读文本。"""
        normalized_payload_mode = self._normalize_replay_payload_mode(payload_mode)
        trace = self.slice_to_here(from_checkpoint=from_checkpoint)
        if end_seq_exclusive is not None:
            trace = tuple(event for event in trace if event.seq < end_seq_exclusive)
        if limit is not None:
            if limit < 0:
                raise ValueError("limit 不能小于 0")
            trace = trace[-limit:]

        header = (
            f"[Replay] events={len(trace)} cursor={self.replay.cursor_seq} "
            f"checkpoints={len(self.replay.checkpoints)}"
        )
        if from_checkpoint is not None:
            header += f" from={from_checkpoint}"
        if end_seq_exclusive is not None:
            header += f" end_seq_exclusive={end_seq_exclusive}"
        lines = [header]
        if not trace:
            lines.append("当前 Replay Trace 还没有匹配事件。")
            return lines

        for event in trace:
            parts = [
                f"#{event.seq:04d}",
                event.kind.value,
                f"drop={event.drop}",
            ]
            if event.metadata:
                parts.append(f"meta={self._truncate(repr(dict(event.metadata)), limit=96)}")
            if include_payload and event.payload is not None:
                raw = self.replay.blob_store.get(event.payload)
                if normalized_payload_mode == "hex":
                    payload_text = raw.hex()
                else:
                    payload_text = self._truncate(repr(raw), limit=96)
                parts.append(f"payload={payload_text}")
            elif event.payload is not None:
                ref = event.payload
                parts.append(f"payload_ref={ref.blob_id}/{ref.size}")
            lines.append(" ".join(parts))
        return lines

    def show_replay(
        self,
        *,
        from_checkpoint: str | None = None,
        end_seq_exclusive: int | None = None,
        limit: int | None = 20,
        include_payload: bool = False,
        payload_mode: ReplayPayloadMode = "repr",
        emit: RegistryEmit = "info",
    ) -> list[str]:
        """打印 replay trace，并返回输出文本。"""
        normalized_emit = self._normalize_emit(emit)
        lines = self.render_replay(
            from_checkpoint=from_checkpoint,
            end_seq_exclusive=end_seq_exclusive,
            limit=limit,
            include_payload=include_payload,
            payload_mode=payload_mode,
        )
        emitter = self._resolve_emitter(normalized_emit)
        for line in lines:
            emitter(line)
        return lines

    def append_event(
        self,
        kind: ReplayEventKind | str,
        *,
        payload: bytes | None = None,
        drop: bool = False,
        metadata: dict[str, object] | None = None,
    ) -> ReplayEvent:
        """记录一条 compact replay event。"""
        return self.replay.append_event(
            kind,
            payload=payload,
            drop=drop,
            metadata=metadata or {},
        )

    def checkpoint(
        self,
        name: str,
        *,
        metadata: dict[str, object] | None = None,
    ) -> ReplayCheckpoint:
        """记录 replay checkpoint。"""
        return self.replay.checkpoint(name, metadata=metadata or {})

    def slice_to_here(self, *, from_checkpoint: str | None = None) -> tuple[ReplayEvent, ...]:
        """返回当前 replay trace 的可重放切片。"""
        return self.replay.slice_to_here(from_checkpoint=from_checkpoint)

    def promote_observation_to_fact(
        self,
        observation_name: str,
        *,
        fact_name: str | None = None,
        kind: FactKind = FactKind.DERIVED,
        source: str = "observation.promote",
        confidence: float | None = None,
        domain: RecordDomain | None = None,
        evidence: list[str] | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, object] | None = None,
        overwrite: bool = True,
    ) -> Fact:
        """把 observation 升级为 fact。"""
        observation = self.require_observation(observation_name)
        fact_domain = observation.domain if domain is None else domain
        fact_confidence = observation.confidence if confidence is None else confidence
        fact_tags = list(observation.tags)
        if tags:
            for tag in tags:
                if tag not in fact_tags:
                    fact_tags.append(tag)
        fact_metadata = dict(observation.metadata)
        fact_metadata.update(metadata or {})
        fact_metadata.setdefault("promoted_from", observation_name)
        return self.record_fact(
            fact_name or observation_name,
            observation.value,
            kind=kind,
            domain=fact_domain,
            source=source,
            confidence=fact_confidence,
            evidence=list(evidence or [observation_name]),
            tags=fact_tags,
            metadata=fact_metadata,
            overwrite=overwrite,
        )

    def _update_observation_metadata(
        self,
        observation_name: str,
        *,
        metadata_patch: dict[str, object],
        overwrite: bool = True,
    ) -> Observation:
        observation = self.require_observation(observation_name)
        metadata = dict(observation.metadata)
        metadata.update(metadata_patch)
        return self.record_observation(
            observation.name,
            observation.value,
            kind=observation.kind,
            domain=observation.domain,
            source=observation.source,
            confidence=observation.confidence,
            tags=list(observation.tags),
            metadata=metadata,
            overwrite=overwrite,
        )

    def validate_observation(
        self,
        observation_name: str,
        *,
        session_factory: Callable[[], object],
        executor: ReplayExecutor,
        probe: bytes,
        predicate: Callable[[bytes], bool],
        from_checkpoint: str | None = None,
        end_seq_exclusive: int | None = None,
        promote_to_fact: bool = True,
        fact_name: str | None = None,
        fact_kind: FactKind = FactKind.DERIVED,
        fact_source: str = "observation.verify",
        fact_confidence: float | None = None,
        capture_replay_registry: bool = False,
        replay_registry_layers: Iterable[RegistryLayer] | RegistryLayer = _LAYER_ORDER,
        replay_registry_detail: RegistryDetail = "standard",
        replay_registry_limit: int | None = None,
    ) -> VerificationResult:
        """基于 replay trace 验证 observation，并可选自动晋升 fact。"""
        result = self.run_replay(
            session_factory=session_factory,
            executor=executor,
            probe=probe,
            predicate=predicate,
            from_checkpoint=from_checkpoint,
            end_seq_exclusive=end_seq_exclusive,
            capture_replay_registry=capture_replay_registry,
            replay_registry_layers=replay_registry_layers,
            replay_registry_detail=replay_registry_detail,
            replay_registry_limit=replay_registry_limit,
        )
        self._update_observation_metadata(
            observation_name,
            metadata_patch={
                "verification_status": "passed" if result.ok else "failed",
                "verified_by": result.run_id,
                "verification_reason": result.reason,
                "verification_output_preview": result.output_preview,
            },
        )
        if result.ok and promote_to_fact:
            self.promote_observation_to_fact(
                observation_name,
                fact_name=fact_name,
                kind=fact_kind,
                source=fact_source,
                confidence=fact_confidence,
                metadata={"validated_by": result.run_id},
                overwrite=True,
            )
        return result

    def run_replay(
        self,
        *,
        session_factory: Callable[[], object],
        executor: ReplayExecutor,
        probe: bytes,
        predicate: Callable[[bytes], bool],
        from_checkpoint: str | None = None,
        end_seq_exclusive: int | None = None,
        capture_replay_registry: bool = False,
        replay_registry_layers: Iterable[RegistryLayer] | RegistryLayer = _LAYER_ORDER,
        replay_registry_detail: RegistryDetail = "standard",
        replay_registry_limit: int | None = None,
    ) -> VerificationResult:
        """直接执行 replay + probe，不触发 observation/fact 语义。"""
        trace = self.slice_to_here(from_checkpoint=from_checkpoint)
        if end_seq_exclusive is not None:
            trace = tuple(event for event in trace if event.seq < end_seq_exclusive)
        layers = self._normalize_layers(replay_registry_layers)
        detail = self._normalize_detail(replay_registry_detail)
        return executor.replay(
            trace,
            session_factory=session_factory,
            probe=probe,
            predicate=predicate,
            capture_registry=capture_replay_registry,
            registry_layers=layers,
            registry_detail=detail,
            registry_limit=replay_registry_limit,
        )

    def replay(
        self,
        *,
        session_factory: Callable[[], object],
        executor: ReplayExecutor,
        probe: bytes,
        predicate: Callable[[bytes], bool],
        from_checkpoint: str | None = None,
    ) -> VerificationResult:
        """兼容入口：转发到 run_replay()."""
        return self.run_replay(
            session_factory=session_factory,
            executor=executor,
            probe=probe,
            predicate=predicate,
            from_checkpoint=from_checkpoint,
        )

    @staticmethod
    def _serialize_payload_ref(payload: object | None) -> dict[str, object] | None:
        if payload is None:
            return None
        if not hasattr(payload, "blob_id"):
            return None
        return {
            "blob_id": str(getattr(payload, "blob_id")),
            "sha256": str(getattr(payload, "sha256")),
            "size": int(getattr(payload, "size")),
        }

    @classmethod
    def _serialize_replay_event(cls, event: ReplayEvent) -> dict[str, object]:
        return {
            "seq": event.seq,
            "ts_ns": event.ts_ns,
            "kind": event.kind.value,
            "payload": cls._serialize_payload_ref(event.payload),
            "drop": bool(event.drop),
            "metadata": dict(event.metadata),
        }

    @classmethod
    def _serialize_replay_checkpoint(cls, checkpoint: ReplayCheckpoint) -> dict[str, object]:
        return {
            "name": checkpoint.name,
            "event_seq": checkpoint.event_seq,
            "trace_digest": checkpoint.trace_digest,
            "metadata": dict(checkpoint.metadata),
        }

    def to_dict(self) -> dict[str, object]:
        return {
            "observations": {name: asdict(item) for name, item in self.observations.items()},
            "facts": {name: asdict(item) for name, item in self.facts.items()},
            "artifacts": {name: asdict(item) for name, item in self.artifacts.items()},
            "context": {name: asdict(item) for name, item in self.context.items()},
            "replay": {
                "events": [
                    self._serialize_replay_event(event)
                    for event in self.replay.iter_events()
                ],
                "checkpoints": {
                    name: self._serialize_replay_checkpoint(item)
                    for name, item in self.replay.checkpoints.items()
                },
            },
        }

__all__ = ["EvidenceRegistry"]
