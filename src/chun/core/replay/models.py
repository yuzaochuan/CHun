"""Compact replay trace 的核心模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


def _empty_metadata() -> Mapping[str, object]:
    return MappingProxyType({})


def _freeze_metadata(metadata: Mapping[str, object] | None) -> Mapping[str, object]:
    if not metadata:
        return _empty_metadata()
    if isinstance(metadata, MappingProxyType):
        return metadata
    return MappingProxyType(dict(metadata))


class ReplayEventKind(str, Enum):
    SPAWN = "spawn"
    SEND = "send"
    SENDLINE = "sendline"
    EXPECT = "expect"
    CHECKPOINT = "checkpoint"


@dataclass(slots=True, frozen=True)
class PayloadRef:
    blob_id: str
    sha256: str
    size: int


@dataclass(slots=True, frozen=True)
class ReplayEvent:
    seq: int
    ts_ns: int
    kind: ReplayEventKind
    payload: PayloadRef | None = None
    drop: bool = False
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", ReplayEventKind(self.kind))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class ReplayCheckpoint:
    name: str
    event_seq: int
    trace_digest: str
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class VerificationRun:
    run_id: str
    trace_start_seq: int
    trace_end_seq: int
    probe: PayloadRef
    started_ns: int
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class VerificationResult:
    run_id: str
    ok: bool
    reason: str
    output_preview: bytes = b""
    completed_ns: int = 0
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


__all__ = [
    "PayloadRef",
    "ReplayCheckpoint",
    "ReplayEvent",
    "ReplayEventKind",
    "VerificationResult",
    "VerificationRun",
]
