"""Workflow 执行期共享模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Literal, Mapping


def _empty_metadata() -> Mapping[str, object]:
    return MappingProxyType({})


def _freeze_metadata(metadata: Mapping[str, object] | None) -> Mapping[str, object]:
    if not metadata:
        return _empty_metadata()
    return MappingProxyType(dict(metadata))


WorkflowPrimitiveKind = Literal[
    "session_init",
    "send",
    "sendline",
    "expect",
    "recv",
    "checkpoint",
]


@dataclass(slots=True, frozen=True)
class WorkflowCheckpoint:
    """workflow 执行期检查点。"""

    name: str
    source_action: str | None = None
    source_node: str | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class WorkflowPrimitive:
    """runtime 真正消费的 primitive。"""

    kind: WorkflowPrimitiveKind
    payload: object | None = None
    args: tuple[object, ...] = ()
    checkpoint: WorkflowCheckpoint | None = None
    source_action: str | None = None
    source_node: str | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class WorkflowTranscript:
    """可 replay 的 workflow transcript。"""

    entry_action: str
    primitives: tuple[WorkflowPrimitive, ...]
    source_map: Mapping[str, object] = field(default_factory=_empty_metadata)
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "primitives", tuple(self.primitives))
        object.__setattr__(self, "source_map", _freeze_metadata(self.source_map))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class WorkflowStepReceipt:
    """单个 primitive 执行后的回执。"""

    step_index: int
    primitive: WorkflowPrimitive
    success: bool
    response: bytes | None = None
    transport_kind: str | None = None
    checkpoint: WorkflowCheckpoint | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class WorkflowExecutionResult:
    """一次 transcript 执行的聚合结果。"""

    transcript: WorkflowTranscript
    receipts: tuple[WorkflowStepReceipt, ...]
    final_checkpoint: WorkflowCheckpoint | None = None
    source: str = "workflow.execute"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "receipts", tuple(self.receipts))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def total_steps(self) -> int:
        return len(self.receipts)


__all__ = [
    "WorkflowCheckpoint",
    "WorkflowExecutionResult",
    "WorkflowPrimitive",
    "WorkflowPrimitiveKind",
    "WorkflowStepReceipt",
    "WorkflowTranscript",
]
