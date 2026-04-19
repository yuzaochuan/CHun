"""FMT 计划 / 观测相关共享模型。"""

from __future__ import annotations

from types import MappingProxyType
from dataclasses import dataclass, field
from enum import Enum
from typing import Literal, Mapping, TypeAlias

AddressLike: TypeAlias = int | str
ValueLike: TypeAlias = int | str
FmtEndian: TypeAlias = Literal["little", "big"]
FmtTargetOrigin: TypeAlias = Literal["absolute", "symbol"]
FmtValueOrigin: TypeAlias = Literal["literal", "symbol"]
FmtWordSize: TypeAlias = Literal[1, 2, 4, 8]
FmtRenderSpecifier: TypeAlias = Literal["hhn", "hn", "n", "lln"]
FmtExecutionDispatch: TypeAlias = Literal["send", "sendline", "exchange"]


def _empty_metadata() -> Mapping[str, object]:
    return MappingProxyType({})


def _freeze_metadata(metadata: Mapping[str, object]) -> Mapping[str, object]:
    if isinstance(metadata, MappingProxyType):
        return metadata
    return MappingProxyType(dict(metadata))


class FmtWriteStrategy(str, Enum):
    """格式化字符串写入拆分策略。"""

    AUTO = "auto"
    BYTE = "byte"
    SHORT = "short"
    INT = "int"
    PTR = "ptr"
    MIXED = "mixed"


class FmtReadMode(str, Enum):
    """格式化字符串读取模式。"""

    POINTER = "pointer"
    STRING = "string"
    RAW = "raw"


class FmtOffsetProbeMode(str, Enum):
    """offset 探测模式。"""

    SEQUENTIAL = "sequential"
    POSITIONAL_WINDOW = "positional_window"


class FmtTaskPolicy(str, Enum):
    """写入原子如何分组为执行任务。"""

    PACKED = "packed"
    BY_TARGET = "by_target"
    BY_ATOM = "by_atom"


class FmtLayoutPolicy(str, Enum):
    """渲染阶段的 payload 布局策略。"""

    ADDRESSES_FIRST = "addresses_first"
    ADDRESSES_LAST = "addresses_last"
    INTERLEAVED = "interleaved"


class FmtExecutionMethod(str, Enum):
    """fmt task 的执行分发方式。"""

    SEND = "send"
    SENDLINE = "sendline"
    EXCHANGE = "exchange"


@dataclass(slots=True, frozen=True)
class FmtTargetRef:
    """规范化后的写入目标引用。"""

    raw: AddressLike
    address: int
    symbol: str | None = None
    origin: FmtTargetOrigin = "absolute"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def is_symbolic(self) -> bool:
        return self.symbol is not None


@dataclass(slots=True, frozen=True)
class FmtValueRef:
    """规范化后的写入值引用。"""

    raw: ValueLike
    value: int
    symbol: str | None = None
    origin: FmtValueOrigin = "literal"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def is_symbolic(self) -> bool:
        return self.symbol is not None


@dataclass(slots=True, frozen=True)
class FmtOffset:
    """格式化字符串输入 offset 的结构化结果。"""

    index: int
    source: str = "unknown"
    strategy: str = "auto"
    confidence: float = 1.0
    signature: bytes | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def marker(self) -> bytes | None:
        """兼容旧字段名，统一映射到 CHun signature。"""
        return self.signature


@dataclass(slots=True, frozen=True)
class FmtOffsetProbeResult:
    """一次 offset 探测的结构化结果。"""

    index: int | None
    method: FmtOffsetProbeMode
    signature: bytes
    matched_token: str | None = None
    verified: bool = False
    confidence: float = 0.0
    raw_output: bytes = b""
    tokens: tuple[str, ...] = ()
    window_start: int | None = None
    window_end: int | None = None
    sep: bytes = b"."
    source: str = "fmt.probe"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", FmtOffsetProbeMode(self.method))
        object.__setattr__(self, "tokens", tuple(self.tokens))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class FmtLeak:
    """一次 fmt 读操作的结果。"""

    target: FmtTargetRef
    address: int
    size: int | None
    mode: FmtReadMode
    raw: bytes
    decoded: int | bytes | str | None = None
    offset: int | None = None
    source: str = "fmt.read"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class FmtWriteRequest:
    """用户层原始写入意图。"""

    target: FmtTargetRef
    value: FmtValueRef
    value_bits: int | None = None
    strategy: FmtWriteStrategy = FmtWriteStrategy.AUTO
    chunk_width: int | None = None
    note: str | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class FmtWriteAtom:
    """最小独立写入单元。"""

    request_index: int
    piece_index: int
    address: int
    value: int
    width: FmtWordSize
    shift: int = 0
    mask: int | None = None
    order_key: int = 0
    target_symbol: str | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def end_address(self) -> int:
        return self.address + self.width


@dataclass(slots=True, frozen=True)
class FmtWriteTask:
    """一个可独立执行的写入任务。"""

    task_index: int
    atoms: tuple[FmtWriteAtom, ...]
    independent: bool = True
    description: str | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "atoms", tuple(self.atoms))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def total_atoms(self) -> int:
        return len(self.atoms)


@dataclass(slots=True, frozen=True)
class FmtWritePlan:
    """Service 层输出的写入计划。"""

    bits: int
    pointer_size: FmtWordSize
    endian: FmtEndian
    offset: int | None
    strategy: FmtWriteStrategy
    task_policy: FmtTaskPolicy
    requests: tuple[FmtWriteRequest, ...]
    atoms: tuple[FmtWriteAtom, ...]
    tasks: tuple[FmtWriteTask, ...]
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "requests", tuple(self.requests))
        object.__setattr__(self, "atoms", tuple(self.atoms))
        object.__setattr__(self, "tasks", tuple(self.tasks))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def total_atoms(self) -> int:
        return len(self.atoms)

    @property
    def total_tasks(self) -> int:
        return len(self.tasks)

    @property
    def is_blind_safe(self) -> bool:
        return self.task_policy == FmtTaskPolicy.BY_ATOM


@dataclass(slots=True, frozen=True)
class FmtRenderStep:
    """单个 atom 的渲染决策。"""

    task_index: int
    atom: FmtWriteAtom
    arg_index: int
    specifier: FmtRenderSpecifier
    counter_before: int
    counter_after: int
    padding: int
    modulus: int
    address_offset: int | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class RenderedFmtTask:
    """纯函数渲染后的单 task 输出。"""

    task_index: int
    atoms: tuple[FmtWriteAtom, ...]
    steps: tuple[FmtRenderStep, ...]
    payload: bytes
    offset: int
    layout: FmtLayoutPolicy
    initial_counter: int = 0
    final_counter: int = 0
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "atoms", tuple(self.atoms))
        object.__setattr__(self, "steps", tuple(self.steps))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class FmtExecutionReceipt:
    """一次 fmt task 执行后的结构化回执。"""

    task_index: int
    rendered: RenderedFmtTask
    payload: bytes
    offset: int
    transport_kind: str
    dispatch: FmtExecutionMethod
    response: bytes | None = None
    source: str = "fmt.execute"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "dispatch", FmtExecutionMethod(self.dispatch))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


__all__ = [
    "AddressLike",
    "FmtEndian",
    "FmtExecutionDispatch",
    "FmtExecutionMethod",
    "FmtExecutionReceipt",
    "FmtOffsetProbeMode",
    "FmtOffsetProbeResult",
    "FmtLayoutPolicy",
    "FmtRenderSpecifier",
    "FmtRenderStep",
    "FmtLeak",
    "FmtOffset",
    "FmtReadMode",
    "FmtTargetOrigin",
    "FmtTargetRef",
    "FmtTaskPolicy",
    "FmtValueOrigin",
    "FmtValueRef",
    "FmtWordSize",
    "FmtWriteAtom",
    "FmtWritePlan",
    "FmtWriteRequest",
    "FmtWriteStrategy",
    "FmtWriteTask",
    "RenderedFmtTask",
    "ValueLike",
]
