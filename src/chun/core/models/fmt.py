"""FMT 计划 / 观测相关共享模型。"""

from __future__ import annotations

from types import MappingProxyType
from dataclasses import dataclass, field
from string import printable
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


class FmtResultKind(str, Enum):
    """fmt 聚合结果类型。"""

    READ = "read"
    WRITE = "write"
    EXECUTION = "execution"


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
    data_offset: int | None
    backend: str
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
    fmt_bytes: bytes
    data_bytes: bytes
    payload: bytes
    offset: int
    data_offset: int | None
    backend: str
    layout: FmtLayoutPolicy
    initial_counter: int = 0
    final_counter: int = 0
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "atoms", tuple(self.atoms))
        object.__setattr__(self, "steps", tuple(self.steps))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class FmtWriteCandidate:
    """单一 strategy 下的写入候选。"""

    strategy: FmtWriteStrategy
    plan: FmtWritePlan | None = None
    rendered_tasks: tuple[RenderedFmtTask, ...] = ()
    error: str | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rendered_tasks", tuple(self.rendered_tasks))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def atom_count(self) -> int:
        return 0 if self.plan is None else self.plan.total_atoms

    @property
    def task_count(self) -> int:
        return 0 if self.plan is None else self.plan.total_tasks

    @property
    def total_payload_len(self) -> int:
        return sum(len(item.payload) for item in self.rendered_tasks)

    @property
    def max_padding(self) -> int:
        values = [
            int(step.padding)
            for rendered in self.rendered_tasks
            for step in rendered.steps
        ]
        return max(values, default=0)

    @property
    def pad_time(self) -> str:
        max_pad = self.max_padding
        if max_pad < 0x100:
            return "LOW"
        if max_pad < 0x1000:
            return "MEDIUM"
        if max_pad < 0x10000:
            return "HIGH"
        return "EXTREME"

    @property
    def data_offsets(self) -> tuple[int | None, ...]:
        return tuple(item.data_offset for item in self.rendered_tasks)

    @property
    def payloads(self) -> tuple[bytes, ...]:
        return tuple(item.payload for item in self.rendered_tasks)

    def total_send_len(self, end: bytes | None = None) -> int:
        suffix_len = len(end or b"")
        return sum(len(item.payload) + suffix_len for item in self.rendered_tasks)


@dataclass(slots=True, frozen=True)
class FmtWriteComparison:
    """同一写请求在多种 strategy 下的对照结果。"""

    target: FmtTargetRef
    value: FmtValueRef
    candidates: tuple[FmtWriteCandidate, ...]
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    def __str__(self) -> str:
        buflen = self.metadata.get("buflen")
        show_hex = bool(self.metadata.get("show_hex", False))
        end = self.metadata.get("end")
        if isinstance(end, str):
            end_bytes = end.encode("latin-1", errors="replace")
        elif isinstance(end, bytes):
            end_bytes = end
        else:
            end_bytes = None

        lines = [
            "[FMT] "
            f"target={hex(self.target.address)} "
            f"value={hex(self.value.value)} "
            f"end={repr(end_bytes if end_bytes is not None else None)} "
            f"buflen={buflen}",
        ]
        for candidate in self.candidates:
            status = self._status_icon(
                candidate=candidate,
                buflen=buflen if isinstance(buflen, int) else None,
                end=end_bytes,
            )
            if not candidate.ok:
                lines.append(f"◆ {candidate.strategy.value.upper()}   {status}")
                lines.append(f"  error    {candidate.error}")
                continue
            data_offsets = ",".join(
                "?" if item is None else str(item) for item in candidate.data_offsets
            )
            duplicate_note = self._duplicate_note(candidate)
            first_line = f"◆ {candidate.strategy.value.upper()}   {status}"
            if duplicate_note:
                first_line += f"   {duplicate_note}"
            lines.append(first_line)
            lines.append(
                "  "
                f"atoms {candidate.atom_count}   "
                f"send {candidate.total_send_len(end_bytes)}B   "
                f"data@{data_offsets}"
            )
            lines.append(
                "  "
                f"max_pad {candidate.max_padding}   "
                f"pad_time {candidate.pad_time}"
            )
            for index, rendered in enumerate(candidate.rendered_tasks):
                if candidate.task_count > 1:
                    lines.append(f"  task[{index}]")
                lines.append("    fmt")
                lines.append(f"      {rendered.fmt_bytes!r}")
                lines.append("    payload")
                lines.append(f"      {rendered.payload!r}")
                if show_hex:
                    send_bytes = rendered.payload + (end_bytes or b"")
                    lines.append("    send.hex")
                    lines.extend(self._format_hexdump(send_bytes, indent="      "))
        return "\n".join(lines)

    def _duplicate_note(self, candidate: FmtWriteCandidate) -> str | None:
        if not candidate.ok:
            return None
        for other in self.candidates:
            if other is candidate or not other.ok:
                continue
            if candidate.payloads == other.payloads:
                return f"same as {other.strategy.value.upper()}"
        return None

    @staticmethod
    def _status_icon(
        *,
        candidate: FmtWriteCandidate,
        buflen: int | None,
        end: bytes | None,
    ) -> str:
        if not candidate.ok:
            return "❌"
        if candidate.pad_time == "EXTREME":
            return "❌"
        if buflen is None:
            return "❔"
        return "✅" if candidate.total_send_len(end) <= buflen else "❌"

    @staticmethod
    def _format_hexdump(data: bytes, *, indent: str) -> list[str]:
        lines = [f"{indent}[CHun.fmt] Sent 0x{len(data):x} bytes:"]
        for offset in range(0, len(data), 16):
            chunk = data[offset : offset + 16]
            hex_pairs = [f"{byte:02x}" for byte in chunk]
            hex_groups = [" ".join(hex_pairs[index : index + 4]) for index in range(0, 16, 4)]
            while len(hex_groups) < 4:
                hex_groups.append("")
            hex_part = "  ".join(f"{group:<11}" for group in hex_groups).rstrip()
            ascii_groups = []
            for index in range(0, len(chunk), 4):
                ascii_chunk = chunk[index : index + 4]
                ascii_groups.append("".join(FmtWriteComparison._hexdump_char(byte) for byte in ascii_chunk))
            ascii_part = "│".join(f"{group:<4}" for group in ascii_groups)
            lines.append(
                f"{indent}    {offset:08x}  {hex_part:<53}  │{ascii_part}│"
            )
        return lines

    @staticmethod
    def _hexdump_char(byte: int) -> str:
        ch = chr(byte)
        if ch in printable and ch not in "\r\n\t\x0b\x0c":
            return ch
        return "·"


@dataclass(slots=True, frozen=True)
class FmtWritesComparison:
    """同一批写请求在多种 strategy 下的对照结果。"""

    requests: tuple[FmtWriteRequest, ...]
    candidates: tuple[FmtWriteCandidate, ...]
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "requests", tuple(self.requests))
        object.__setattr__(self, "candidates", tuple(self.candidates))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    def __str__(self) -> str:
        buflen = self.metadata.get("buflen")
        show_hex = bool(self.metadata.get("show_hex", False))
        end = self.metadata.get("end")
        if isinstance(end, str):
            end_bytes = end.encode("latin-1", errors="replace")
        elif isinstance(end, bytes):
            end_bytes = end
        else:
            end_bytes = None

        request_preview = ", ".join(
            f"{hex(request.target.address)}<-{hex(request.value.value)}"
            for request in self.requests[:3]
        )
        if len(self.requests) > 3:
            request_preview += ", ..."
        lines = [
            "[FMT.writes] "
            f"requests={len(self.requests)} "
            f"writes=[{request_preview}] "
            f"end={repr(end_bytes if end_bytes is not None else None)} "
            f"buflen={buflen}",
        ]
        for candidate in self.candidates:
            status = FmtWriteComparison._status_icon(
                candidate=candidate,
                buflen=buflen if isinstance(buflen, int) else None,
                end=end_bytes,
            )
            if not candidate.ok:
                lines.append(f"◆ {candidate.strategy.value.upper()}   {status}")
                lines.append(f"  error {candidate.error}")
                continue
            data_offsets = ",".join(
                "?" if item is None else str(item) for item in candidate.data_offsets
            )
            duplicate_note = self._duplicate_note(candidate)
            first_line = f"◆ {candidate.strategy.value.upper()}   {status}"
            if duplicate_note:
                first_line += f"   {duplicate_note}"
            lines.append(first_line)
            lines.append(
                "  "
                f"atoms {candidate.atom_count}   "
                f"tasks {candidate.task_count}   "
                f"send {candidate.total_send_len(end_bytes)}B   "
                f"data@{data_offsets}"
            )
            lines.append(
                "  "
                f"max_pad {candidate.max_padding}   "
                f"pad_time {candidate.pad_time}"
            )
            for index, rendered in enumerate(candidate.rendered_tasks):
                prefix = f"  task[{index}] " if candidate.task_count > 1 else "  "
                lines.append(f"{prefix}fmt {rendered.fmt_bytes!r}")
                lines.append(f"{prefix}payload {rendered.payload!r}")
                if show_hex:
                    send_bytes = rendered.payload + (end_bytes or b"")
                    lines.append(f"{prefix}send.hex")
                    lines.extend(
                        FmtWriteComparison._format_hexdump(send_bytes, indent="      ")
                    )
        return "\n".join(lines)

    def _duplicate_note(self, candidate: FmtWriteCandidate) -> str | None:
        if not candidate.ok:
            return None
        for other in self.candidates:
            if other is candidate or not other.ok:
                continue
            if candidate.payloads == other.payloads:
                return f"same as {other.strategy.value.upper()}"
        return None


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


@dataclass(slots=True, frozen=True)
class FmtExecutionResult:
    """一次完整 fmt 写执行的聚合结果。"""

    kind: FmtResultKind
    plan: FmtWritePlan
    receipts: tuple[FmtExecutionReceipt, ...]
    offset: int
    result_prefix: str = "fmt.exec"
    source: str = "fmt.execute_plan"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "kind", FmtResultKind(self.kind))
        object.__setattr__(self, "receipts", tuple(self.receipts))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def total_tasks(self) -> int:
        return len(self.receipts)

    @property
    def task_indexes(self) -> tuple[int, ...]:
        return tuple(receipt.task_index for receipt in self.receipts)

    @property
    def responses(self) -> tuple[bytes | None, ...]:
        return tuple(receipt.response for receipt in self.receipts)


__all__ = [
    "AddressLike",
    "FmtEndian",
    "FmtExecutionResult",
    "FmtExecutionDispatch",
    "FmtExecutionMethod",
    "FmtExecutionReceipt",
    "FmtOffsetProbeMode",
    "FmtOffsetProbeResult",
    "FmtResultKind",
    "FmtWriteCandidate",
    "FmtWriteComparison",
    "FmtWritesComparison",
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
