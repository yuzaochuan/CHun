"""Action IR 共享模型。"""

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


@dataclass(slots=True, frozen=True)
class SourceSpan:
    """源码跨度信息。"""

    lineno: int
    end_lineno: int
    col_offset: int = 0
    end_col_offset: int = 0


@dataclass(slots=True, frozen=True)
class ImportRef:
    """单条 import 引用。"""

    module: str | None
    name: str
    alias: str | None = None
    level: int = 0
    kind: Literal["import", "from"] = "import"
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class ImportModel:
    """模块 import 区域。"""

    refs: tuple[ImportRef, ...]
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "refs", tuple(self.refs))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class LiteralNode:
    """字面值节点。"""

    value: object
    value_type: str
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class NameRefNode:
    """变量引用节点。"""

    name: str
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class ExprNode:
    """纯表达式调用节点。"""

    kind: str
    callee: str
    args: tuple[object, ...] = ()
    keywords: Mapping[str, object] = field(default_factory=_empty_metadata)
    effect: Literal["pure"] = "pure"
    evaluated: bool = False
    resolved_value: object | None = None
    value_type: str | None = None
    value_summary: Mapping[str, object] = field(default_factory=_empty_metadata)
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "keywords", _freeze_metadata(self.keywords))
        object.__setattr__(self, "value_summary", _freeze_metadata(self.value_summary))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class PrimitiveNode:
    """底层 IO 原语节点。"""

    kind: str
    payload: object | None = None
    args: tuple[object, ...] = ()
    keywords: Mapping[str, object] = field(default_factory=_empty_metadata)
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "keywords", _freeze_metadata(self.keywords))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class CallNode:
    """当前模块 ActionDef 间的调用边。"""

    callee: str
    args: tuple[object, ...] = ()
    keywords: Mapping[str, object] = field(default_factory=_empty_metadata)
    assign_to: str | None = None
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "keywords", _freeze_metadata(self.keywords))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class AnalysisNode:
    """推断/分析调用节点。"""

    callee: str
    args: tuple[object, ...] = ()
    keywords: Mapping[str, object] = field(default_factory=_empty_metadata)
    replayable: bool = False
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "keywords", _freeze_metadata(self.keywords))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class OpaqueCallNode:
    """当前无法稳定翻译的调用节点。"""

    callee: str
    args: tuple[object, ...] = ()
    keywords: Mapping[str, object] = field(default_factory=_empty_metadata)
    reason: str = "unsupported"
    replayable: bool = False
    expandable: bool = False
    truncated: bool = False
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "keywords", _freeze_metadata(self.keywords))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class RecursiveCallNode:
    """递归或循环调用占位节点。"""

    callee: str
    cycle: tuple[str, ...]
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "cycle", tuple(self.cycle))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class AssignNode:
    """赋值语句节点。"""

    target: str
    value: object
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class FunctionActionDef:
    """当前模块内的函数级 ActionDef。"""

    action_id: str
    qualname: str
    params: tuple[str, ...]
    body: tuple[object, ...]
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "params", tuple(self.params))
        object.__setattr__(self, "body", tuple(self.body))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class TopLevelBlockDef:
    """定义之间的顶层可执行块。"""

    block_id: str
    body: tuple[object, ...]
    source_span: SourceSpan | None = None
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "body", tuple(self.body))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))


@dataclass(slots=True, frozen=True)
class ExpActionIR:
    """整个 exploit 文件的 Action IR。"""

    module_name: str
    imports: ImportModel
    functions: tuple[FunctionActionDef, ...]
    top_level_blocks: tuple[TopLevelBlockDef, ...]
    entrypoints: tuple[str, ...]
    source: str
    filename: str = "<memory>"
    metadata: Mapping[str, object] = field(default_factory=_empty_metadata)

    def __post_init__(self) -> None:
        object.__setattr__(self, "functions", tuple(self.functions))
        object.__setattr__(self, "top_level_blocks", tuple(self.top_level_blocks))
        object.__setattr__(self, "entrypoints", tuple(self.entrypoints))
        object.__setattr__(self, "metadata", _freeze_metadata(self.metadata))

    @property
    def action_map(self) -> Mapping[str, object]:
        mapping: dict[str, object] = {}
        for block in self.top_level_blocks:
            mapping[block.block_id] = block
        for func in self.functions:
            mapping[func.action_id] = func
        return MappingProxyType(mapping)


__all__ = [
    "AnalysisNode",
    "AssignNode",
    "CallNode",
    "ExpActionIR",
    "ExprNode",
    "FunctionActionDef",
    "ImportModel",
    "ImportRef",
    "LiteralNode",
    "NameRefNode",
    "OpaqueCallNode",
    "PrimitiveNode",
    "RecursiveCallNode",
    "SourceSpan",
    "TopLevelBlockDef",
]
