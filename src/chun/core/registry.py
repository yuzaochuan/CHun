"""统一情报中心（Registry）。

所有模块拿到的泄漏值、推导出的 base、以及补充元数据都应汇总到这里。
这样可以避免“脚本越写越大后，状态散落在各个对象里”的问题。
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Iterator, Mapping

from ..utils.display import print_registry_snapshot


class RecordKind(str, Enum):
    """Registry 里记录项的语义类型。"""

    GENERIC = "generic"
    LEAK = "leak"
    BASE = "base"
    LIBC_SYMBOL = "libc-symbol"
    PIE_RET = "pie-ret"
    STACK_PTR = "stack"
    HEAP_PTR = "heap"
    FMT_OFFSET_HIT = "fmt-offset-hit"


class RecordSource(str, Enum):
    """记录来源，用于追踪可信度。"""

    MANUAL = "manual"
    BLIND_FMT = "blind-fmt"
    LOCAL_ELF = "local-elf"
    GDB_SYNC = "gdb-sync"
    LIBC_SEARCHER = "libc-searcher"
    DERIVED = "derived"


class AddressClass(str, Enum):
    """地址归属的启发式分类（提示用，不是绝对真相）。"""

    TEXT_NON_PIE = "text-non-pie"
    PIE_LIKE = "pie-like"
    LIBC_LIKE = "libc-like"
    STACK_LIKE = "stack-like"
    HEAP_LIKE = "heap-like"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class AddressRecord:
    """一条地址情报记录。"""

    name: str
    value: int
    kind: RecordKind = RecordKind.LEAK
    source: RecordSource = RecordSource.MANUAL
    confidence: float = 0.50
    notes: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(slots=True)
class BaseCandidate:
    """`infer_base()` 产出的候选 base（带评分）。"""

    base_name: str
    raw_base: int
    aligned_base: int
    score: float
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class BaseRecord:
    """通过阈值后正式入库的 base 记录。"""

    name: str
    base: int
    source: RecordSource = RecordSource.DERIVED
    confidence: float = 0.50
    derived_from: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def _clamp_confidence(value: float) -> float:
    """把置信度限制在 ``[0.0, 1.0]`` 区间。"""
    return max(0.0, min(1.0, value))


class PwnRegistry:
    """Pwn 场景下的统一状态中心。"""

    def __init__(self, page_size: int = 0x1000, accept_score: float = 0.55) -> None:
        """初始化空 Registry。"""
        self.page_size = page_size
        self.accept_score = accept_score
        self._records: dict[str, AddressRecord] = {}
        self._bases: dict[str, BaseRecord] = {}
        self._misc: dict[str, Any] = {}

    @staticmethod
    def _coerce_kind(kind: RecordKind | str) -> RecordKind:
        """把外部传入的 kind 归一化为 ``RecordKind``。"""
        if isinstance(kind, RecordKind):
            return kind
        for enum_value in RecordKind:
            if kind == enum_value.value:
                return enum_value
        return RecordKind.GENERIC

    @staticmethod
    def _coerce_source(source: RecordSource | str) -> RecordSource:
        """把外部传入的 source 归一化为 ``RecordSource``。"""
        if isinstance(source, RecordSource):
            return source
        for enum_value in RecordSource:
            if source == enum_value.value:
                return enum_value
        return RecordSource.MANUAL

    def add_record(self, record: AddressRecord) -> AddressRecord:
        """插入或覆盖一条地址记录。"""
        record.confidence = _clamp_confidence(record.confidence)
        self._records[record.name] = record
        return record

    def add_address(
        self,
        name: str,
        value: int,
        kind: RecordKind | str = RecordKind.LEAK,
        source: RecordSource | str = RecordSource.MANUAL,
        confidence: float = 0.50,
        notes: str = "",
        meta: Mapping[str, Any] | None = None,
    ) -> AddressRecord:
        """添加一条 typed 地址记录。"""
        record = AddressRecord(
            name=name,
            value=value,
            kind=self._coerce_kind(kind),
            source=self._coerce_source(source),
            confidence=_clamp_confidence(confidence),
            notes=notes,
            meta=dict(meta or {}),
        )
        return self.add_record(record)

    def add_log(self, name: str | None = None, value: Any = None, **kwargs: Any) -> None:
        """兼容历史 `my_tools.py` 风格的加记录接口。"""
        if name is not None and value is not None:
            self._add_any_value(str(name), value)

        for key, item in kwargs.items():
            self._add_any_value(key, item)

    def _add_any_value(self, key: str, item: Any) -> None:
        """整数写入地址表，其他值写入 misc。"""
        if isinstance(item, int):
            self.add_address(name=key, value=item, kind=RecordKind.LEAK)
        else:
            self._misc[key] = item

    def add_base(
        self,
        name: str,
        base: int,
        source: RecordSource | str = RecordSource.DERIVED,
        confidence: float = 0.50,
        derived_from: str = "",
        meta: Mapping[str, Any] | None = None,
    ) -> BaseRecord:
        """入库一条 base，同时镜像成地址记录方便统一查看。"""
        base_record = BaseRecord(
            name=name,
            base=base,
            source=self._coerce_source(source),
            confidence=_clamp_confidence(confidence),
            derived_from=derived_from,
            meta=dict(meta or {}),
        )
        self._bases[name] = base_record
        self.add_address(
            name=f"{name}_base",
            value=base,
            kind=RecordKind.BASE,
            source=base_record.source,
            confidence=base_record.confidence,
            notes=f"由 {derived_from} 推导" if derived_from else "Base 记录",
            meta={"base_name": name, **base_record.meta},
        )
        return base_record

    def get_record(self, name: str) -> AddressRecord | None:
        """按名称读取地址记录。"""
        return self._records.get(name)

    def get_base(self, name: str) -> BaseRecord | None:
        """按名称读取 base 记录。"""
        return self._bases.get(name)

    def get_value(self, name: str, default: Any = None) -> Any:
        """优先从地址记录读取值，找不到再查 misc。"""
        record = self.get_record(name)
        if record is not None:
            return record.value
        return self._misc.get(name, default)

    def iter_records(self) -> Iterator[AddressRecord]:
        """按插入顺序遍历地址记录。"""
        return iter(self._records.values())

    def iter_bases(self) -> Iterator[BaseRecord]:
        """按插入顺序遍历 base 记录。"""
        return iter(self._bases.values())

    def classify_address(self, value: int) -> AddressClass:
        """按常见 Linux 映射区间对地址做启发式分类。"""
        if value <= 0:
            return AddressClass.UNKNOWN

        if 0x08048000 <= value <= 0x09000000:
            return AddressClass.TEXT_NON_PIE

        if 0x0000550000000000 <= value <= 0x000055FFFFFFFFFF:
            return AddressClass.PIE_LIKE

        if 0x00007F0000000000 <= value <= 0x00007FFEFFFFFFFF:
            return AddressClass.LIBC_LIKE

        if 0x00007FFF00000000 <= value <= 0x00007FFFFFFFFFFF:
            return AddressClass.STACK_LIKE

        if 0x0000560000000000 <= value <= 0x000056FFFFFFFFFF:
            return AddressClass.HEAP_LIKE

        return AddressClass.UNKNOWN

    def infer_base(
        self,
        leak_name: str,
        symbol_offset: int,
        base_name: str | None = None,
        source: RecordSource | str = RecordSource.DERIVED,
        min_accept_score: float | None = None,
        store: bool = True,
    ) -> BaseCandidate:
        """根据“泄漏地址 + 已知偏移”推导候选 base，并进行评分。

        当前评分因子：
        1. 页对齐质量
        2. 地址区间合理性
        3. 泄漏来源置信度继承
        4. 与已存在 base 的一致性/冲突
        """
        record = self.get_record(leak_name)
        if record is None:
            raise KeyError(f"找不到记录：{leak_name}")
        if symbol_offset < 0:
            raise ValueError("symbol_offset 不能为负数")

        inferred_name = base_name or f"{leak_name}.inferred"
        raw_base = record.value - symbol_offset
        aligned_base = raw_base & ~(self.page_size - 1)

        reasons: list[str] = []
        score = 0.0

        if raw_base == aligned_base:
            score += 0.20
            reasons.append("原始 base 已按页对齐 (+0.20)")
        else:
            score += 0.12
            reasons.append("原始 base 向下页对齐 (+0.12)")

        addr_class = self.classify_address(aligned_base)
        if addr_class in {
            AddressClass.PIE_LIKE,
            AddressClass.LIBC_LIKE,
            AddressClass.TEXT_NON_PIE,
        }:
            score += 0.25
            reasons.append(f"落在较可信地址区间：{addr_class.value} (+0.25)")
        elif addr_class in {AddressClass.STACK_LIKE, AddressClass.HEAP_LIKE}:
            score += 0.10
            reasons.append(f"落在弱可信地址区间：{addr_class.value} (+0.10)")
        else:
            score += 0.04
            reasons.append("地址区间未知，仅给弱先验 (+0.04)")

        source_bonus = 0.10 * record.confidence
        score += source_bonus
        reasons.append(f"继承泄漏来源置信度 (+{source_bonus:.2f})")

        existing = self.get_base(inferred_name)
        if existing is not None:
            if existing.base == aligned_base:
                score += 0.35
                reasons.append("与已确认 base 一致 (+0.35)")
            else:
                score -= 0.50
                reasons.append("与已确认 base 冲突 (-0.50)")

        score = _clamp_confidence(score)
        candidate = BaseCandidate(
            base_name=inferred_name,
            raw_base=raw_base,
            aligned_base=aligned_base,
            score=score,
            reasons=reasons,
        )

        threshold = min_accept_score if min_accept_score is not None else self.accept_score
        if store and score >= threshold:
            self.add_base(
                name=inferred_name,
                base=aligned_base,
                source=source,
                confidence=score,
                derived_from=leak_name,
                meta={
                    "symbol_offset": symbol_offset,
                    "raw_base": raw_base,
                    "address_class": addr_class.value,
                },
            )
        return candidate

    def derive_base(
        self,
        leak_name: str,
        symbol_offset: int,
        base_name: str | None = None,
        source: RecordSource | str = RecordSource.DERIVED,
    ) -> BaseCandidate:
        """`infer_base()` 的便捷别名。"""
        return self.infer_base(
            leak_name=leak_name,
            symbol_offset=symbol_offset,
            base_name=base_name,
            source=source,
            store=True,
        )

    def puts_log(self) -> None:
        """按分组打印 Registry 快照，适合打题时快速看全局状态。"""
        address_rows = [
            (
                record.name,
                record.value,
                record.kind.value,
                record.source.value,
                record.confidence,
            )
            for record in self._records.values()
        ]
        base_rows = [
            (base.name, base.base, base.source.value, base.confidence)
            for base in self._bases.values()
        ]
        misc_rows = list(self._misc.items())

        print_registry_snapshot(address_rows, base_rows, misc_rows)

    def to_dict(self) -> dict[str, Any]:
        """导出当前快照为普通字典，便于序列化/调试。"""
        return {
            "records": {name: asdict(record) for name, record in self._records.items()},
            "bases": {name: asdict(base) for name, base in self._bases.items()},
            "misc": dict(self._misc),
        }

    def __len__(self) -> int:
        """返回 Registry 总键数量。"""
        return len(self._records) + len(self._bases) + len(self._misc)

    def __contains__(self, key: str) -> bool:
        """支持 `in` 判断，覆盖 record/base/misc 三个区域。"""
        return key in self._records or key in self._bases or key in self._misc

    def names(self) -> Iterable[str]:
        """遍历所有已知键名。"""
        yield from self._records.keys()
        yield from self._bases.keys()
        yield from self._misc.keys()


Reg = PwnRegistry


__all__ = [
    "AddressClass",
    "AddressRecord",
    "BaseCandidate",
    "BaseRecord",
    "PwnRegistry",
    "RecordKind",
    "RecordSource",
    "Reg",
]
