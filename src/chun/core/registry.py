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


_ADD_LOG_META_KEYS = frozenset({"kind", "source", "confidence", "notes", "meta"})


class RecordKind(str, Enum):
    """Registry 里记录项的语义类型。"""

    GENERIC = "generic"  # 通用记录：暂未细分语义的普通条目。
    LEAK = "leak"  # 地址泄漏：手工或脚本拿到的原始地址值。
    BASE = "base"  # 基址记录：已经确认可作为模块基址使用的地址。
    LIBC_SYMBOL = "libc-symbol"  # libc 符号泄漏：如 puts/system/_IO_2_1_stderr_。
    PIE_RET = "pie-ret"  # PIE 返回地址：常见于栈泄漏里拿到的代码段返回地址。
    STACK_PTR = "stack"  # 栈指针：明显位于栈区的地址或栈扫描命中结果。
    HEAP_PTR = "heap"  # 堆指针：明显位于堆区的地址或堆块相关泄漏。
    FMT_OFFSET_HIT = "fmt-offset-hit"  # FMT 偏移命中：定位到输入 offset 的结果。


class RecordSource(str, Enum):
    """记录来源，用于追踪可信度。"""

    MANUAL = "manual"  # 人工录入：脚本作者显式登记的结果。
    BLIND_FMT = "blind-fmt"  # blind fmt：通过盲打格式化字符串探测得到。
    LOCAL_ELF = "local-elf"  # 本地 ELF：来自本地二进制/符号表/静态信息。
    GDB_SYNC = "gdb-sync"  # GDB 同步：调试期间人工确认后写回。
    LIBC_SEARCHER = "libc-searcher"  # LibcSearcher：由外部库匹配得到。
    DERIVED = "derived"  # 推导结果：由已有记录进一步计算得到。


class AddressClass(str, Enum):
    """地址归属的启发式分类（提示用，不是绝对真相）。"""

    TEXT_NON_PIE = "text-non-pie"  # 非 PIE 代码段：典型 32 位/固定装载 text 地址。
    PIE_LIKE = "pie-like"  # PIE 风格地址：常见于 0x55... 附近的主程序映射。
    LIBC_LIKE = "libc-like"  # libc 风格地址：常见于 0x7f... 的共享库映射。
    STACK_LIKE = "stack-like"  # 栈风格地址：高地址、接近用户态栈区。
    HEAP_LIKE = "heap-like"  # 堆风格地址：常见于 0x56... 一类 heap 映射。
    UNKNOWN = "unknown"  # 未知类型：暂时无法可靠归类的地址。


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
        """兼容历史 `my_tools.py` 风格的加记录接口。

        兼容两类用法：

        - 旧风格：`add_log("puts@libc", leak)` / `add_log(note="warmup")`
        - 增强风格：`add_log("puts@libc", leak, kind=..., source=..., confidence=...)`

        当且仅当能明确定位到“一条记录”时，`kind/source/confidence/notes/meta`
        这些元字段才会被解释为记录元信息；其他情况仍按历史逻辑写入。
        """
        meta_kwargs = self._extract_add_log_meta(kwargs)
        data_kwargs = {key: item for key, item in kwargs.items() if key not in _ADD_LOG_META_KEYS}

        if name is not None and value is not None:
            self._add_any_value(str(name), value, **meta_kwargs)

        if meta_kwargs and name is None and len(data_kwargs) == 1:
            key, item = next(iter(data_kwargs.items()))
            self._add_any_value(key, item, **meta_kwargs)
            return

        for key, item in kwargs.items():
            if key in _ADD_LOG_META_KEYS and meta_kwargs:
                continue
            self._add_any_value(key, item)

    @staticmethod
    def _extract_add_log_meta(kwargs: Mapping[str, Any]) -> dict[str, Any]:
        """从 `add_log()` 的关键字参数中提取元信息字段。"""
        meta_kwargs: dict[str, Any] = {}
        for key in _ADD_LOG_META_KEYS:
            if key in kwargs:
                meta_kwargs[key] = kwargs[key]
        return meta_kwargs

    def _add_any_value(self, key: str, item: Any, **meta_kwargs: Any) -> None:
        """整数写入地址表，其他值写入 misc。"""
        if isinstance(item, int):
            self.add_address(
                name=key,
                value=item,
                kind=meta_kwargs.get("kind", RecordKind.LEAK),
                source=meta_kwargs.get("source", RecordSource.MANUAL),
                confidence=meta_kwargs.get("confidence", 0.50),
                notes=meta_kwargs.get("notes", ""),
                meta=meta_kwargs.get("meta"),
            )
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

    @staticmethod
    def _expected_base_classes(
        leak_name: str,
        record_kind: RecordKind,
    ) -> set[AddressClass]:
        """根据记录语义猜测更可能出现的基址类型。"""
        expected = PwnRegistry._expected_base_classes_from_kind(record_kind)
        expected.update(PwnRegistry._expected_base_classes_from_name(leak_name))
        return expected

    @staticmethod
    def _expected_base_classes_from_kind(record_kind: RecordKind) -> set[AddressClass]:
        """优先依据记录类型判断更可能出现的基址类型。"""
        expected: set[AddressClass] = set()

        if record_kind == RecordKind.LIBC_SYMBOL:
            expected.add(AddressClass.LIBC_LIKE)

        if record_kind == RecordKind.PIE_RET:
            expected.update({AddressClass.PIE_LIKE, AddressClass.TEXT_NON_PIE})

        if record_kind == RecordKind.STACK_PTR:
            expected.add(AddressClass.STACK_LIKE)

        if record_kind == RecordKind.HEAP_PTR:
            expected.add(AddressClass.HEAP_LIKE)

        return expected

    @staticmethod
    def _expected_base_classes_from_name(leak_name: str) -> set[AddressClass]:
        """从键名里提取弱语义线索，只作补充，不替代 kind。"""
        name = leak_name.lower()
        expected: set[AddressClass] = set()

        if "libc" in name:
            expected.add(AddressClass.LIBC_LIKE)

        if "pie" in name or "@elf" in name:
            expected.update({AddressClass.PIE_LIKE, AddressClass.TEXT_NON_PIE})

        if "stack" in name:
            expected.add(AddressClass.STACK_LIKE)

        if "heap" in name:
            expected.add(AddressClass.HEAP_LIKE)

        return expected

    @staticmethod
    def _source_prior(source: RecordSource) -> float:
        """记录来源的先验可靠度。"""
        priors = {
            RecordSource.MANUAL: 0.02,
            RecordSource.BLIND_FMT: 0.01,
            RecordSource.LOCAL_ELF: 0.08,
            RecordSource.GDB_SYNC: 0.12,
            RecordSource.LIBC_SEARCHER: 0.05,
            RecordSource.DERIVED: 0.04,
        }
        return priors.get(source, 0.02)

    def _related_base_conflicts(
        self,
        inferred_name: str,
        aligned_base: int,
        expected_classes: set[AddressClass],
        fallback_class: AddressClass,
    ) -> tuple[int, int]:
        """统计同类 base 中与当前候选一致/冲突的数量。"""
        same_group_matches = 0
        same_group_conflicts = 0
        comparable_classes = expected_classes or {fallback_class}

        for existing_name, existing in self._bases.items():
            if existing_name == inferred_name:
                continue

            existing_class = existing.meta.get("address_class")
            if isinstance(existing_class, str):
                try:
                    existing_addr_class = AddressClass(existing_class)
                except ValueError:
                    existing_addr_class = self.classify_address(existing.base)
            else:
                existing_addr_class = self.classify_address(existing.base)

            if existing_addr_class not in comparable_classes:
                continue

            if existing.base == aligned_base:
                same_group_matches += 1
            else:
                same_group_conflicts += 1

        return same_group_matches, same_group_conflicts

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
        aligned_base = raw_base & ~(self.page_size - 1) if raw_base > 0 else raw_base

        reasons: list[str] = []
        score = 0.0

        if raw_base == aligned_base:
            score += 0.20
            reasons.append("原始 base 已按页对齐 (+0.20)")
        else:
            misalignment = raw_base % self.page_size
            if misalignment <= max(0x20, self.page_size // 128):
                score += 0.04
                reasons.append(
                    f"原始 base 接近页边界，轻微加分 (+0.04, misalign={misalignment:#x})"
                )
            elif misalignment <= max(0x100, self.page_size // 16):
                score += 0.01
                reasons.append(
                    f"原始 base 有一定页对齐迹象，弱加分 (+0.01, misalign={misalignment:#x})"
                )
            elif misalignment >= self.page_size - max(0x80, self.page_size // 8):
                score -= 0.04
                reasons.append(
                    f"原始 base 离页边界较远，轻微扣分 (-0.04, misalign={misalignment:#x})"
                )
            else:
                reasons.append(
                    f"原始 base 未严格页对齐，不额外加分 (misalign={misalignment:#x})"
                )

        if symbol_offset > record.value:
            score -= 0.18
            reasons.append("symbol_offset 大于泄漏值，raw_base 明显异常 (-0.18)")
        elif raw_base <= 0:
            score -= 0.18
            reasons.append("推导出的 raw_base 非正数，可信度较低 (-0.18)")
        elif raw_base < self.page_size:
            score -= 0.10
            reasons.append("推导出的 raw_base 过小，不像真实映射基址 (-0.10)")

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

        kind_expected_classes = self._expected_base_classes_from_kind(record.kind)
        name_expected_classes = self._expected_base_classes_from_name(record.name)
        expected_classes = self._expected_base_classes(record.name, record.kind)

        if kind_expected_classes:
            expected_labels = "/".join(sorted(item.value for item in kind_expected_classes))
            if addr_class in kind_expected_classes:
                score += 0.10
                reasons.append(
                    f"记录类型与候选基址类型匹配：期望 {expected_labels} (+0.10)"
                )
            else:
                score -= 0.08
                reasons.append(
                    f"记录类型与候选基址类型不符：期望 {expected_labels} (-0.08)"
                )
        elif name_expected_classes:
            expected_labels = "/".join(sorted(item.value for item in name_expected_classes))
            if addr_class in name_expected_classes:
                score += 0.04
                reasons.append(
                    f"键名语义弱匹配候选基址类型：期望 {expected_labels} (+0.04)"
                )
            else:
                score -= 0.03
                reasons.append(
                    f"键名语义与候选基址类型偏离：期望 {expected_labels} (-0.03)"
                )

        source_prior = self._source_prior(record.source)
        confidence_bonus = 0.08 * record.confidence
        source_bonus = source_prior + confidence_bonus
        score += source_bonus
        reasons.append(
            f"来源先验 + 置信度继承：src={record.source.value} (+{source_prior:.2f}) "
            f"+ conf={record.confidence:.2f} (+{confidence_bonus:.2f})"
        )

        existing = self.get_base(inferred_name)
        if existing is not None:
            if existing.base == aligned_base:
                score += 0.35
                reasons.append("与已确认 base 一致 (+0.35)")
            else:
                score -= 0.50
                reasons.append("与已确认 base 冲突 (-0.50)")

        related_matches, related_conflicts = self._related_base_conflicts(
            inferred_name=inferred_name,
            aligned_base=aligned_base,
            expected_classes=expected_classes,
            fallback_class=addr_class,
        )
        if related_matches:
            related_bonus = min(0.18, 0.08 * related_matches)
            score += related_bonus
            reasons.append(f"与同类 base 保持一致 (+{related_bonus:.2f})")
        if related_conflicts:
            related_penalty = min(0.36, 0.18 * related_conflicts)
            score -= related_penalty
            reasons.append(f"与同类 base 存在冲突 (-{related_penalty:.2f})")

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
                    "reasons": list(reasons),
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

    def puts_log(self, verbose: bool = False) -> None:
        """按分组打印 Registry 快照，适合打题时快速看全局状态。

        默认展示简洁信息，减少日常打题时的视觉负担；
        当 `verbose=True` 时再展开显示元信息细节。
        """
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

        print_registry_snapshot(address_rows, base_rows, misc_rows, verbose=verbose)

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
