from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Mapping, Protocol, Sequence

from ..._compat import log
from ...core.models import (
    AddressLike,
    FmtEndian,
    FmtExecutionReceipt,
    FmtExecutionResult,
    FmtLayoutPolicy,
    FmtLeak,
    FmtOffset,
    FmtOffsetProbeMode,
    FmtOffsetProbeResult,
    FmtReadMode,
    FmtResultKind,
    FmtTargetRef,
    FmtTaskPolicy,
    FmtValueRef,
    FmtWriteCandidate,
    FmtWriteComparison,
    FmtWriteAtom,
    FmtWritePlan,
    FmtWriteRequest,
    FmtWriteStrategy,
    FmtWriteTask,
    FactKind,
    RecordDomain,
    RenderedFmtTask,
    ValueLike,
)
from .errors import (
    FmtConfigurationError,
    FmtExecutionError,
    FmtOffsetMissingError,
    FmtReadError,
    FmtSymbolResolveError,
    FmtWriteError,
)
from .planner import DefaultFmtWritePlanner
from .readers import DefaultFmtReadExecutor
from .probes import FmtOffsetProbe as DefaultFmtOffsetProbe
from .renderer import DefaultFmtTaskRenderer
from .writers import DefaultFmtPlanExecutor

if TYPE_CHECKING:
    from chun.core.session import CHunSession


@dataclass(slots=True, frozen=True)
class _ArchContext:
    bits: int
    endian: FmtEndian
    pointer_size: int


class FmtOffsetProbe(Protocol):
    """
    probes.py 的抽象入口。
    """

    def find_offset(
        self,
        session: "CHunSession",
        *,
        mode: FmtOffsetProbeMode | str = FmtOffsetProbeMode.SEQUENTIAL,
        **kwargs: object,
    ) -> FmtOffsetProbeResult: ...


class FmtReadExecutor(Protocol):
    """
    readers.py 的抽象入口。
    负责真正构造读 payload 并发给 transport。
    """

    def read(
        self,
        session: "CHunSession",
        target: FmtTargetRef,
        *,
        size: int,
        mode: FmtReadMode,
        offset: int,
        **kwargs: object,
    ) -> FmtLeak: ...


class FmtWritePlanner(Protocol):
    """
    planner.py 的抽象入口。
    只做 request -> atoms 的纯规划，不做发送。
    """

    def plan(
        self,
        requests: Sequence[FmtWriteRequest],
        *,
        bits: int,
        endian: FmtEndian,
        pointer_size: int,
        task_policy: FmtTaskPolicy,
        **kwargs: object,
    ) -> FmtWritePlan: ...


class FmtPlanExecutor(Protocol):
    """
    writers.py / blind.py 的抽象入口。
    负责 task -> payload -> transport.send/exchange 的执行。
    """

    def execute_task(
        self,
        session: "CHunSession",
        task: FmtWriteTask,
        *,
        plan: FmtWritePlan,
        offset: int,
        rendered: RenderedFmtTask | None = None,
        **kwargs: object,
    ) -> FmtExecutionReceipt: ...


class FmtTaskRenderer(Protocol):
    """
    renderer.py 的抽象入口。
    只做 task -> bytes 的纯渲染，不做发送。
    """

    def render(
        self,
        task: FmtWriteTask,
        *,
        plan: FmtWritePlan,
        offset: int,
        data_offset: int | None = None,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
    ) -> RenderedFmtTask: ...


class FmtService:
    """
    Stateless service:
    - 不缓存 offset
    - 不缓存已解析地址
    - 不缓存执行进度
    - 只通过 session.rec 读取/写入事实与产物
    """

    def __init__(
        self,
        session: "CHunSession",
        *,
        prober: FmtOffsetProbe | None = None,
        planner: FmtWritePlanner | None = None,
        reader: FmtReadExecutor | None = None,
        renderer: FmtTaskRenderer | None = None,
        executor: FmtPlanExecutor | None = None,
    ) -> None:
        self.session = session
        self._prober = prober if prober is not None else DefaultFmtOffsetProbe()
        self._planner = planner if planner is not None else DefaultFmtWritePlanner()
        self._reader = reader if reader is not None else DefaultFmtReadExecutor()
        self._renderer = renderer if renderer is not None else DefaultFmtTaskRenderer()
        self._executor = (
            executor
            if executor is not None
            else DefaultFmtPlanExecutor(renderer=self._renderer)
        )

    # ------------------------------------------------------------------
    # public: offset
    # ------------------------------------------------------------------

    def get_offset(self, *, required: bool = False) -> FmtOffset | None:
        """
        逻辑：
        1. 从 session.rec.get_fact("fmt.offset") 读取。
        2. 允许 registry 返回 Fact 对象或裸 value，统一解包。
        3. 若不存在：
           - required=False: 返回 None
           - required=True: 抛异常
        4. 组装成 FmtOffset 返回，但不在 service 内缓存。
        """
        entry = self.session.rec.get_fact("fmt.offset")
        if entry is None:
            if required:
                raise FmtOffsetMissingError("missing fact: fmt.offset")
            return None

        value = entry.value if hasattr(entry, "value") else entry
        meta = dict(getattr(entry, "metadata", {}))

        return FmtOffset(
            index=int(value),
            source=getattr(entry, "source", "registry"),
            confidence=float(getattr(entry, "confidence", 1.0)),
            strategy=str(meta.get("method", meta.get("strategy", "registry"))),
            signature=meta.get("signature", meta.get("marker")),
            metadata=meta,
        )

    def set_offset(
        self,
        offset: int | FmtOffset | FmtOffsetProbeResult,
        *,
        overwrite: bool = True,
        source: str = "fmt.service",
    ) -> FmtOffset:
        """
        逻辑：
        1. 规范化成 FmtOffset。
        2. 写 fact: fmt.offset = <int>
        3. 可选再写 artifact/detail，保留 probe 元信息。
        4. 返回结构化 FmtOffset。
        """
        if isinstance(offset, FmtOffset):
            model = offset
        elif isinstance(offset, FmtOffsetProbeResult):
            if offset.index is None:
                raise FmtOffsetMissingError(
                    "probe result does not contain a resolved fmt.offset"
                )
            model = FmtOffset(
                index=offset.index,
                source=offset.source,
                strategy=offset.method.value,
                confidence=offset.confidence,
                signature=offset.signature,
                metadata={
                    "matched_token": offset.matched_token,
                    "verified": offset.verified,
                    "window_start": offset.window_start,
                    "window_end": offset.window_end,
                    "sep": offset.sep,
                    **offset.metadata,
                },
            )
        else:
            model = FmtOffset(
                index=int(offset),
                source=source,
            )

        self.session.rec.record_fact(
            "fmt.offset",
            model.index,
            kind=FactKind.OFFSET,
            domain=RecordDomain.FMT,
            source=model.source,
            confidence=model.confidence,
            tags=["fmt", "offset"],
            metadata={
                "strategy": model.strategy,
                "signature": model.signature,
                **model.metadata,
            },
            overwrite=overwrite,
        )

        self.session.rec.record_artifact(
            "fmt.offset.detail",
            model,
            domain=RecordDomain.FMT,
            source=model.source,
            overwrite=True,
        )

        return model

    def find_offset(
        self,
        *,
        mode: FmtOffsetProbeMode | str = FmtOffsetProbeMode.SEQUENTIAL,
        max_slots: int = 32,
        window_start: int | None = None,
        window_size: int | None = None,
        sep: bytes = b".",
        signature: bytes | None = None,
        store: bool = True,
        loginfo: bool = False,
        source: str = "fmt.probe",
    ) -> FmtOffsetProbeResult:
        """
        逻辑：
        1. 通过 probes backend 执行真正的 offset 探测。
        2. prober 内部按需回写 observation / artifact / fact。
        3. 返回结构化 probe result。
        """
        if self._prober is None:
            raise FmtConfigurationError("no fmt prober configured")

        result = self._prober.find_offset(
            self.session,
            mode=mode,
            max_slots=max_slots,
            window_start=window_start,
            window_size=window_size,
            sep=sep,
            signature=signature,
            store=store,
            source=source,
        )
        if loginfo:
            self._log_find_offset_result(result)
        return result

    @staticmethod
    def _log_find_offset_result(result: FmtOffsetProbeResult) -> None:
        token = result.matched_token or "<unknown>"
        window = "?"
        if result.window_start is not None and result.window_end is not None:
            window = f"{result.window_start}-{result.window_end}"
        log.success(
            "fmt offset found: "
            f"index={result.index} method={result.method.value} token={token}"
        )
        log.info(
            "fmt offset detail: "
            f"signature={result.signature!r} sep={result.sep!r} "
            f"window={window} confidence={result.confidence:.2f}"
        )

    @staticmethod
    def _log_compare_write_result(result: FmtWriteComparison) -> None:
        log.info(str(result))

    # ------------------------------------------------------------------
    # public: symbol/value resolution
    # ------------------------------------------------------------------

    def resolve_target(self, target: AddressLike) -> FmtTargetRef:
        """
        逻辑：
        1. int 直接视为绝对地址。
        2. str 走 session.resolve.symbol(target)，得到绝对地址。
        3. 返回 FmtTargetRef(raw, address, symbol, origin)。
        """
        if isinstance(target, int):
            return FmtTargetRef(
                raw=target,
                address=target,
                origin="absolute",
            )

        addr = self._resolve_target_symbol(target)
        return FmtTargetRef(
            raw=target,
            address=addr,
            symbol=target,
            origin="symbol",
        )

    def resolve_value(self, value: ValueLike) -> FmtValueRef:
        """
        逻辑：
        1. int 直接作为字面值。
        2. str 走 session.resolve.symbol(value)。
           这允许 plan_writes({"printf@got": "system"})。
        """
        if isinstance(value, int):
            return FmtValueRef(
                raw=value,
                value=value,
                origin="literal",
            )

        resolved = self._resolve_value_symbol(value)
        return FmtValueRef(
            raw=value,
            value=resolved,
            symbol=value,
            origin="symbol",
        )

    # ------------------------------------------------------------------
    # public: read
    # ------------------------------------------------------------------

    def read(
        self,
        target: AddressLike,
        *,
        size: int = 8,
        mode: FmtReadMode = FmtReadMode.RAW,
        offset: int | None = None,
        reader: FmtReadExecutor | None = None,
        observation_name: str | None = None,
        store: bool = True,
        **kwargs: object,
    ) -> FmtLeak:
        """
        逻辑：
        1. resolve_target()
        2. offset 优先级：
           arg > registry(fmt.offset)
        3. 交给 readers backend 真正构造 payload 并发送
        4. 结果作为 observation 回写
        5. 返回 FmtLeak

        注意：
        - read 结果默认只记 observation，不直接升级为 fact。
        - 若 decoded 是稳定地址，可由更上层逻辑再决定是否 record_addr / record_symbol_leak。
        """
        backend = reader or self._reader
        if backend is None:
            raise FmtConfigurationError("no fmt read backend configured")

        resolved_target = self.resolve_target(target)
        resolved_offset = (
            offset if offset is not None else self.get_offset(required=True).index
        )

        leak = backend.read(
            self.session,
            resolved_target,
            size=size,
            mode=mode,
            offset=resolved_offset,
            **kwargs,
        )

        if store:
            self.session.rec.record_observation(
                observation_name
                or f"fmt.leak.{resolved_target.symbol or hex(resolved_target.address)}",
                leak,
                domain=RecordDomain.FMT,
                source=leak.source,
                tags=["fmt", "leak"],
                metadata={
                    "mode": leak.mode.value,
                    "size": leak.size,
                    **leak.metadata,
                },
            )

        return leak

    # ------------------------------------------------------------------
    # public: write planning
    # ------------------------------------------------------------------

    def plan_write(
        self,
        target: AddressLike,
        value: ValueLike,
        **kwargs: object,
    ) -> FmtWritePlan:
        """
        单目标 convenience wrapper。
        """
        return self.plan_writes({target: value}, **kwargs)

    def write(
        self,
        target: AddressLike,
        value: ValueLike,
        **kwargs: object,
    ) -> FmtExecutionResult:
        """单目标高层写接口：内部自动规划并执行。"""
        return self.writes({target: value}, **kwargs)

    def compare_write(
        self,
        target: AddressLike,
        value: ValueLike,
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        offset: int | None = None,
        task_policy: FmtTaskPolicy = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        buflen: int | None = None,
        end: bytes | None = None,
        show_hex: bool = False,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
        loginfo: bool = False,
        **kwargs: object,
    ) -> FmtWriteComparison:
        resolved_target = self.resolve_target(target)
        resolved_value = self.resolve_value(value)
        normalized_strategies = tuple(
            self._normalize_write_strategy(item) for item in strategies
        )

        candidates: list[FmtWriteCandidate] = []
        for strategy in normalized_strategies:
            try:
                plan = self.plan_write(
                    resolved_target.address,
                    resolved_value.value,
                    strategy=strategy,
                    offset=offset,
                    task_policy=task_policy,
                    data_offset=data_offset,
                    store=False,
                    **kwargs,
                )
                rendered_tasks = self.render_plan(
                    plan,
                    offset=offset,
                    data_offset=data_offset,
                    layout=layout,
                    initial_counter=initial_counter,
                    store=False,
                )
                candidates.append(
                    FmtWriteCandidate(
                        strategy=strategy,
                        plan=plan,
                        rendered_tasks=rendered_tasks,
                        metadata={
                            "layout": layout.value,
                            "offset": plan.offset,
                        },
                    )
                )
            except Exception as exc:
                candidates.append(
                    FmtWriteCandidate(
                        strategy=strategy,
                        error=f"{type(exc).__name__}: {exc}",
                        metadata={"layout": layout.value},
                    )
                )

        result = FmtWriteComparison(
            target=resolved_target,
            value=resolved_value,
            candidates=tuple(candidates),
            metadata={
                "requested_strategies": tuple(
                    strategy.value for strategy in normalized_strategies
                ),
                "offset": offset,
                "task_policy": task_policy.value,
                "data_offset": data_offset,
                "buflen": buflen,
                "end": end,
                "show_hex": show_hex,
                "layout": layout.value,
            },
        )
        if loginfo:
            self._log_compare_write_result(result)
        return result

    def plan_writes(
        self,
        writes: Mapping[AddressLike, ValueLike] | Sequence[FmtWriteRequest],
        *,
        strategy: FmtWriteStrategy = FmtWriteStrategy.AUTO,
        chunk_width: int | None = None,
        value_bits: int | None = None,
        task_policy: FmtTaskPolicy = FmtTaskPolicy.PACKED,
        offset: int | None = None,
        data_offset: int | None = None,
        backend: str = "pwntools",
        write_size: str | None = None,
        write_size_max: str = "long",
        overflows: int = 16,
        backend_strategy: str = "small",
        badbytes: bytes | bytearray | Sequence[int] = (),
        no_dollars: bool = False,
        numbwritten: int = 0,
        artifact_name: str | None = None,
        store: bool = True,
    ) -> FmtWritePlan:
        """
        逻辑：
        1. 读取当前 bits / endian
           - 优先 session.elf.bits
           - fallback: registry context arch.bits / arch.endian
        2. 读取当前 fmt.offset（若存在）
        3. 规范化 writes：
           - target: int|str -> FmtTargetRef
           - value: int|str -> FmtValueRef
        4. 根据 strategy / chunk_width / value_bits 交给 planner backend
           拆成 FmtWriteAtom
        5. 根据 task_policy 把 atoms regroup 成 tasks
        6. 构造 FmtWritePlan
        7. 若 store=True，则 artifact 回写
        """
        arch = self._read_arch_context()

        current_offset_model = self.get_offset(required=False)
        current_offset = (
            offset
            if offset is not None
            else (current_offset_model.index if current_offset_model else None)
        )
        current_data_offset = data_offset

        requests = self._normalize_requests(
            writes,
            strategy=strategy,
            chunk_width=chunk_width,
            value_bits=value_bits,
        )
        try:
            base_plan = self._planner.plan(
                requests,
                bits=arch.bits,
                endian=arch.endian,
                pointer_size=arch.pointer_size,
                task_policy=task_policy,
                backend=backend,
                write_size=write_size
                or self._infer_write_size(strategy=strategy, chunk_width=chunk_width),
                write_size_max=write_size_max,
                overflows=overflows,
                backend_strategy=backend_strategy,
                badbytes=badbytes,
                no_dollars=no_dollars,
                numbwritten=numbwritten,
                data_offset=current_data_offset,
                fmt_offset=current_offset,
            )
        except FmtWriteError:
            raise
        except Exception as exc:
            raise FmtWriteError("fmt write planning failed") from exc
        plan = replace(
            base_plan,
            offset=current_offset,
            data_offset=current_data_offset,
            metadata={
                **dict(base_plan.metadata),
                "artifact_name": artifact_name,
                "bits": arch.bits,
                "endian": arch.endian,
                "pointer_size": arch.pointer_size,
                "request_count": len(requests),
                "backend": backend,
                "fmt_offset": current_offset,
                "data_offset": current_data_offset,
            },
        )

        if store:
            self.session.rec.record_artifact(
                artifact_name or "fmt.plan",
                plan,
                domain=RecordDomain.FMT,
                source="fmt.plan_writes",
                tags=["fmt", "plan"],
                metadata={
                    "bits": arch.bits,
                    "endian": arch.endian,
                    "pointer_size": arch.pointer_size,
                    "task_policy": task_policy.value,
                    "request_count": len(requests),
                    "atom_count": plan.total_atoms,
                    "task_count": plan.total_tasks,
                    "backend": plan.backend,
                    "fmt_offset": plan.offset,
                    "data_offset": plan.data_offset,
                },
                overwrite=True,
            )

        return plan

    def writes(
        self,
        writes: Mapping[AddressLike, ValueLike] | Sequence[FmtWriteRequest],
        *,
        strategy: FmtWriteStrategy = FmtWriteStrategy.AUTO,
        chunk_width: int | None = None,
        value_bits: int | None = None,
        task_policy: FmtTaskPolicy = FmtTaskPolicy.PACKED,
        offset: int | None = None,
        data_offset: int | None = None,
        backend: str = "pwntools",
        write_size: str | None = None,
        write_size_max: str = "long",
        overflows: int = 16,
        backend_strategy: str = "small",
        badbytes: bytes | bytearray | Sequence[int] = (),
        no_dollars: bool = False,
        numbwritten: int = 0,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
        artifact_name: str | None = "fmt.write.plan",
        result_prefix: str = "fmt.write",
        store: bool = True,
        record_rendered: bool = True,
        executor: FmtPlanExecutor | None = None,
        **kwargs: object,
    ) -> FmtExecutionResult:
        """批量高层写接口：plan -> execute 的 façade。"""
        plan = self.plan_writes(
            writes,
            strategy=strategy,
            chunk_width=chunk_width,
            value_bits=value_bits,
            task_policy=task_policy,
            offset=offset,
            data_offset=data_offset,
            backend=backend,
            write_size=write_size,
            write_size_max=write_size_max,
            overflows=overflows,
            backend_strategy=backend_strategy,
            badbytes=badbytes,
            no_dollars=no_dollars,
            numbwritten=numbwritten,
            artifact_name=artifact_name,
            store=store,
        )
        return self.execute_plan(
            plan,
            executor=executor,
            offset=offset,
            data_offset=data_offset,
            layout=layout,
            initial_counter=initial_counter,
            result_prefix=result_prefix,
            record=store,
            record_rendered=record_rendered,
            **kwargs,
        )

    def split_plan(
        self,
        plan: FmtWritePlan,
        *,
        task_policy: FmtTaskPolicy = FmtTaskPolicy.BY_ATOM,
        artifact_name: str | None = None,
        store: bool = False,
    ) -> FmtWritePlan:
        """
        逻辑：
        1. 不改 atoms，只重组 tasks。
        2. 返回一个新的 FmtWritePlan。
        3. BY_ATOM 是最适合 BlindReconnectTransport 的拆法。
        """
        tasks = self._group_atoms(plan.atoms, policy=task_policy)
        out = replace(plan, task_policy=task_policy, tasks=tuple(tasks))

        if store:
            self.session.rec.record_artifact(
                artifact_name or "fmt.plan.split",
                out,
                domain=RecordDomain.FMT,
                source="fmt.split_plan",
                tags=["fmt", "plan"],
                overwrite=True,
            )

        return out

    def render_task(
        self,
        task: FmtWriteTask,
        *,
        plan: FmtWritePlan,
        offset: int | None = None,
        data_offset: int | None = None,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
        artifact_name: str | None = None,
        store: bool = False,
    ) -> RenderedFmtTask:
        resolved_offset = (
            offset
            if offset is not None
            else (
                plan.offset
                if plan.offset is not None
                else self._read_fmt_offset()
            )
        )
        resolved_data_offset = (
            data_offset
            if data_offset is not None
            else plan.data_offset
        )
        rendered = self._renderer.render(
            task,
            plan=plan,
            offset=resolved_offset,
            data_offset=resolved_data_offset,
            layout=layout,
            initial_counter=initial_counter,
        )

        if store:
            self.session.rec.record_artifact(
                artifact_name or f"fmt.render.task.{task.task_index}",
                rendered,
                domain=RecordDomain.FMT,
                source="fmt.render_task",
                tags=["fmt", "render"],
                overwrite=True,
            )

        return rendered

    def render_plan(
        self,
        plan: FmtWritePlan,
        *,
        offset: int | None = None,
        data_offset: int | None = None,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
        artifact_prefix: str = "fmt.render",
        store: bool = False,
    ) -> tuple[RenderedFmtTask, ...]:
        resolved_offset = (
            offset
            if offset is not None
            else (
                plan.offset
                if plan.offset is not None
                else self._read_fmt_offset()
            )
        )
        resolved_data_offset = (
            data_offset
            if data_offset is not None
            else plan.data_offset
        )

        rendered: list[RenderedFmtTask] = []
        current_counter = initial_counter
        for task in plan.tasks:
            item = self._renderer.render(
                task,
                plan=plan,
                offset=resolved_offset,
                data_offset=resolved_data_offset,
                layout=layout,
                initial_counter=(
                    current_counter if not task.independent else initial_counter
                ),
            )
            rendered.append(item)
            if not task.independent:
                current_counter = item.final_counter

            if store:
                self.session.rec.record_artifact(
                    f"{artifact_prefix}.task.{task.task_index}",
                    item,
                    domain=RecordDomain.FMT,
                    source="fmt.render_plan",
                    tags=["fmt", "render"],
                    overwrite=True,
                )

        return tuple(rendered)

    # ------------------------------------------------------------------
    # public: execution orchestration
    # ------------------------------------------------------------------

    def execute_plan(
        self,
        plan: FmtWritePlan,
        *,
        executor: FmtPlanExecutor | None = None,
        offset: int | None = None,
        data_offset: int | None = None,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
        result_prefix: str = "fmt.exec",
        record: bool = True,
        record_rendered: bool = True,
        **kwargs: object,
    ) -> FmtExecutionResult:
        """
        注意：
        这里不是 payload 算法实现层，而是 orchestration 层。

        逻辑：
        1. offset 优先级：
           arg > plan.offset > registry(fmt.offset)
        2. 先 render_plan() 生成 RenderedFmtTask
        3. 对每个 rendered task 调用 executor.execute_task(...)
        4. 原始响应写 observation，结构化结果写 artifact
        5. 返回结构化回执列表
        """
        backend = executor or self._executor
        if backend is None:
            raise FmtConfigurationError("no fmt executor configured")

        resolved_offset = (
            offset
            if offset is not None
            else (
                plan.offset
                if plan.offset is not None
                else self._read_fmt_offset()
            )
        )
        resolved_data_offset = (
            data_offset
            if data_offset is not None
            else plan.data_offset
        )

        rendered_items = self.render_plan(
            plan,
            offset=resolved_offset,
            data_offset=resolved_data_offset,
            layout=layout,
            initial_counter=initial_counter,
            artifact_prefix=f"{result_prefix}.render",
            store=record and record_rendered,
        )

        results: list[FmtExecutionReceipt] = []
        for task, rendered in zip(plan.tasks, rendered_items, strict=True):
            try:
                result = backend.execute_task(
                    self.session,
                    task,
                    plan=plan,
                    offset=resolved_offset,
                    rendered=rendered,
                    **kwargs,
                )
            except FmtWriteError:
                raise
            except Exception as exc:
                raise FmtExecutionError(
                    f"fmt task execution failed: task_index={task.task_index}"
                ) from exc
            results.append(result)

            if record:
                self.session.rec.record_observation(
                    f"{result_prefix}.response.{task.task_index}",
                    result.response,
                    domain=RecordDomain.FMT,
                    source=result.source,
                    tags=["fmt", "exec", "response"],
                    metadata={
                        "dispatch": result.dispatch.value,
                        "transport_kind": result.transport_kind,
                        "received": result.response is not None,
                    },
                    overwrite=True,
                )
                self.session.rec.record_artifact(
                    f"{result_prefix}.task.{task.task_index}",
                    result,
                    domain=RecordDomain.FMT,
                    source=result.source,
                    tags=["fmt", "exec"],
                    metadata={
                        "dispatch": result.dispatch.value,
                        "transport_kind": result.transport_kind,
                    },
                    overwrite=True,
                )

        return FmtExecutionResult(
            kind=FmtResultKind.EXECUTION,
            plan=plan,
            receipts=tuple(results),
            offset=resolved_offset,
            result_prefix=result_prefix,
            source="fmt.execute_plan",
            metadata={
                "layout": layout.value,
                "initial_counter": initial_counter,
                "data_offset": resolved_data_offset,
            },
        )

    def blind(self) -> "BlindFmtService":
        """
        交给 blind.py 的 facade：
        - 默认 task_policy = BY_ATOM
        - 默认用 BlindReconnectTransport.exchange()/run()
        - 共用同一个 session 与 registry
        """
        from .blind import BlindFmtService

        return BlindFmtService(self.session, base=self)

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _read_arch_context(self) -> _ArchContext:
        """统一读取架构上下文。"""
        elf = getattr(self.session, "elf", None)
        if elf is not None and getattr(elf, "bits", None):
            bits = int(elf.bits)
            endian: FmtEndian = (
                "little" if bool(getattr(elf, "little_endian", True)) else "big"
            )
            return _ArchContext(bits=bits, endian=endian, pointer_size=bits // 8)

        bits_entry = self.session.rec.get_context("arch.bits")
        endian_entry = self.session.rec.get_context("arch.endian")
        if bits_entry is not None and endian_entry is not None:
            bits_value = bits_entry.value if hasattr(bits_entry, "value") else bits_entry
            endian_value = (
                endian_entry.value if hasattr(endian_entry, "value") else endian_entry
            )
            bits = int(bits_value)
            endian = str(endian_value)
            return _ArchContext(
                bits=bits,
                endian=endian,  # type: ignore[arg-type]
                pointer_size=bits // 8,
            )

        return _ArchContext(bits=64, endian="little", pointer_size=8)

    @staticmethod
    def _infer_write_size(
        *,
        strategy: FmtWriteStrategy,
        chunk_width: int | None,
    ) -> str:
        if chunk_width in (1, 2, 4, 8):
            return {1: "byte", 2: "short", 4: "int", 8: "long"}[chunk_width]
        mapping = {
            FmtWriteStrategy.BYTE: "byte",
            FmtWriteStrategy.SHORT: "short",
            FmtWriteStrategy.INT: "int",
            FmtWriteStrategy.PTR: "long",
        }
        return mapping.get(strategy, "short")

    @staticmethod
    def _normalize_write_strategy(
        strategy: FmtWriteStrategy | str,
    ) -> FmtWriteStrategy:
        if isinstance(strategy, FmtWriteStrategy):
            return strategy
        return FmtWriteStrategy(str(strategy).lower())

    def _read_fmt_offset(self) -> int:
        """统一读取 fmt offset fact。"""
        entry = self.session.rec.get_fact("fmt.offset")
        if entry is None:
            raise FmtOffsetMissingError("missing fact: fmt.offset")

        value = entry.value if hasattr(entry, "value") else entry
        return int(value)

    def _resolve_target_symbol(self, name: str) -> int:
        bound_elf = getattr(self.session, "elf", None)
        if bound_elf is not None:
            resolved = self._resolve_from_object(bound_elf, name)
            if resolved is not None:
                return resolved
        try:
            return int(self.session.resolve.symbol(name))
        except Exception as exc:
            raise FmtSymbolResolveError(
                f"unable to resolve fmt target symbol: {name}"
            ) from exc

    def _resolve_value_symbol(self, name: str) -> int:
        last_exc: Exception | None = None
        try:
            return int(self.session.resolve.symbol(name))
        except Exception as exc:
            last_exc = exc

        for obj in (getattr(self.session, "libc_elf", None), getattr(self.session, "elf", None)):
            if obj is None:
                continue
            resolved = self._resolve_from_object(obj, name, include_base=True)
            if resolved is not None:
                return resolved

        if last_exc is not None:
            raise FmtSymbolResolveError(
                f"unable to resolve fmt value symbol: {name}"
            ) from last_exc
        raise FmtSymbolResolveError(f"unable to resolve fmt value symbol: {name}")

    def _resolve_from_object(
        self,
        obj: object,
        name: str,
        *,
        include_base: bool = False,
    ) -> int | None:
        for attr in ("got", "plt", "sym", "symbols"):
            table = getattr(obj, attr, None)
            if table is None:
                continue
            try:
                if name in table:
                    value = int(table[name])
                    if include_base:
                        return int(getattr(obj, "address", 0)) + value
                    return value
            except Exception:
                continue
        return None

    def _normalize_requests(
        self,
        writes: Mapping[AddressLike, ValueLike] | Sequence[FmtWriteRequest],
        *,
        strategy: FmtWriteStrategy,
        chunk_width: int | None,
        value_bits: int | None,
    ) -> list[FmtWriteRequest]:
        if not isinstance(writes, Mapping):
            return list(writes)

        out: list[FmtWriteRequest] = []
        for target, value in writes.items():
            out.append(
                FmtWriteRequest(
                    target=self.resolve_target(target),
                    value=self.resolve_value(value),
                    value_bits=value_bits,
                    strategy=strategy,
                    chunk_width=chunk_width,
                )
            )
        return out

    def _group_atoms(
        self,
        atoms: Sequence[FmtWriteAtom],
        *,
        policy: FmtTaskPolicy,
    ) -> list[FmtWriteTask]:
        """
        这里只做 task regroup，不做 payload 级排序优化。
        payload builder 如果需要，可再使用 atom.order_key 做内部排序。
        """
        if policy == FmtTaskPolicy.BY_ATOM:
            return [
                FmtWriteTask(
                    task_index=i,
                    atoms=(atom,),
                    independent=True,
                )
                for i, atom in enumerate(atoms)
            ]

        if policy == FmtTaskPolicy.BY_TARGET:
            buckets: dict[int, list[FmtWriteAtom]] = {}
            for atom in atoms:
                buckets.setdefault(atom.request_index, []).append(atom)

            return [
                FmtWriteTask(
                    task_index=i,
                    atoms=tuple(group),
                    independent=True,
                )
                for i, group in enumerate(buckets.values())
            ]

        return [
            FmtWriteTask(
                task_index=0,
                atoms=tuple(atoms),
                independent=True,
            )
        ]
