"""脚本态 fmt 语法糖。"""

from __future__ import annotations

import sys
import time
from typing import TYPE_CHECKING, Any, Mapping, Sequence

from ..core.models import (
    AddressLike,
    FmtExecutionMethod,
    FmtExecutionReceipt,
    FmtExecutionResult,
    FmtLayoutPolicy,
    FmtOffsetProbeMode,
    FmtOffsetProbeResult,
    FmtRenderStep,
    FmtResultKind,
    FmtTaskPolicy,
    FmtWriteCandidate,
    FmtWriteComparison,
    FmtWriteStrategy,
    RenderedFmtTask,
    ValueLike,
)
from ..plugins.fmt import FmtService
from ..plugins.fmt.runtime import dispatch_fmt_payload

if TYPE_CHECKING:
    from ..core.models import FmtWritePlan


def _script_module() -> Any:
    return sys.modules[__package__]


class _ScriptFmtWriteAction:
    """脚本态 fmt.write(...) 的延迟门面。"""

    def __init__(
        self,
        service: FmtService,
        *,
        target: AddressLike,
        value: ValueLike,
        strategy: FmtWriteStrategy,
        offset: int | None,
        task_policy: FmtTaskPolicy,
        data_offset: int | None,
        delim: bytes | str | None,
        head: bytes | None,
        head_numbwritten: int,
        end: bytes | None,
    ) -> None:
        self._service = service
        self._target = target
        self._value = value
        self._strategy = strategy
        self._offset = offset
        self._task_policy = task_policy
        self._data_offset = data_offset
        self._delim = delim
        self._head = head
        self._head_numbwritten = head_numbwritten
        self._end = end

    def info(
        self,
        buflen: int | None = None,
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        show_hex: bool = False,
    ) -> Any:
        """只做规划与对比输出，不发送 payload。"""
        result = self._service.compare_write(
            self._target,
            self._value,
            strategies=strategies,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
            buflen=buflen,
            end=self._end,
            show_hex=show_hex,
            loginfo=False,
        )
        if self._head:
            result = _apply_head_to_comparison(
                self._service,
                result,
                offset=self._offset,
                data_offset=self._data_offset,
                head=self._head,
                head_numbwritten=self._head_numbwritten,
            )
        log_fn = getattr(self._service, "_log_compare_write_result", None)
        if callable(log_fn):
            log_fn(result)
        return result

    def send(self, _buflen: int | None = None, *, show_hex: bool = False) -> Any:
        """按当前配置构造并发送单地址写入 payload。"""
        _ = (_buflen, show_hex)
        plan = self._service.plan_write(
            self._target,
            self._value,
            strategy=self._strategy,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
        )
        if self._head:
            resolved_offset = _resolve_script_fmt_offset(
                self._service,
                plan=plan,
                offset=self._offset,
            )
            rendered = _render_headed_single_task(
                self._service,
                plan=plan,
                offset=resolved_offset,
                data_offset=self._data_offset,
                head=self._head,
                head_numbwritten=self._head_numbwritten,
            )
            rendered_items = (rendered,)
        else:
            resolved_offset = _resolve_script_fmt_offset(
                self._service,
                plan=plan,
                offset=self._offset,
            )
            rendered_items = self._service.render_plan(
                plan,
                offset=resolved_offset,
                data_offset=self._data_offset,
                store=False,
            )
        _warn_for_script_fmt_send(
            rendered_items,
            buflen=_buflen,
            end=self._end,
        )
        if self._delim is not None:
            self._service.session.io.recvuntil(_normalize_recv_delim(self._delim))
        if self._head:
            return _execute_headed_single_task(
                self._service,
                plan=plan,
                rendered=rendered_items[0],
                offset=resolved_offset,
                end=self._end,
            )
        return self._service.execute_plan(
            plan,
            offset=resolved_offset,
            data_offset=self._data_offset,
            receive=False,
            end=self._end,
        )


class _ScriptFmtWritesAction:
    """脚本态 fmt.writes(...) 的延迟门面。"""

    def __init__(
        self,
        service: FmtService,
        *,
        writes: Mapping[AddressLike, ValueLike] | Sequence[tuple[AddressLike, ValueLike]],
        strategy: FmtWriteStrategy,
        offset: int | None,
        task_policy: FmtTaskPolicy,
        data_offset: int | None,
        delim: bytes | str | None,
        end: bytes | None,
    ) -> None:
        self._service = service
        self._writes = writes
        self._strategy = strategy
        self._offset = offset
        self._task_policy = task_policy
        self._data_offset = data_offset
        self._delim = delim
        self._end = end

    def info(
        self,
        buflen: int | None = None,
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        show_hex: bool = False,
    ) -> Any:
        """只做多地址写入策略对比，不发送 payload。"""
        return self._service.compare_writes(
            self._writes,
            strategies=strategies,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
            buflen=buflen,
            end=self._end,
            show_hex=show_hex,
            loginfo=True,
        )

    def send(self, _buflen: int | None = None, *, show_hex: bool = False) -> Any:
        """按当前配置构造并发送多地址写入 payload。"""
        _ = (_buflen, show_hex)
        plan = self._service.plan_writes(
            self._writes,
            strategy=self._strategy,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
        )
        rendered_items = self._service.render_plan(
            plan,
            offset=self._offset,
            data_offset=self._data_offset,
            store=False,
        )
        _warn_for_script_fmt_send(
            rendered_items,
            buflen=_buflen,
            end=self._end,
        )
        if self._delim is not None:
            self._service.session.io.recvuntil(_normalize_recv_delim(self._delim))
        return self._service.execute_plan(
            plan,
            offset=self._offset,
            data_offset=self._data_offset,
            receive=False,
            end=self._end,
        )


class _ScriptFmtFacade:
    """脚本态 fmt 语法糖：默认打开 offset 探测日志。"""

    def __init__(self, service: FmtService) -> None:
        self._service = service

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
        verify: bool = False,
        verify_marker: bytes = b"aabb",
        verify_from_checkpoint: str | None = None,
        verify_promote: bool = True,
        verify_loginfo: bool | None = None,
        loginfo: bool = True,
        source: str = "fmt.probe",
    ) -> FmtOffsetProbeResult:
        """探测 fmt offset，默认开启日志便于手写 exp 调试。"""
        stage_start = time.perf_counter()
        kwargs: dict[str, Any] = {"loginfo": loginfo}
        if mode != FmtOffsetProbeMode.SEQUENTIAL:
            kwargs["mode"] = mode
        if max_slots != 32:
            kwargs["max_slots"] = max_slots
        if window_start is not None:
            kwargs["window_start"] = window_start
        if window_size is not None:
            kwargs["window_size"] = window_size
        if sep != b".":
            kwargs["sep"] = sep
        if signature is not None:
            kwargs["signature"] = signature
        if store is not True:
            kwargs["store"] = store
        if verify is not False:
            kwargs["verify"] = verify
        if verify_marker != b"aabb":
            kwargs["verify_marker"] = verify_marker
        if verify_from_checkpoint is not None:
            kwargs["verify_from_checkpoint"] = verify_from_checkpoint
        if verify_promote is not True:
            kwargs["verify_promote"] = verify_promote
        if verify_loginfo is not None:
            kwargs["verify_loginfo"] = verify_loginfo
        if source != "fmt.probe":
            kwargs["source"] = source
        result = self._service.find_offset(**kwargs)
        _emit_script_timing(
            "script.fmt.find_offset.total",
            stage_start,
            extra=f"verify={verify} store={store}",
        )
        return result

    def write(
        self,
        target: AddressLike,
        value: ValueLike,
        delim: bytes | str | None = None,
        offset: int | None = None,
        *,
        strategy: FmtWriteStrategy | str = FmtWriteStrategy.AUTO,
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        head: bytes | None = None,
        head_numbwritten: int = 0,
        end: bytes | None = b"\n",
    ) -> _ScriptFmtWriteAction:
        """构造单地址写入动作对象，可继续 `.info()` 或 `.send()`。"""
        return _ScriptFmtWriteAction(
            self._service,
            target=target,
            value=value,
            strategy=self._normalize_strategy(strategy),
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            delim=delim,
            head=head,
            head_numbwritten=head_numbwritten,
            end=end,
        )

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
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        buflen: int | None = None,
        end: bytes | None = b"\n",
        show_hex: bool = False,
        loginfo: bool = True,
    ) -> Any:
        """直接做单地址写入策略比较。"""
        return self._service.compare_write(
            target,
            value,
            strategies=strategies,
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            buflen=buflen,
            end=end,
            show_hex=show_hex,
            loginfo=loginfo,
        )

    def writes(
        self,
        writes: Mapping[AddressLike, ValueLike] | Sequence[tuple[AddressLike, ValueLike]],
        delim: bytes | str | None = None,
        offset: int | None = None,
        *,
        strategy: FmtWriteStrategy | str = FmtWriteStrategy.AUTO,
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        end: bytes | None = b"\n",
    ) -> _ScriptFmtWritesAction:
        """构造多地址写入动作对象，可继续 `.info()` 或 `.send()`。"""
        return _ScriptFmtWritesAction(
            self._service,
            writes=writes,
            strategy=self._normalize_strategy(strategy),
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            delim=delim,
            end=end,
        )

    def compare_writes(
        self,
        writes: Mapping[AddressLike, ValueLike] | Sequence[tuple[AddressLike, ValueLike]],
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        offset: int | None = None,
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        buflen: int | None = None,
        end: bytes | None = b"\n",
        show_hex: bool = False,
        loginfo: bool = True,
    ) -> Any:
        """直接做多地址写入策略比较。"""
        return self._service.compare_writes(
            writes,
            strategies=strategies,
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            buflen=buflen,
            end=end,
            show_hex=show_hex,
            loginfo=loginfo,
        )

    @staticmethod
    def _normalize_strategy(strategy: FmtWriteStrategy | str) -> FmtWriteStrategy:
        """兼容字符串策略输入。"""
        if isinstance(strategy, FmtWriteStrategy):
            return strategy
        return FmtWriteStrategy(str(strategy).lower())

    @staticmethod
    def _normalize_task_policy(policy: FmtTaskPolicy | str) -> FmtTaskPolicy:
        """兼容字符串 task policy 输入。"""
        if isinstance(policy, FmtTaskPolicy):
            return policy
        return FmtTaskPolicy(str(policy).lower())

    def __getattr__(self, name: str) -> Any:
        """将未覆盖的方法透传到 session.fmt。"""
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._service, name)


def _normalize_recv_delim(delim: bytes | str) -> bytes:
    """将脚本层 `delim` 统一转为 bytes。"""
    if isinstance(delim, bytes):
        return delim
    return delim.encode()


def _resolve_script_fmt_offset(
    service: FmtService,
    *,
    plan: object,
    offset: int | None,
) -> int:
    """优先使用显式 offset，其次计划内 offset，最后读取 fact 层。"""
    if offset is not None:
        return offset
    plan_offset = getattr(plan, "offset", None)
    if isinstance(plan_offset, int):
        return plan_offset
    return int(service.get_offset(required=True).index)


def _render_headed_single_task(
    service: FmtService,
    *,
    plan: "FmtWritePlan",
    offset: int,
    data_offset: int | None,
    head: bytes,
    head_numbwritten: int,
) -> RenderedFmtTask:
    """渲染带 head 的单 task payload。"""
    from pwnlib.fmtstr import AtomWrite, make_payload_dollar
    from pwnlib.util.cyclic import cyclic

    context = _script_module().context
    tasks = tuple(getattr(plan, "tasks"))
    if len(tasks) != 1:
        raise ValueError("head 目前仅支持单 task 的 write 发送。")

    task = tasks[0]
    pointer_size = int(getattr(plan, "pointer_size"))
    bits = int(getattr(plan, "bits"))
    endian = str(getattr(plan, "endian"))
    no_dollars = bool(getattr(plan, "metadata", {}).get("no_dollars", False))
    counter_size = 4 if bits <= 32 else 8
    atoms = [
        AtomWrite(atom.address, atom.width, atom.value, mask=atom.mask)
        for atom in task.atoms
    ]
    stabilization_steps = 0

    with context.local(bits=bits, endian=endian):
        if data_offset is not None:
            raw_fmt, data = make_payload_dollar(
                data_offset,
                atoms,
                numbwritten=head_numbwritten,
                countersize=counter_size,
                no_dollars=no_dollars,
            )
            required_prefix_len = (data_offset - offset) * pointer_size
            padding_len = required_prefix_len - (len(head) + len(raw_fmt))
            if padding_len < 0:
                raise ValueError("head 过长，显式 data_offset 无法容纳当前 payload。")
            resolved_data_offset = data_offset
        else:
            fmt_bytes = b""
            data = b""
            for stabilization_steps in range(1, 33):
                slot_delta = (len(head) + len(fmt_bytes)) // pointer_size
                candidate_data_offset = offset + slot_delta
                raw_fmt, data = make_payload_dollar(
                    candidate_data_offset,
                    atoms,
                    numbwritten=head_numbwritten,
                    countersize=counter_size,
                    no_dollars=no_dollars,
                )
                padding_len = (-(len(head) + len(raw_fmt))) % pointer_size
                total_prefix_len = len(head) + len(raw_fmt) + padding_len
                new_data_offset = offset + (total_prefix_len // pointer_size)
                if new_data_offset == candidate_data_offset:
                    resolved_data_offset = new_data_offset
                    break
                fmt_bytes = raw_fmt + cyclic(padding_len)
            else:
                raise RuntimeError("head payload did not converge")

    padding_bytes = cyclic(padding_len)
    current_counter = head_numbwritten
    steps: list[FmtRenderStep] = []
    for index, (chun_atom, atom) in enumerate(zip(task.atoms, atoms, strict=True)):
        padding = atom.compute_padding(current_counter)
        counter_after = (current_counter + padding) % (1 << (counter_size * 8))
        steps.append(
            FmtRenderStep(
                task_index=task.task_index,
                atom=chun_atom,
                arg_index=resolved_data_offset + index,
                specifier=_specifier_for_width(chun_atom.width),
                counter_before=current_counter,
                counter_after=counter_after,
                padding=padding,
                modulus=1 << (chun_atom.width * 8),
                address_offset=index * pointer_size,
                metadata={"backend": "pwntools", "head": head},
            )
        )
        current_counter = counter_after

    fmt_bytes = head + raw_fmt
    payload = fmt_bytes + padding_bytes + data
    return RenderedFmtTask(
        task_index=task.task_index,
        atoms=tuple(task.atoms),
        steps=tuple(steps),
        fmt_bytes=fmt_bytes,
        data_bytes=data,
        payload=payload,
        offset=offset,
        data_offset=resolved_data_offset,
        backend="pwntools",
        layout=FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter=head_numbwritten,
        final_counter=current_counter,
        metadata={
            "backend": "pwntools",
            "head": head,
            "head_numbwritten": head_numbwritten,
            "padding_len": len(padding_bytes),
            "data_offset": resolved_data_offset,
            "stabilization_steps": stabilization_steps,
        },
    )


def _execute_headed_single_task(
    service: FmtService,
    *,
    plan: object,
    rendered: RenderedFmtTask,
    offset: int,
    end: bytes | None,
) -> FmtExecutionResult:
    """执行带 head 的单 task，并包装成标准执行结果。"""
    response, dispatch, metadata = dispatch_fmt_payload(
        service.session,
        rendered.payload,
        receive=False,
        newline=(end is None),
        end=end,
        recv_bytes=4096,
        recv_until=None,
    )
    receipt = FmtExecutionReceipt(
        task_index=rendered.task_index,
        rendered=rendered,
        payload=rendered.payload,
        offset=offset,
        transport_kind=service.session.transport_spec.kind,
        dispatch=FmtExecutionMethod(dispatch),
        response=response,
        source="fmt.execute(head)",
        metadata=metadata,
    )
    return FmtExecutionResult(
        kind=FmtResultKind.EXECUTION,
        plan=plan,
        receipts=(receipt,),
        offset=offset,
        result_prefix="fmt.write",
        source="fmt.execute(head)",
        metadata={"head": rendered.metadata.get("head"), "data_offset": rendered.data_offset},
    )


def _apply_head_to_comparison(
    service: FmtService,
    result: FmtWriteComparison,
    *,
    offset: int | None,
    data_offset: int | None,
    head: bytes,
    head_numbwritten: int,
) -> FmtWriteComparison:
    """把 head 渲染逻辑应用到 compare_write 结果。"""
    candidates: list[FmtWriteCandidate] = []
    for candidate in result.candidates:
        if not candidate.ok or candidate.plan is None:
            candidates.append(candidate)
            continue
        try:
            resolved_offset = _resolve_script_fmt_offset(
                service,
                plan=candidate.plan,
                offset=offset,
            )
            rendered = _render_headed_single_task(
                service,
                plan=candidate.plan,
                offset=resolved_offset,
                data_offset=data_offset,
                head=head,
                head_numbwritten=head_numbwritten,
            )
            candidates.append(
                FmtWriteCandidate(
                    strategy=candidate.strategy,
                    plan=candidate.plan,
                    rendered_tasks=(rendered,),
                    metadata=dict(candidate.metadata),
                )
            )
        except Exception as exc:
            candidates.append(
                FmtWriteCandidate(
                    strategy=candidate.strategy,
                    error=f"{type(exc).__name__}: {exc}",
                    metadata=dict(candidate.metadata),
                )
            )
    return FmtWriteComparison(
        target=result.target,
        value=result.value,
        candidates=tuple(candidates),
        metadata=dict(result.metadata),
    )


def _specifier_for_width(width: int) -> str:
    """将写宽度映射到 `%n` 修饰符。"""
    return {
        1: "hhn",
        2: "hn",
        4: "n",
        8: "lln",
    }[width]


def _warn_for_script_fmt_send(
    rendered_items: Sequence[object],
    *,
    buflen: int | None,
    end: bytes | None,
) -> None:
    """在发送前给出长度与高 padding 风险提示。"""
    log = _script_module().log
    suffix_len = len(end or b"")
    total_send_len = sum(
        len(getattr(item, "payload", b"")) + suffix_len for item in rendered_items
    )
    max_pad = max(
        (
            int(getattr(step, "padding", 0))
            for item in rendered_items
            for step in getattr(item, "steps", ())
        ),
        default=0,
    )
    pad_time = _pad_time_for_max_padding(max_pad)

    if buflen is not None and total_send_len > buflen:
        log.error(f"fmt 发送长度 {total_send_len}B 超过 buflen={buflen}B，仍继续发送。")
    if pad_time in {"HIGH", "EXTREME"}:
        log.warning(f"fmt 的 pad_time 为 {pad_time}（max_pad={max_pad}），服务端可能变慢或超时。")


def _pad_time_for_max_padding(max_pad: int) -> str:
    """按最大 padding 粗分写入耗时等级。"""
    if max_pad < 0x100:
        return "LOW"
    if max_pad < 0x1000:
        return "MEDIUM"
    if max_pad < 0x10000:
        return "HIGH"
    return "EXTREME"


def _emit_script_timing(stage: str, start: float, *, extra: str | None = None) -> None:
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    suffix = f" | {extra}" if extra else ""
    print(f"[script-timing] {stage}: {elapsed_ms:.3f} ms{suffix}", flush=True)
