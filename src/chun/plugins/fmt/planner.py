from __future__ import annotations

from math import ceil
from typing import Sequence

from ...core.models import (
    FmtEndian,
    FmtTaskPolicy,
    FmtWordSize,
    FmtWriteAtom,
    FmtWritePlan,
    FmtWriteRequest,
    FmtWriteStrategy,
    FmtWriteTask,
)
from .backends import PwntoolsFmtBackend


class DefaultFmtWritePlanner:
    """默认的 fmt 规划器。

    这一层不再把自己定位成“核心 atom 优化引擎”。
    当前默认职责是：
    - 持有 backend 选择
    - 把 CHun 的 request / config 交给 backend
    - 仅在 `backend="native"` 时走旧的实验性 fallback
    """

    def __init__(self) -> None:
        self._pwntools = PwntoolsFmtBackend()
        self._native = _NativeFmtWritePlanner()

    def plan(
        self,
        requests: Sequence[FmtWriteRequest],
        *,
        bits: int,
        endian: FmtEndian,
        pointer_size: int,
        task_policy: FmtTaskPolicy,
        backend: str = "pwntools",
        write_size: str | None = None,
        write_size_max: str | None = None,
        overflows: int = 16,
        backend_strategy: str = "small",
        badbytes: bytes | bytearray | Sequence[int] = (),
        no_dollars: bool = False,
        numbwritten: int = 0,
        data_offset: int | None = None,
        fmt_offset: int | None = None,
    ) -> FmtWritePlan:
        normalized_pointer_size = self._normalize_pointer_size(pointer_size)

        if backend == "pwntools":
            resolved_write_size = (
                write_size
                if write_size is not None
                else self._infer_backend_write_size(requests)
            )
            resolved_write_size_max = (
                write_size_max
                if write_size_max is not None
                else self._infer_backend_write_size_max(requests)
            )
            return self._pwntools.build_plan(
                requests,
                bits=bits,
                endian=endian,
                pointer_size=normalized_pointer_size,
                task_policy=task_policy,
                write_size=resolved_write_size,
                write_size_max=resolved_write_size_max,
                overflows=overflows,
                strategy=backend_strategy,
                badbytes=badbytes,
                no_dollars=no_dollars,
                numbwritten=numbwritten,
                data_offset=data_offset,
                fmt_offset=fmt_offset,
            )
        if backend == "native":
            return self._native.plan(
                requests,
                bits=bits,
                endian=endian,
                pointer_size=normalized_pointer_size,
                task_policy=task_policy,
                fmt_offset=fmt_offset,
                data_offset=data_offset,
            )
        raise ValueError(f"unsupported fmt backend: {backend}")

    @staticmethod
    def _infer_backend_write_size(requests: Sequence[FmtWriteRequest]) -> str:
        if not requests:
            return "short"
        strategies = {request.strategy for request in requests}
        if len(strategies) == 1:
            strategy = next(iter(strategies))
            if strategy == FmtWriteStrategy.BYTE:
                return "byte"
            if strategy == FmtWriteStrategy.SHORT:
                return "short"
            if strategy == FmtWriteStrategy.INT:
                return "int"
        return "short"

    @staticmethod
    def _infer_backend_write_size_max(requests: Sequence[FmtWriteRequest]) -> str:
        if not requests:
            return "long"
        strategies = {request.strategy for request in requests}
        if len(strategies) == 1:
            strategy = next(iter(strategies))
            if strategy == FmtWriteStrategy.BYTE:
                return "byte"
            if strategy == FmtWriteStrategy.SHORT:
                return "short"
            if strategy == FmtWriteStrategy.INT:
                return "int"
            if strategy == FmtWriteStrategy.PTR:
                return "long"
        return "long"

    def _normalize_pointer_size(self, pointer_size: int) -> FmtWordSize:
        if pointer_size not in (1, 2, 4, 8):
            raise ValueError(f"unsupported pointer size: {pointer_size}")
        return pointer_size  # type: ignore[return-value]


class _NativeFmtWritePlanner:
    """旧的 native 切片器，仅作为 fallback 保留。"""

    def plan(
        self,
        requests: Sequence[FmtWriteRequest],
        *,
        bits: int,
        endian: FmtEndian,
        pointer_size: FmtWordSize,
        task_policy: FmtTaskPolicy,
        fmt_offset: int | None,
        data_offset: int | None,
    ) -> FmtWritePlan:
        atoms: list[FmtWriteAtom] = []

        for request_index, request in enumerate(requests):
            atoms.extend(
                self._build_request_atoms(
                    request,
                    request_index=request_index,
                    bits=bits,
                    endian=endian,
                    pointer_size=pointer_size,
                )
            )

        tasks = self._group_atoms(atoms, policy=task_policy)
        return FmtWritePlan(
            bits=bits,
            pointer_size=pointer_size,
            endian=endian,
            offset=fmt_offset,
            data_offset=data_offset,
            backend="native",
            strategy=self._infer_plan_strategy(requests),
            task_policy=task_policy,
            requests=tuple(requests),
            atoms=tuple(atoms),
            tasks=tuple(tasks),
            metadata={"backend": "native"},
        )

    def _build_request_atoms(
        self,
        request: FmtWriteRequest,
        *,
        request_index: int,
        bits: int,
        endian: FmtEndian,
        pointer_size: FmtWordSize,
    ) -> list[FmtWriteAtom]:
        width = self._resolve_unit_width(
            request,
            bits=bits,
            pointer_size=pointer_size,
        )
        self._validate_alignment(
            request.target.address,
            width=width,
            strategy=request.strategy,
            pointer_size=pointer_size,
        )

        unsigned_value = request.value.value & ((1 << bits) - 1)
        unit_bits = width * 8
        total_bits = self._resolve_value_bits(
            request,
            bits=bits,
            unit_bits=unit_bits,
            unsigned_value=unsigned_value,
        )
        piece_count = max(1, ceil(total_bits / unit_bits))
        mask = (1 << unit_bits) - 1

        atoms: list[FmtWriteAtom] = []
        for piece_index in range(piece_count):
            shift = self._piece_shift(
                piece_index,
                piece_count=piece_count,
                unit_bits=unit_bits,
                endian=endian,
            )
            atoms.append(
                FmtWriteAtom(
                    request_index=request_index,
                    piece_index=piece_index,
                    address=request.target.address + piece_index * width,
                    value=(unsigned_value >> shift) & mask,
                    width=width,
                    shift=shift,
                    mask=mask,
                    order_key=piece_index,
                    target_symbol=request.target.symbol,
                    metadata={"backend": "native"},
                )
            )
        return atoms

    def _resolve_unit_width(
        self,
        request: FmtWriteRequest,
        *,
        bits: int,
        pointer_size: FmtWordSize,
    ) -> FmtWordSize:
        requested_width = request.chunk_width
        if requested_width is None:
            requested_width = self._default_unit_width(bits, request.strategy)

        if requested_width not in (1, 2, 4, 8):
            raise ValueError(f"unsupported fmt chunk width: {requested_width}")
        if requested_width > pointer_size:
            raise ValueError(
                f"fmt chunk width {requested_width} exceeds pointer size {pointer_size}"
            )
        width = requested_width
        if request.strategy == FmtWriteStrategy.BYTE and width != 1:
            raise ValueError("BYTE strategy requires chunk width 1")
        if request.strategy == FmtWriteStrategy.SHORT and width != 2:
            raise ValueError("SHORT strategy requires chunk width 2")
        if request.strategy == FmtWriteStrategy.INT and width != 4:
            raise ValueError("INT strategy requires chunk width 4")
        if request.strategy == FmtWriteStrategy.PTR and width != pointer_size:
            raise ValueError("PTR strategy requires native pointer-sized writes")
        return width  # type: ignore[return-value]

    def _default_unit_width(self, bits: int, strategy: FmtWriteStrategy) -> FmtWordSize:
        if strategy == FmtWriteStrategy.BYTE:
            return 1
        if strategy == FmtWriteStrategy.SHORT:
            return 2
        if strategy == FmtWriteStrategy.INT:
            return 4
        if strategy == FmtWriteStrategy.PTR:
            return (bits // 8)  # type: ignore[return-value]
        return 2

    def _resolve_value_bits(
        self,
        request: FmtWriteRequest,
        *,
        bits: int,
        unit_bits: int,
        unsigned_value: int,
    ) -> int:
        if request.value_bits is not None:
            if request.value_bits <= 0:
                raise ValueError("value_bits must be positive")
            if request.value_bits > bits:
                raise ValueError("value_bits exceeds architecture bits")
            return request.value_bits
        significant_bits = unsigned_value.bit_length()
        if significant_bits == 0:
            return unit_bits
        return min(bits, ceil(significant_bits / unit_bits) * unit_bits)

    def _piece_shift(
        self,
        piece_index: int,
        *,
        piece_count: int,
        unit_bits: int,
        endian: FmtEndian,
    ) -> int:
        if endian == "little":
            return piece_index * unit_bits
        return (piece_count - 1 - piece_index) * unit_bits

    def _validate_alignment(
        self,
        address: int,
        *,
        width: FmtWordSize,
        strategy: FmtWriteStrategy,
        pointer_size: FmtWordSize,
    ) -> None:
        if strategy == FmtWriteStrategy.BYTE:
            return
        alignment = pointer_size if strategy == FmtWriteStrategy.PTR else width
        if address % alignment != 0:
            raise ValueError(
                f"unaligned fmt target address {hex(address)} for width {alignment}"
            )

    def _group_atoms(
        self,
        atoms: Sequence[FmtWriteAtom],
        *,
        policy: FmtTaskPolicy,
    ) -> list[FmtWriteTask]:
        if policy == FmtTaskPolicy.BY_ATOM:
            return [
                FmtWriteTask(task_index=index, atoms=(atom,), independent=True)
                for index, atom in enumerate(atoms)
            ]
        if policy == FmtTaskPolicy.BY_TARGET:
            buckets: dict[int, list[FmtWriteAtom]] = {}
            for atom in atoms:
                buckets.setdefault(atom.request_index, []).append(atom)
            return [
                FmtWriteTask(task_index=index, atoms=tuple(group), independent=True)
                for index, group in enumerate(buckets.values())
            ]
        return [FmtWriteTask(task_index=0, atoms=tuple(atoms), independent=True)]

    def _infer_plan_strategy(
        self,
        requests: Sequence[FmtWriteRequest],
    ) -> FmtWriteStrategy:
        if not requests:
            return FmtWriteStrategy.AUTO
        strategies = {request.strategy for request in requests}
        if len(strategies) == 1:
            return next(iter(strategies))
        return FmtWriteStrategy.MIXED


__all__ = ["DefaultFmtWritePlanner"]
