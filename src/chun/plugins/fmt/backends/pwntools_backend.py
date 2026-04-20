from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from ...._compat import context
from ....core.models import (
    FmtEndian,
    FmtRenderStep,
    FmtTaskPolicy,
    FmtWriteAtom,
    FmtWritePlan,
    FmtWriteRequest,
    FmtWriteStrategy,
    FmtWriteTask,
)
from ..errors import FmtDataOffsetResolutionError


@dataclass(slots=True, frozen=True)
class PwntoolsRenderedPayload:
    """pwntools backend 输出的拆分 payload。"""

    fmt: bytes
    data: bytes
    payload: bytes
    data_offset: int
    initial_counter: int
    final_counter: int
    steps: tuple[FmtRenderStep, ...]
    metadata: dict[str, object]


class PwntoolsFmtBackend:
    """基于 pwntools fmtstr 的 write payload backend。

    这里负责真正的 atom 生成、排序和 fmt/data 拆分。
    CHun 上层继续保留 typed plan/result、registry 和 execution orchestration。
    """

    name = "pwntools"
    _MAX_DATA_OFFSET_STEPS = 32

    def build_plan(
        self,
        requests: Sequence[FmtWriteRequest],
        *,
        bits: int,
        endian: FmtEndian,
        pointer_size: int,
        task_policy: FmtTaskPolicy,
        write_size: str,
        write_size_max: str,
        overflows: int,
        strategy: str,
        badbytes: bytes | bytearray | Iterable[int],
        no_dollars: bool,
        numbwritten: int,
        data_offset: int | None,
        fmt_offset: int | None,
    ) -> FmtWritePlan:
        from pwnlib.fmtstr import make_atoms

        writes = self._build_writes_map(requests, bits=bits, endian=endian)
        normalized_badbytes = frozenset(int(b) for b in badbytes)

        with context.local(bits=bits, endian=endian):
            atoms = make_atoms(
                writes,
                self._write_size_to_width(write_size),
                self._write_size_to_width(write_size_max),
                numbwritten,
                overflows,
                strategy,
                normalized_badbytes,
            )

        chun_atoms = tuple(self._to_chun_atom(atom, requests=requests) for atom in atoms)
        tasks = tuple(self._group_atoms(chun_atoms, policy=task_policy))
        return FmtWritePlan(
            bits=bits,
            pointer_size=pointer_size,  # type: ignore[arg-type]
            endian=endian,
            offset=fmt_offset,
            data_offset=data_offset,
            backend=self.name,
            strategy=self._infer_plan_strategy(requests),
            task_policy=task_policy,
            requests=tuple(requests),
            atoms=chun_atoms,
            tasks=tasks,
            metadata={
                "backend": self.name,
                "write_size": write_size,
                "write_size_max": write_size_max,
                "overflows": overflows,
                "backend_strategy": strategy,
                "badbytes": bytes(sorted(normalized_badbytes)),
                "no_dollars": no_dollars,
                "numbwritten": numbwritten,
                "fmt_offset": fmt_offset,
                "data_offset": data_offset,
                "writes": writes,
            },
        )

    def render_task(
        self,
        task: FmtWriteTask,
        *,
        plan: FmtWritePlan,
        fmt_offset: int,
        data_offset: int | None,
        initial_counter: int,
    ) -> PwntoolsRenderedPayload:
        from pwnlib.fmtstr import AtomWrite, make_payload_dollar
        from pwnlib.util.cyclic import cyclic

        no_dollars = bool(plan.metadata.get("no_dollars", False))
        counter_size = 4 if plan.bits <= 32 else 8
        atoms = [self._to_pwntools_atom(atom) for atom in task.atoms]
        resolved_data_offset: int
        stabilization_steps = 0

        with context.local(bits=plan.bits, endian=plan.endian):
            if data_offset is not None:
                fmt_bytes, data_bytes = make_payload_dollar(
                    data_offset,
                    atoms,
                    numbwritten=initial_counter,
                    countersize=counter_size,
                    no_dollars=no_dollars,
                )
                padding_len = self._required_padding_len(
                    fmt_len=len(fmt_bytes),
                    fmt_offset=fmt_offset,
                    data_offset=data_offset,
                    pointer_size=plan.pointer_size,
                )
                resolved_data_offset = data_offset
            else:
                fmt_bytes = b""
                data_bytes = b""
                for stabilization_steps in range(1, self._MAX_DATA_OFFSET_STEPS + 1):
                    slot_delta = len(fmt_bytes) // plan.pointer_size
                    candidate_data_offset = fmt_offset + slot_delta
                    raw_fmt_bytes, data_bytes = make_payload_dollar(
                        candidate_data_offset,
                        atoms,
                        numbwritten=initial_counter,
                        countersize=counter_size,
                        no_dollars=no_dollars,
                    )
                    padding_len = (-len(raw_fmt_bytes)) % plan.pointer_size
                    aligned_prefix_len = len(raw_fmt_bytes) + padding_len
                    new_data_offset = fmt_offset + (aligned_prefix_len // plan.pointer_size)
                    if new_data_offset == candidate_data_offset:
                        fmt_bytes = raw_fmt_bytes
                        resolved_data_offset = new_data_offset
                        break
                    fmt_bytes = raw_fmt_bytes + cyclic(padding_len)
                else:
                    raise FmtDataOffsetResolutionError(
                        "fmt append-address data_offset did not converge"
                    )
            padding_bytes = cyclic(padding_len)

        current_counter = initial_counter
        steps: list[FmtRenderStep] = []
        for index, (chun_atom, atom) in enumerate(zip(task.atoms, atoms, strict=True)):
            padding = atom.compute_padding(current_counter)
            counter_after = (current_counter + padding) % (1 << (counter_size * 8))
            steps.append(
                FmtRenderStep(
                    task_index=task.task_index,
                    atom=chun_atom,
                    arg_index=resolved_data_offset + index,
                    specifier=self._specifier_for_width(chun_atom.width),
                    counter_before=current_counter,
                    counter_after=counter_after,
                    padding=padding,
                    modulus=1 << (chun_atom.width * 8),
                    address_offset=index * plan.pointer_size,
                    metadata={"backend": self.name},
                )
            )
            current_counter = counter_after

        return PwntoolsRenderedPayload(
            fmt=fmt_bytes,
            data=data_bytes,
            payload=fmt_bytes + padding_bytes + data_bytes,
            data_offset=resolved_data_offset,
            initial_counter=initial_counter,
            final_counter=current_counter,
            steps=tuple(steps),
            metadata={
                "backend": self.name,
                "fmt_len": len(fmt_bytes),
                "padding_len": len(padding_bytes),
                "data_len": len(data_bytes),
                "no_dollars": no_dollars,
                "fmt_offset": fmt_offset,
                "explicit_data_offset": data_offset is not None,
                "stabilization_steps": stabilization_steps,
            },
        )

    @staticmethod
    def _required_padding_len(
        *,
        fmt_len: int,
        fmt_offset: int,
        data_offset: int,
        pointer_size: int,
    ) -> int:
        slot_delta = data_offset - fmt_offset
        if slot_delta < 0:
            raise FmtDataOffsetResolutionError(
                "explicit data_offset must be greater than or equal to fmt_offset"
            )
        required_prefix_len = slot_delta * pointer_size
        if required_prefix_len < fmt_len:
            raise FmtDataOffsetResolutionError(
                "explicit data_offset is too small for rendered fmt prefix"
            )
        return required_prefix_len - fmt_len

    def _build_writes_map(
        self,
        requests: Sequence[FmtWriteRequest],
        *,
        bits: int,
        endian: FmtEndian,
    ) -> dict[int, bytes]:
        result: dict[int, bytes] = {}
        byteorder = "little" if endian == "little" else "big"
        for request in requests:
            byte_len = self._resolve_request_byte_len(request, bits=bits)
            result[request.target.address] = int(request.value.value).to_bytes(
                byte_len,
                byteorder=byteorder,
                signed=False,
            )
        return result

    @staticmethod
    def _resolve_request_byte_len(request: FmtWriteRequest, *, bits: int) -> int:
        pointer_size = bits // 8
        if request.chunk_width is not None:
            unit_width = request.chunk_width
        elif request.strategy == FmtWriteStrategy.BYTE:
            unit_width = 1
        elif request.strategy == FmtWriteStrategy.SHORT:
            unit_width = 2
        elif request.strategy == FmtWriteStrategy.INT:
            unit_width = 4
        elif request.strategy == FmtWriteStrategy.PTR:
            unit_width = pointer_size
        else:
            unit_width = 1

        value_bits = (
            request.value_bits
            if request.value_bits is not None
            else max(unit_width * 8, int(request.value.value).bit_length())
        )
        byte_len = max(unit_width, (value_bits + 7) // 8)
        return max(1, min(pointer_size, byte_len))

    def _to_chun_atom(
        self,
        atom: object,
        *,
        requests: Sequence[FmtWriteRequest],
    ) -> FmtWriteAtom:
        start = int(getattr(atom, "start"))
        size = int(getattr(atom, "size"))
        integer = int(getattr(atom, "integer"))
        mask = getattr(atom, "mask", None)

        request_index, piece_index, target_symbol = self._match_request(
            start,
            requests,
            atom_size=size,
        )
        return FmtWriteAtom(
            request_index=request_index,
            piece_index=piece_index,
            address=start,
            value=integer,
            width=size,  # type: ignore[arg-type]
            shift=piece_index * size * 8,
            mask=int(mask) if mask is not None else None,
            order_key=integer,
            target_symbol=target_symbol,
            metadata={"backend": self.name},
        )

    @staticmethod
    def _to_pwntools_atom(atom: FmtWriteAtom) -> object:
        from pwnlib.fmtstr import AtomWrite

        return AtomWrite(atom.address, atom.width, atom.value, mask=atom.mask)

    @staticmethod
    def _match_request(
        address: int,
        requests: Sequence[FmtWriteRequest],
        *,
        atom_size: int,
    ) -> tuple[int, int, str | None]:
        for request_index, request in enumerate(requests):
            start = request.target.address
            width = max(1, (request.value_bits + 7) // 8) if request.value_bits else 8
            if start <= address < start + width:
                piece_index = max(0, (address - start) // atom_size)
                return request_index, piece_index, request.target.symbol
        return 0, 0, None

    @staticmethod
    def _group_atoms(
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

    @staticmethod
    def _write_size_to_width(write_size: str) -> int:
        mapping = {"byte": 1, "short": 2, "int": 4, "long": 8}
        if write_size not in mapping:
            raise ValueError(f"unsupported pwntools fmt write size: {write_size}")
        return mapping[write_size]

    @staticmethod
    def _infer_plan_strategy(
        requests: Sequence[FmtWriteRequest],
    ) -> FmtWriteStrategy:
        if not requests:
            return FmtWriteStrategy.AUTO
        strategies = {request.strategy for request in requests}
        if len(strategies) == 1:
            return next(iter(strategies))
        return FmtWriteStrategy.MIXED

    @staticmethod
    def _specifier_for_width(width: int) -> str:
        if width == 1:
            return "hhn"
        if width == 2:
            return "hn"
        if width == 4:
            return "n"
        if width == 8:
            return "lln"
        raise ValueError(f"unsupported pwntools atom width: {width}")


__all__ = ["PwntoolsFmtBackend", "PwntoolsRenderedPayload"]
