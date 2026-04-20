from __future__ import annotations

from ...core.models import FmtLayoutPolicy, FmtRenderStep, RenderedFmtTask
from .backends import PwntoolsFmtBackend
from .errors import FmtWriteError


class DefaultFmtTaskRenderer:
    """默认的 task 级渲染器。

    当前默认职责不再是“自研 padding 排序器”，而是：
    - 对接 backend 生成的 fmt/data
    - 把 backend 结果包装成 CHun 的 `RenderedFmtTask`
    - 仅在 `backend="native"` 时才走旧实现的极薄 fallback
    """

    def __init__(self) -> None:
        self._pwntools = PwntoolsFmtBackend()

    def render(
        self,
        task,
        *,
        plan,
        offset: int,
        data_offset: int | None = None,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
    ) -> RenderedFmtTask:
        if plan.backend == "pwntools":
            if layout != FmtLayoutPolicy.ADDRESSES_LAST:
                raise FmtWriteError(
                    "pwntools backend only supports ADDRESSES_LAST layout"
                )
            resolved_data_offset = (
                data_offset if data_offset is not None else plan.data_offset
            )
            if resolved_data_offset is None:
                raise FmtWriteError(
                    "pwntools backend requires explicit data_offset or plan.data_offset"
                )
            rendered = self._pwntools.render_task(
                task,
                plan=plan,
                data_offset=resolved_data_offset,
                initial_counter=initial_counter,
            )
            return RenderedFmtTask(
                task_index=task.task_index,
                atoms=tuple(task.atoms),
                steps=rendered.steps,
                fmt_bytes=rendered.fmt,
                data_bytes=rendered.data,
                payload=rendered.payload,
                offset=offset,
                data_offset=resolved_data_offset,
                backend=plan.backend,
                layout=layout,
                initial_counter=initial_counter,
                final_counter=rendered.final_counter,
                metadata={
                    **rendered.metadata,
                    "fmt_offset": offset,
                    "data_offset": resolved_data_offset,
                },
            )

        # native fallback：仅保留最小兼容路径
        ordered_atoms = tuple(
            sorted(
                task.atoms,
                key=lambda atom: (atom.order_key, atom.request_index, atom.piece_index),
            )
        )
        current_counter = initial_counter
        step_chunks: list[bytes] = []
        steps: list[FmtRenderStep] = []
        resolved_data_offset = data_offset if data_offset is not None else offset

        for index, atom in enumerate(ordered_atoms):
            specifier = self._specifier_for_width(atom.width)
            modulus = 1 << (atom.width * 8)
            padding = (atom.value % modulus - (current_counter % modulus)) % modulus
            arg_index = resolved_data_offset + index

            chunk = b""
            if padding > 0:
                chunk += f"%{padding}c".encode()
            chunk += f"%{arg_index}${specifier}".encode()
            step_chunks.append(chunk)
            steps.append(
                FmtRenderStep(
                    task_index=task.task_index,
                    atom=atom,
                    arg_index=arg_index,
                    specifier=specifier,
                    counter_before=current_counter,
                    counter_after=current_counter + padding,
                    padding=padding,
                    modulus=modulus,
                    address_offset=index * plan.pointer_size,
                    metadata={"backend": "native"},
                )
            )
            current_counter += padding

        fmt_bytes = b"".join(step_chunks)
        data_bytes = b"".join(
            atom.address.to_bytes(plan.pointer_size, byteorder=plan.endian, signed=False)
            for atom in ordered_atoms
        )
        payload = (
            data_bytes + fmt_bytes
            if layout == FmtLayoutPolicy.ADDRESSES_FIRST
            else fmt_bytes + data_bytes
            if layout == FmtLayoutPolicy.ADDRESSES_LAST
            else b"".join(
                part
                for atom, chunk in zip(ordered_atoms, step_chunks, strict=True)
                for part in (
                    chunk,
                    atom.address.to_bytes(
                        plan.pointer_size, byteorder=plan.endian, signed=False
                    ),
                )
            )
        )
        return RenderedFmtTask(
            task_index=task.task_index,
            atoms=ordered_atoms,
            steps=tuple(steps),
            fmt_bytes=fmt_bytes,
            data_bytes=data_bytes,
            payload=payload,
            offset=offset,
            data_offset=resolved_data_offset,
            backend=plan.backend,
            layout=layout,
            initial_counter=initial_counter,
            final_counter=current_counter,
            metadata={"backend": plan.backend, "fallback": True},
        )

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
        raise FmtWriteError(f"unsupported fmt render width: {width}")


__all__ = ["DefaultFmtTaskRenderer"]
