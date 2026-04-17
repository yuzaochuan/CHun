from __future__ import annotations

from ...core.models import (
    FmtLayoutPolicy,
    FmtRenderSpecifier,
    FmtRenderStep,
    FmtWritePlan,
    FmtWriteTask,
    RenderedFmtTask,
)


class DefaultFmtTaskRenderer:
    """默认的 task 级 fmt 渲染器。"""

    def render(
        self,
        task: FmtWriteTask,
        *,
        plan: FmtWritePlan,
        offset: int,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
    ) -> RenderedFmtTask:
        ordered_atoms = tuple(
            sorted(
                task.atoms,
                key=lambda atom: (atom.order_key, atom.request_index, atom.piece_index),
            )
        )
        current_counter = initial_counter
        step_chunks: list[bytes] = []
        steps: list[FmtRenderStep] = []

        for index, atom in enumerate(ordered_atoms):
            specifier = self._specifier_for_width(atom.width)
            modulus = 1 << (atom.width * 8)
            padding = (atom.value % modulus - (current_counter % modulus)) % modulus
            arg_index = offset + index

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
                )
            )
            current_counter += padding

        payload = self._build_payload(
            ordered_atoms,
            step_chunks=tuple(step_chunks),
            pointer_size=plan.pointer_size,
            endian=plan.endian,
            layout=layout,
        )
        return RenderedFmtTask(
            task_index=task.task_index,
            atoms=ordered_atoms,
            steps=tuple(steps),
            payload=payload,
            offset=offset,
            layout=layout,
            initial_counter=initial_counter,
            final_counter=current_counter,
        )

    def _build_payload(
        self,
        atoms: tuple[object, ...],
        *,
        step_chunks: tuple[bytes, ...],
        pointer_size: int,
        endian: str,
        layout: FmtLayoutPolicy,
    ) -> bytes:
        address_chunks = tuple(
            atom.address.to_bytes(pointer_size, byteorder=endian, signed=False)
            for atom in atoms
        )
        format_bytes = b"".join(step_chunks)
        address_bytes = b"".join(address_chunks)

        if layout == FmtLayoutPolicy.ADDRESSES_FIRST:
            return address_bytes + format_bytes
        if layout == FmtLayoutPolicy.ADDRESSES_LAST:
            return format_bytes + address_bytes
        if layout == FmtLayoutPolicy.INTERLEAVED:
            parts: list[bytes] = []
            for chunk, address in zip(step_chunks, address_chunks):
                parts.append(chunk)
                parts.append(address)
            return b"".join(parts)
        raise ValueError(f"unsupported fmt layout policy: {layout}")

    def _specifier_for_width(self, width: int) -> FmtRenderSpecifier:
        if width == 1:
            return "hhn"
        if width == 2:
            return "hn"
        if width == 4:
            return "n"
        if width == 8:
            return "lln"
        raise ValueError(f"unsupported fmt render width: {width}")


__all__ = ["DefaultFmtTaskRenderer"]
