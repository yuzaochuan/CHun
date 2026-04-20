from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...core.models import (
    FmtExecutionReceipt,
    FmtLayoutPolicy,
    FmtWritePlan,
    FmtWriteTask,
    RenderedFmtTask,
)
from .errors import FmtExecutionError
from .renderer import DefaultFmtTaskRenderer
from .runtime import dispatch_fmt_payload

if TYPE_CHECKING:
    from chun.core.session import CHunSession
    from .service import FmtTaskRenderer


@dataclass(slots=True)
class DefaultFmtPlanExecutor:
    """默认的 fmt task 执行器。"""

    renderer: "FmtTaskRenderer | None" = None
    default_recv_bytes: int = 4096

    def __post_init__(self) -> None:
        if self.renderer is None:
            self.renderer = DefaultFmtTaskRenderer()

    def execute_task(
        self,
        session: "CHunSession",
        task: FmtWriteTask,
        *,
        plan: FmtWritePlan,
        offset: int,
        rendered: RenderedFmtTask | None = None,
        layout: FmtLayoutPolicy = FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter: int = 0,
        recv_bytes: int | None = None,
        recv_until: bytes | None = None,
        receive: bool = True,
        newline: bool = True,
        source: str = "fmt.execute",
    ) -> FmtExecutionReceipt:
        rendered_task = rendered
        if rendered_task is None:
            assert self.renderer is not None
            rendered_task = self.renderer.render(
                task,
                plan=plan,
                offset=offset,
                layout=layout,
                initial_counter=initial_counter,
            )

        try:
            response, dispatch, metadata = dispatch_fmt_payload(
                session,
                rendered_task.payload,
                receive=receive,
                newline=newline,
                recv_bytes=recv_bytes or self.default_recv_bytes,
                recv_until=recv_until,
            )
        except Exception as exc:
            raise FmtExecutionError(
                f"fmt payload dispatch failed: task_index={task.task_index}"
            ) from exc
        return FmtExecutionReceipt(
            task_index=task.task_index,
            rendered=rendered_task,
            payload=rendered_task.payload,
            offset=offset,
            transport_kind=session.transport_spec.kind,
            dispatch=dispatch,
            response=response,
            source=source,
            metadata=metadata,
        )

__all__ = ["DefaultFmtPlanExecutor"]
