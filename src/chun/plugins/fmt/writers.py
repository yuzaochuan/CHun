from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable

from ...core.models import (
    FmtExecutionMethod,
    FmtExecutionReceipt,
    FmtLayoutPolicy,
    FmtWritePlan,
    FmtWriteTask,
    RenderedFmtTask,
)
from .renderer import DefaultFmtTaskRenderer

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

        response, dispatch, metadata = self._dispatch_payload(
            session,
            rendered_task.payload,
            receive=receive,
            newline=newline,
            recv_bytes=recv_bytes or self.default_recv_bytes,
            recv_until=recv_until,
        )
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

    def _dispatch_payload(
        self,
        session: "CHunSession",
        payload: bytes,
        *,
        receive: bool,
        newline: bool,
        recv_bytes: int,
        recv_until: bytes | None,
    ) -> tuple[bytes | None, FmtExecutionMethod, dict[str, object]]:
        transport = session.io

        if self._supports_exchange(session):
            receiver = self._build_exchange_receiver(
                receive=receive,
                recv_until=recv_until,
                recv_bytes=recv_bytes,
            )
            response = transport.exchange(payload, receive=receiver, newline=newline)
            return response, FmtExecutionMethod.EXCHANGE, {
                "receive": receive,
                "recv_until": recv_until,
                "recv_bytes": recv_bytes,
                "newline": newline,
            }

        if newline:
            transport.sendline(payload)
            dispatch = FmtExecutionMethod.SENDLINE
        else:
            transport.send(payload)
            dispatch = FmtExecutionMethod.SEND

        response = None
        if receive:
            if recv_until is not None:
                response = transport.recvuntil(recv_until)
            else:
                response = transport.recv(recv_bytes)

        return response, dispatch, {
            "receive": receive,
            "recv_until": recv_until,
            "recv_bytes": recv_bytes,
            "newline": newline,
        }

    @staticmethod
    def _supports_exchange(session: "CHunSession") -> bool:
        return bool(
            session.transport_spec.kind == "blind-reconnect"
            and hasattr(session.transport, "exchange")
        )

    @staticmethod
    def _build_exchange_receiver(
        *,
        receive: bool,
        recv_until: bytes | None,
        recv_bytes: int,
    ) -> Callable[[Any], bytes | None] | None:
        if not receive:
            return None
        if recv_until is not None:
            return lambda raw: raw.recvuntil(recv_until)
        return lambda raw: raw.recv(recv_bytes)


__all__ = ["DefaultFmtPlanExecutor"]
