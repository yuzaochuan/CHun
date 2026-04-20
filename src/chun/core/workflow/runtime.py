"""workflow runtime 抽象与 process backend。"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from ..models import (
    ContextKind,
    ObservationKind,
    RecordDomain,
    WorkflowCheckpoint,
    WorkflowPrimitive,
    WorkflowStepReceipt,
)
from ..session import CHunSession
from .launchers import ProcessLauncher, WorkflowLauncher


class WorkflowRuntime(Protocol):
    """最小 workflow runtime 接口。"""

    def start_session(
        self,
        *,
        launcher: WorkflowLauncher | None = None,
        primitive: WorkflowPrimitive | None = None,
    ) -> CHunSession: ...

    def execute_primitive(
        self,
        session: CHunSession,
        primitive: WorkflowPrimitive,
        *,
        step_index: int,
    ) -> WorkflowStepReceipt: ...

    def checkpoint(
        self,
        session: CHunSession,
        checkpoint: WorkflowCheckpoint,
        *,
        step_index: int,
    ) -> WorkflowStepReceipt: ...

    def close_session(self, session: CHunSession) -> None: ...


class ProcessWorkflowRuntime:
    """第一版本地 process runtime。"""

    def start_session(
        self,
        *,
        launcher: WorkflowLauncher | None = None,
        primitive: WorkflowPrimitive | None = None,
    ) -> CHunSession:
        resolved_launcher = launcher
        if resolved_launcher is None:
            if primitive is None or primitive.kind != "session_init":
                raise RuntimeError("workflow runtime requires launcher or session_init primitive")
            binary = primitive.payload
            if not isinstance(binary, str) or not binary:
                raise RuntimeError("session_init primitive requires binary path payload")
            launcher_kwargs = primitive.metadata.get("launcher_kwargs", {})
            if not isinstance(launcher_kwargs, Mapping):
                raise RuntimeError("session_init launcher_kwargs must be a mapping")
            resolved_launcher = ProcessLauncher(
                binary=binary,
                argv=launcher_kwargs.get("argv"),
                libc=launcher_kwargs.get("libc"),
                ld=launcher_kwargs.get("ld"),
                env=launcher_kwargs.get("env"),
                cwd=launcher_kwargs.get("cwd"),
                log_level=str(launcher_kwargs.get("log_level", "info")),
                terminal=launcher_kwargs.get("terminal"),
            )
        return resolved_launcher.launch(primitive)

    def execute_primitive(
        self,
        session: CHunSession,
        primitive: WorkflowPrimitive,
        *,
        step_index: int,
    ) -> WorkflowStepReceipt:
        if primitive.kind == "send":
            payload = self._coerce_bytes(primitive.payload)
            session.io.send(payload)
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                transport_kind=session.transport_spec.kind,
                metadata={"sent": payload, "dispatch": "send"},
            )
        if primitive.kind == "sendline":
            payload = self._coerce_bytes(primitive.payload)
            session.io.sendline(payload)
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                transport_kind=session.transport_spec.kind,
                metadata={"sent": payload, "dispatch": "sendline"},
            )
        if primitive.kind == "expect":
            delim = self._coerce_bytes(primitive.payload)
            response = session.io.recvuntil(delim)
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                response=response,
                transport_kind=session.transport_spec.kind,
                metadata={"delimiter": delim, "dispatch": "recvuntil"},
            )
        if primitive.kind == "recv":
            size = primitive.payload if isinstance(primitive.payload, int) else 4096
            response = session.io.recv(size)
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                response=response,
                transport_kind=session.transport_spec.kind,
                metadata={"size": size, "dispatch": "recv"},
            )
        raise RuntimeError(f"unsupported workflow primitive for process runtime: {primitive.kind}")

    def checkpoint(
        self,
        session: CHunSession,
        checkpoint: WorkflowCheckpoint,
        *,
        step_index: int,
    ) -> WorkflowStepReceipt:
        session.rec.set_context(
            "workflow.current_checkpoint",
            checkpoint.name,
            kind=ContextKind.SESSION,
            domain=RecordDomain.WORKFLOW,
            source="workflow.checkpoint",
            overwrite=True,
        )
        return WorkflowStepReceipt(
            step_index=step_index,
            primitive=WorkflowPrimitive(
                kind="checkpoint",
                checkpoint=checkpoint,
                source_action=checkpoint.source_action,
                source_node=checkpoint.source_node,
                metadata=checkpoint.metadata,
            ),
            success=True,
            transport_kind=session.transport_spec.kind,
            checkpoint=checkpoint,
            metadata={"checkpoint": checkpoint.name},
        )

    def close_session(self, session: CHunSession) -> None:
        session.close()

    @staticmethod
    def _coerce_bytes(value: object | None) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode()
        raise TypeError(f"workflow payload is not bytes-compatible: {type(value).__name__}")


__all__ = ["ProcessWorkflowRuntime", "WorkflowRuntime"]
