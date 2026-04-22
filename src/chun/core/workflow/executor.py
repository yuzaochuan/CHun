"""Workflow transcript 执行器。"""

from __future__ import annotations

from typing import Callable

from ..models import (
    ArtifactKind,
    ContextKind,
    ObservationKind,
    RecordDomain,
    WorkflowExecutionResult,
    WorkflowPrimitive,
    WorkflowStepReceipt,
    WorkflowTranscript,
)
from .launchers import WorkflowLauncher
from .runtime import ProcessWorkflowRuntime, WorkflowRuntime, WorkflowScriptFacade


class WorkflowExecutor:
    """遍历 transcript，并通过 runtime 执行。"""

    def __init__(self, runtime: WorkflowRuntime | None = None) -> None:
        self.runtime = runtime if runtime is not None else ProcessWorkflowRuntime()

    def execute(
        self,
        transcript: WorkflowTranscript,
        *,
        launcher: WorkflowLauncher | None = None,
        artifact_prefix: str = "workflow.exec",
        record: bool = True,
        on_complete: Callable[[object, WorkflowExecutionResult], None] | None = None,
    ) -> WorkflowExecutionResult:
        session = None
        env: dict[str, object] = {}
        receipts: list[WorkflowStepReceipt] = []
        final_checkpoint = None
        try:
            for index, primitive in enumerate(transcript.primitives):
                if primitive.kind == "session_init":
                    if session is not None:
                        raise RuntimeError("workflow session already started")
                    session = self.runtime.start_session(launcher=launcher, primitive=primitive)
                    receipt = WorkflowStepReceipt(
                        step_index=index,
                        primitive=primitive,
                        success=True,
                        transport_kind=session.transport_spec.kind,
                        metadata={"started": True},
                    )
                    bind_target = primitive.metadata.get("bind_target")
                    if isinstance(bind_target, str) and bind_target:
                        env[bind_target] = WorkflowScriptFacade(session)
                elif primitive.kind == "checkpoint":
                    if primitive.checkpoint is None:
                        raise RuntimeError("checkpoint primitive requires WorkflowCheckpoint")
                    if session is None:
                        receipt = WorkflowStepReceipt(
                            step_index=index,
                            primitive=primitive,
                            success=True,
                            checkpoint=primitive.checkpoint,
                            metadata={"checkpoint": primitive.checkpoint.name, "pending_session": True},
                        )
                    else:
                        receipt = self.runtime.checkpoint(
                            session,
                            primitive.checkpoint,
                            step_index=index,
                        )
                    final_checkpoint = primitive.checkpoint
                else:
                    if session is None:
                        session = self.runtime.start_session(launcher=launcher, primitive=None)
                    receipt = self.runtime.execute_primitive(
                        session,
                        primitive,
                        step_index=index,
                        env=env,
                    )
                receipts.append(receipt)
                if record and session is not None:
                    self._record_receipt(session, artifact_prefix, transcript, receipt)

            result = WorkflowExecutionResult(
                transcript=transcript,
                receipts=tuple(receipts),
                final_checkpoint=final_checkpoint,
                metadata={"artifact_prefix": artifact_prefix},
            )
            if record and session is not None:
                session.rec.record_artifact(
                    f"{artifact_prefix}.result",
                    result,
                    kind=ArtifactKind.GENERIC,
                    domain=RecordDomain.WORKFLOW,
                    source="workflow.execute",
                    overwrite=True,
                )
                session.rec.record_artifact(
                    f"{artifact_prefix}.transcript",
                    transcript,
                    kind=ArtifactKind.GENERIC,
                    domain=RecordDomain.WORKFLOW,
                    source="workflow.execute",
                    overwrite=True,
                )
                if final_checkpoint is not None:
                    session.rec.set_context(
                        "workflow.current_checkpoint",
                        final_checkpoint.name,
                        kind=ContextKind.SESSION,
                        domain=RecordDomain.WORKFLOW,
                        source="workflow.execute",
                        overwrite=True,
                    )
                if on_complete is not None:
                    on_complete(session, result)
            return result
        finally:
            if session is not None:
                self.runtime.close_session(session)

    @staticmethod
    def _record_receipt(session, prefix: str, transcript: WorkflowTranscript, receipt: WorkflowStepReceipt) -> None:
        step_name = f"{prefix}.step.{receipt.step_index}"
        session.rec.record_artifact(
            step_name,
            receipt,
            kind=ArtifactKind.GENERIC,
            domain=RecordDomain.WORKFLOW,
            source="workflow.execute",
            overwrite=True,
        )
        if receipt.response is not None:
            session.rec.record_observation(
                f"{prefix}.response.{receipt.step_index}",
                receipt.response,
                kind=ObservationKind.SCALAR,
                domain=RecordDomain.WORKFLOW,
                source="workflow.execute",
                overwrite=True,
            )


__all__ = ["WorkflowExecutor"]
