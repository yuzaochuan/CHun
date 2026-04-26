"""CHun 对外公共接口。"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_TRANSPORT_EXPORTS = {
    "BlindReconnectTransport",
    "HttpxTransport",
    "PwntoolsTubeTransport",
    "WebSocketTransport",
}
_SCRIPT_EXPORTS = {"ScriptEntry"}

__all__ = [
    "AddressLike",
    "AnalysisNode",
    "Artifact",
    "ArtifactKind",
    "AssignNode",
    "BlindReconnectTransport",
    "BridgeError",
    "CHun",
    "CHunError",
    "CHunSession",
    "CallNode",
    "ContextEntry",
    "ContextKind",
    "CorefileAnalyzer",
    "CrashAnalysisError",
    "CrashAnalysisResult",
    "DebuggerBridgeError",
    "DynELFResolver",
    "EvidenceRegistry",
    "ExpActionIR",
    "ExploitWorkflowCompiler",
    "ExprNode",
    "Fact",
    "FactKind",
    "FmtEndian",
    "FmtExecutionMethod",
    "FmtExecutionResult",
    "FmtExecutionReceipt",
    "FmtWriteCandidate",
    "FmtWriteComparison",
    "FmtWritesComparison",
    "FmtLayoutPolicy",
    "FmtLeak",
    "FmtOffset",
    "FmtOffsetProbeMode",
    "FmtOffsetProbeResult",
    "FmtReadMode",
    "FmtRenderSpecifier",
    "FmtRenderStep",
    "FmtResultKind",
    "FmtTargetOrigin",
    "FmtTargetRef",
    "FmtTaskPolicy",
    "FmtValueOrigin",
    "FmtValueRef",
    "FmtWordSize",
    "FmtWriteAtom",
    "FmtWritePlan",
    "FmtWriteRequest",
    "FmtWriteStrategy",
    "FmtWriteTask",
    "FunctionActionDef",
    "GdbMiBridge",
    "GdbMiResult",
    "HttpxTransport",
    "ImportModel",
    "ImportRef",
    "InferenceError",
    "InferenceInputError",
    "InferenceService",
    "LibcCatalogService",
    "LiteralNode",
    "MissingDependencyError",
    "NameRefNode",
    "Observation",
    "ObservationKind",
    "OpaqueCallNode",
    "PrimitiveNode",
    "ProcessLauncher",
    "ProcessWorkflowRuntime",
    "PwntoolsGdbBridge",
    "PwntoolsTubeTransport",
    "PayloadRef",
    "ReplayCheckpoint",
    "ReplayEvent",
    "ReplayEventKind",
    "ReplayExecutor",
    "ReplayRecorder",
    "RecordDomain",
    "RecursiveCallNode",
    "RegistryConflictError",
    "RegistryError",
    "RenderedFmtTask",
    "ResolveService",
    "ResolvedSymbolResult",
    "ResolverError",
    "ScriptEntry",
    "SourceSpan",
    "TargetSpec",
    "TopLevelBlockDef",
    "TransportCapabilityError",
    "TransportClosedError",
    "TransportConfigError",
    "TransportSpec",
    "ValueLike",
    "WebSocketTransport",
    "WorkflowCheckpoint",
    "WorkflowExecutionResult",
    "WorkflowExecutor",
    "WorkflowJsonCodec",
    "WorkflowLauncher",
    "WorkflowPrimitive",
    "WorkflowPrimitiveKind",
    "WorkflowRuntime",
    "WorkflowStepReceipt",
    "WorkflowTranscript",
    "WorkflowTranslatorRegistry",
    "VerificationResult",
    "VerificationRun",
    "InMemoryBlobStore",
]


def __getattr__(name: str) -> Any:
    if name == "CHun":
        return getattr(import_module(".facade", __name__), name)
    if name in _SCRIPT_EXPORTS:
        return getattr(import_module(".script", __name__), name)
    if name in _TRANSPORT_EXPORTS:
        return getattr(import_module(".transports", __name__), name)
    if name in __all__:
        return getattr(import_module(".core", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
