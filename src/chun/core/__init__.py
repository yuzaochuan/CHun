"""CHun 核心模块导出。"""

from __future__ import annotations

from importlib import import_module
from typing import Any

_BRIDGE_EXPORTS = {"GdbMiBridge", "PwntoolsGdbBridge"}
_CACHE_EXPORTS = {"CacheService"}
_ANALYSIS_EXPORTS = {"CorefileAnalyzer"}
_CATALOG_EXPORTS = {"LibcCatalogService"}
_ERROR_EXPORTS = {
    "BridgeError",
    "CHunError",
    "CrashAnalysisError",
    "DebuggerBridgeError",
    "InferenceError",
    "InferenceInputError",
    "MissingDependencyError",
    "RegistryConflictError",
    "RegistryError",
    "RegistryNotFoundError",
    "ResolverError",
    "TransportCapabilityError",
    "TransportClosedError",
    "TransportConfigError",
    "TransportError",
}
_INFERENCE_EXPORTS = {"InferenceService"}
_REGISTRY_EXPORTS = {"EvidenceRegistry"}
_REPLAY_EXPORTS = {
    "InMemoryBlobStore",
    "PayloadRef",
    "ReplayCheckpoint",
    "ReplayEvent",
    "ReplayEventKind",
    "ReplayExecutor",
    "ReplayRecorder",
    "VerificationResult",
    "VerificationRun",
}
_RESOLVE_EXPORTS = {"DynELFResolver", "ResolveService"}
_SESSION_EXPORTS = {"CHunSession"}
_WORKFLOW_EXPORTS = {
    "ExploitWorkflowCompiler",
    "ProcessLauncher",
    "ProcessWorkflowRuntime",
    "WorkflowExecutor",
    "WorkflowJsonCodec",
    "WorkflowLauncher",
    "WorkflowRuntime",
    "WorkflowTranslatorRegistry",
}

__all__ = [
    "AddressLike",
    "AnalysisNode",
    "Artifact",
    "ArtifactKind",
    "AssignNode",
    "BaseInferenceResult",
    "BridgeError",
    "CacheService",
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
    "PayloadRef",
    "PrimitiveNode",
    "ProcessLauncher",
    "ProcessWorkflowRuntime",
    "PwntoolsGdbBridge",
    "ReplayCheckpoint",
    "ReplayEvent",
    "ReplayEventKind",
    "ReplayExecutor",
    "ReplayRecorder",
    "RecordDomain",
    "RecursiveCallNode",
    "RegistryConflictError",
    "RegistryError",
    "RegistryNotFoundError",
    "RenderedFmtTask",
    "ResolveService",
    "ResolvedSymbolResult",
    "ResolverError",
    "SourceSpan",
    "TargetKind",
    "TargetSpec",
    "TopLevelBlockDef",
    "TransportCapabilityError",
    "TransportClosedError",
    "TransportConfigError",
    "TransportError",
    "TransportKind",
    "TransportSpec",
    "ValueLike",
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
    if name in _BRIDGE_EXPORTS:
        return getattr(import_module("..bridges.gdb", __name__), name)
    if name in _CACHE_EXPORTS:
        return getattr(import_module(".cache", __name__), name)
    if name in _ANALYSIS_EXPORTS:
        return getattr(import_module(".analysis", __name__), name)
    if name in _CATALOG_EXPORTS:
        return getattr(import_module(".catalog", __name__), name)
    if name in _ERROR_EXPORTS:
        return getattr(import_module(".errors", __name__), name)
    if name in _INFERENCE_EXPORTS:
        return getattr(import_module(".inference", __name__), name)
    if name in _REGISTRY_EXPORTS:
        return getattr(import_module(".registry", __name__), name)
    if name in _REPLAY_EXPORTS:
        return getattr(import_module(".replay", __name__), name)
    if name in _RESOLVE_EXPORTS:
        return getattr(import_module(".resolve", __name__), name)
    if name in _SESSION_EXPORTS:
        return getattr(import_module(".session", __name__), name)
    if name in _WORKFLOW_EXPORTS:
        return getattr(import_module(".workflow", __name__), name)
    if name in __all__:
        return getattr(import_module(".models", __name__), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
