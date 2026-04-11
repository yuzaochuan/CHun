"""核心模型导出。"""

from .analysis import CrashAnalysisResult, GdbMiResult, ResolvedSymbolResult
from .records import (
    Artifact,
    ArtifactKind,
    BaseInferenceResult,
    ContextEntry,
    ContextKind,
    Fact,
    FactKind,
    Observation,
    ObservationKind,
    RecordDomain,
)
from .target import TargetKind, TargetSpec
from .transport import TransportKind, TransportSpec

__all__ = [
    "Artifact",
    "ArtifactKind",
    "BaseInferenceResult",
    "CrashAnalysisResult",
    "ContextEntry",
    "ContextKind",
    "Fact",
    "FactKind",
    "GdbMiResult",
    "Observation",
    "ObservationKind",
    "RecordDomain",
    "ResolvedSymbolResult",
    "TargetKind",
    "TargetSpec",
    "TransportKind",
    "TransportSpec",
]
