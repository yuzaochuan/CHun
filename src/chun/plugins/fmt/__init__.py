"""FMT plugin public exports."""

from __future__ import annotations

from dataclasses import dataclass

from ...core.models import (
    AddressLike,
    FmtEndian,
    FmtExecutionMethod,
    FmtExecutionReceipt,
    FmtLayoutPolicy,
    FmtRenderSpecifier,
    FmtRenderStep,
    FmtLeak,
    FmtOffset,
    FmtOffsetProbeMode,
    FmtOffsetProbeResult,
    FmtReadMode,
    FmtTargetRef,
    FmtTaskPolicy,
    FmtValueRef,
    FmtWordSize,
    FmtWriteAtom,
    FmtWritePlan,
    FmtWriteRequest,
    FmtWriteStrategy,
    FmtWriteTask,
    RenderedFmtTask,
    ValueLike,
)
from .blind import BlindFmtService
from .planner import DefaultFmtWritePlanner
from .probes import FmtOffsetNotFoundError, FmtOffsetProbe, FmtOffsetProbeError
from .readers import DefaultFmtReadExecutor
from .renderer import DefaultFmtTaskRenderer
from .writers import DefaultFmtPlanExecutor
from .service import (
    FmtPlanExecutor,
    FmtReadExecutor,
    FmtService,
    FmtTaskRenderer,
    FmtWritePlanner,
)


@dataclass(slots=True)
class FmtCapability:
    """描述 fmt 子系统已暴露的能力项。"""

    name: str
    description: str = ""


__all__ = [
    "AddressLike",
    "BlindFmtService",
    "DefaultFmtReadExecutor",
    "DefaultFmtPlanExecutor",
    "DefaultFmtWritePlanner",
    "DefaultFmtTaskRenderer",
    "FmtCapability",
    "FmtEndian",
    "FmtExecutionMethod",
    "FmtExecutionReceipt",
    "FmtLayoutPolicy",
    "FmtRenderSpecifier",
    "FmtRenderStep",
    "FmtLeak",
    "FmtOffset",
    "FmtOffsetProbeMode",
    "FmtOffsetProbeResult",
    "FmtOffsetNotFoundError",
    "FmtOffsetProbe",
    "FmtOffsetProbeError",
    "FmtPlanExecutor",
    "FmtReadExecutor",
    "FmtReadMode",
    "FmtService",
    "FmtTargetRef",
    "FmtTaskPolicy",
    "FmtTaskRenderer",
    "FmtValueRef",
    "FmtWordSize",
    "FmtWriteAtom",
    "FmtWritePlan",
    "FmtWritePlanner",
    "FmtWriteRequest",
    "FmtWriteStrategy",
    "FmtWriteTask",
    "RenderedFmtTask",
    "ValueLike",
]
