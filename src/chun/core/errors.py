"""CHun 核心错误类型。"""

from __future__ import annotations


class CHunError(Exception):
    """CHun 的基础异常类型。"""


class RegistryError(CHunError):
    """Registry 相关基础异常。"""


class RegistryConflictError(RegistryError):
    """记录冲突或非法覆盖。"""


class RegistryNotFoundError(RegistryError):
    """请求的记录不存在。"""


class MissingDependencyError(CHunError):
    """缺少可选运行时依赖。"""


class InferenceError(CHunError):
    """Inference 相关基础异常。"""


class InferenceInputError(InferenceError):
    """Inference 输入不合法。"""


class BridgeError(CHunError):
    """Bridge 相关基础异常。"""


class DebuggerBridgeError(BridgeError):
    """调试器桥接错误。"""


class ResolverError(BridgeError):
    """符号解析桥接错误。"""


class CrashAnalysisError(BridgeError):
    """Corefile / crash 分析错误。"""


class TransportError(CHunError):
    """Transport 层基础异常。"""


class TransportConfigError(TransportError):
    """Transport 或 TargetSpec 配置不合法。"""


class TransportCapabilityError(TransportError):
    """当前 transport 不支持某项操作。"""


class TransportClosedError(TransportError):
    """Transport 尚未打开或已关闭。"""


__all__ = [
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
]
