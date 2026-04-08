"""CHun 核心错误类型。"""

from __future__ import annotations


class CHunError(Exception):
    """CHun 的基础异常类型。"""


class MissingDependencyError(CHunError):
    """缺少可选运行时依赖。"""


class TransportError(CHunError):
    """Transport 层基础异常。"""


class TransportConfigError(TransportError):
    """Transport 或 TargetSpec 配置不合法。"""


class TransportCapabilityError(TransportError):
    """当前 transport 不支持某项操作。"""


class TransportClosedError(TransportError):
    """Transport 尚未打开或已关闭。"""


__all__ = [
    "CHunError",
    "MissingDependencyError",
    "TransportCapabilityError",
    "TransportClosedError",
    "TransportConfigError",
    "TransportError",
]
