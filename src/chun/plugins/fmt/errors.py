from __future__ import annotations

from ...core.errors import CHunError


class FmtError(CHunError):
    """FMT 子系统基础异常。"""


class FmtConfigurationError(FmtError):
    """FMT 子系统缺少必要 backend 或配置。"""


class FmtOffsetMissingError(FmtError):
    """缺少已确认的 fmt.offset。"""


class FmtSymbolResolveError(FmtError):
    """FMT 目标/值符号解析失败。"""


class FmtReadError(FmtError):
    """FMT 读链执行失败。"""


class FmtWriteError(FmtError):
    """FMT 写链执行失败。"""


class FmtDataOffsetResolutionError(FmtWriteError):
    """FMT 追加地址区 data_offset 解析/收敛失败。"""


class FmtExecutionError(FmtWriteError):
    """FMT task 执行阶段失败。"""


__all__ = [
    "FmtConfigurationError",
    "FmtDataOffsetResolutionError",
    "FmtError",
    "FmtExecutionError",
    "FmtOffsetMissingError",
    "FmtReadError",
    "FmtSymbolResolveError",
    "FmtWriteError",
]
