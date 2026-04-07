"""格式化字符串相关的扩展占位模块。"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class FmtCapability:
    """描述一个未来可扩展的 fmt 能力项。"""

    name: str
    description: str = ""


__all__ = ["FmtCapability"]
