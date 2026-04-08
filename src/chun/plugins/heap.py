"""堆利用插件占位模块。

按当前迭代计划，heap 相关能力暂不在本阶段实现。
"""

from __future__ import annotations


class HeapPlugin:
    """未来堆模块的接口占位。"""

    def __init__(self) -> None:
        """初始化占位插件。"""

    def status(self) -> str:
        """返回当前实现状态。"""
        return "未实现"


__all__ = ["HeapPlugin"]
