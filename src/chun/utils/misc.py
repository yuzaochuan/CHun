"""杂项工具函数。"""

from __future__ import annotations


def itob(num: int) -> bytes:
    """把整数转换为 ASCII bytes。

    菜单类 Pwn 题常见输入是数字字符串，这个函数用于减少
    `str(num).encode()` 的重复手写。
    """
    return str(num).encode()
