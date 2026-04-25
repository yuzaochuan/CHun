"""pwntools 兼容层。

这个模块把 CHun 里会用到的 pwntools 对象统一在一个地方导入。
如果运行环境里没有安装 pwntools，会提供可读的降级报错，
这样排错时能一眼看出缺的依赖是什么。
"""

from __future__ import annotations

import logging
from typing import Any

LOGGER = logging.getLogger("chun")


def _runtime_error(name: str) -> RuntimeError:
    """构造统一的运行期错误信息。"""
    return RuntimeError(f"使用 '{name}' 需要 pwntools，请先安装：pip install pwntools")


try:
    from pwn import (
        ELF,
        Corefile,
        DynELF,
        MemLeak,
        ROP,
        args,  # type: ignore
        context,
        cyclic_find,
        gdb,
        log,
        pause,
        process,
        remote,
        ssh,
    )
except Exception:  # pragma: no cover

    class _Args:
        """pwntools 命令行参数的降级命名空间。"""

        REMOTE: bool = False
        GDB: bool = False

    class _Context:
        """pwntools ``context`` 的降级版本，只保留项目所需字段。"""

        binary: Any = None
        log_level: str = "info"
        terminal: list[str] = ["tmux", "splitw", "-h", "-d"]

    class _FallbackLog:
        """简单日志适配器，接口尽量贴合 pwntools 的 ``log``。"""

        def info(self, message: str) -> None:
            LOGGER.info(message)

        def warning(self, message: str) -> None:
            LOGGER.warning(message)

        def warn(self, message: str) -> None:
            LOGGER.warning(message)

        def error(self, message: str) -> None:
            LOGGER.error(message)

        def debug(self, message: str) -> None:
            LOGGER.debug(message)

        def success(self, message: str) -> None:
            LOGGER.info("[成功] %s", message)

    def _missing(*_args: Any, **_kwargs: Any) -> Any:
        """缺少 pwntools 时，统一抛出可读错误。"""
        raise _runtime_error("pwntools 运行时")

    class ELF:  # type: ignore[override]
        """ELF 的降级占位类，调用即报错。"""

        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise _runtime_error("ELF")

    class _Gdb:
        """gdb 命名空间的降级实现。"""

        @staticmethod
        def attach(*_args: Any, **_kwargs: Any) -> None:
            raise _runtime_error("gdb.attach")

        @staticmethod
        def debug(*_args: Any, **_kwargs: Any) -> None:
            raise _runtime_error("gdb.debug")

    args = _Args()
    context = _Context()
    gdb = _Gdb()
    log = _FallbackLog()
    pause = _missing
    process = _missing
    remote = _missing
    ssh = _missing
    MemLeak = _missing
    DynELF = _missing
    Corefile = _missing
    cyclic_find = _missing
    ROP = _missing


__all__ = [
    "Corefile",
    "DynELF",
    "ELF",
    "MemLeak",
    "ROP",
    "args",
    "context",
    "cyclic_find",
    "gdb",
    "log",
    "pause",
    "process",
    "remote",
    "ssh",
]
