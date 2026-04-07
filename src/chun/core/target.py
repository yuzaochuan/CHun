"""目标会话层：负责 ELF、进程/远程连接、GDB 挂载。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from .._compat import ELF, args, context, gdb, log, pause, process, remote


DEFAULT_TERMINAL: tuple[str, ...] = ("tmux", "splitw", "-h")
TubeLike = Any


def resolve_remote_mode(
    config_remote: bool,
    cli_remote: bool,
    override: bool | None = None,
) -> bool:
    """解析当前运行模式。

    优先级：显式 `override` > 命令行 `REMOTE` > 配置默认值。
    """
    if override is not None:
        return override
    if cli_remote:
        return True
    return config_remote


@dataclass(slots=True)
class TargetConfig:
    """创建目标会话所需的配置项。"""

    binary_path: str
    libc_path: str | None = None
    host: str | None = None
    port: int | None = None
    remote_mode: bool = False
    log_level: str = "debug"
    terminal: Sequence[str] = field(default_factory=lambda: list(DEFAULT_TERMINAL))
    checksec: bool = False
    process_argv: Sequence[str] | None = None
    process_env: Mapping[str, str] | None = None
    process_cwd: str | None = None


class TargetSession:
    """运行期会话对象，持有 ELF/libc 信息并负责启动 IO。"""

    def __init__(self, config: TargetConfig) -> None:
        """初始化 context，并加载 ELF/libc 元信息。"""
        self.config = config
        self._configure_context()

        self.elf: ELF = ELF(config.binary_path, checksec=config.checksec)
        context.binary = self.elf

        self.libc: ELF | None
        if config.libc_path:
            self.libc = ELF(config.libc_path, checksec=config.checksec)
            log.info("已按显式路径加载 libc。")
        else:
            self.libc = self.elf.libc
            if self.libc is not None:
                log.info("已根据目标 ELF 自动关联 libc。")
            else:
                log.warning("自动关联 libc 失败，建议手动传入 libc_path。")

    def _configure_context(self) -> None:
        """集中设置 pwntools context，避免到处改全局状态。"""
        context.log_level = self.config.log_level
        context.terminal = list(self.config.terminal)

    def start(
        self,
        host: str | None = None,
        port: int | None = None,
        remote_mode: bool | None = None,
    ) -> TubeLike:
        """按模式启动本地进程或远程连接。"""
        use_remote = resolve_remote_mode(
            config_remote=self.config.remote_mode,
            cli_remote=bool(getattr(args, "REMOTE", False)),
            override=remote_mode,
        )

        if use_remote:
            target_host = host or self.config.host
            target_port = port if port is not None else self.config.port
            if target_host is None or target_port is None:
                raise ValueError("远程模式必须同时提供 host 和 port。")
            log.info(f"正在连接远程目标：{target_host}:{target_port}")
            return remote(target_host, int(target_port))

        argv = list(self.config.process_argv) if self.config.process_argv else [self.elf.path]
        log.info(f"正在启动本地进程：{' '.join(argv)}")
        return process(
            argv,
            env=dict(self.config.process_env) if self.config.process_env else None,
            cwd=self.config.process_cwd,
        )

    @staticmethod
    def is_remote_io(io_obj: TubeLike) -> bool:
        """启发式判断 tube 是否为远程连接对象。"""
        return hasattr(io_obj, "rhost") and hasattr(io_obj, "rport")

    def attach_gdb(
        self,
        io_obj: TubeLike,
        gdbscript: str = "",
        show_summary: Callable[[], None] | None = None,
    ) -> None:
        """在开启 `GDB` 参数时挂载调试器（仅本地进程）。"""
        if not bool(getattr(args, "GDB", False)):
            return

        if self.is_remote_io(io_obj):
            log.warning("远程连接不支持直接 gdb.attach。")
            return

        if show_summary is not None:
            show_summary()

        gdb.attach(io_obj, gdbscript=gdbscript)
        pause()


__all__ = [
    "DEFAULT_TERMINAL",
    "TargetConfig",
    "TargetSession",
    "TubeLike",
    "resolve_remote_mode",
]
