"""基于 pwntools tube 的主力 transport。"""

from __future__ import annotations

from typing import Any

from .._compat import context, process, remote, ssh
from ..core.errors import TransportConfigError
from ..core.models import TargetSpec, TransportSpec
from .base import BaseTransport


class PwntoolsTubeTransport(BaseTransport):
    """统一承接 process / remote / ssh.process。"""

    def __init__(self, target: TargetSpec, spec: TransportSpec) -> None:
        super().__init__(target, spec)
        self._tube: Any = None
        self._ssh_client: Any = None
        self._configure_context()

    def _configure_context(self) -> None:
        log_level = self.target.metadata.get("log_level")
        if isinstance(log_level, str):
            context.log_level = log_level

        terminal = self.target.metadata.get("terminal")
        if isinstance(terminal, (list, tuple)):
            context.terminal = list(terminal)

    def _open(self) -> None:
        if self.target.kind == "process":
            self._tube = self._open_process()
            return

        if self.target.kind == "remote":
            self._tube = self._open_remote()
            return

        if self.target.kind == "ssh":
            self._tube = self._open_ssh_process()
            return

        raise TransportConfigError(
            f"PwntoolsTubeTransport 不支持目标类型：{self.target.kind}"
        )

    def _open_process(self) -> Any:
        argv = list(self.target.argv)
        if not argv:
            if self.target.binary is None:
                raise TransportConfigError("process 模式至少需要 binary 或 argv。")
            argv = [self.target.binary]

        return process(
            argv,
            env=self.target.env or None,
            cwd=self.target.cwd,
        )

    def _open_remote(self) -> Any:
        if self.target.host is None or self.target.port is None:
            raise TransportConfigError("remote 模式必须提供 host 和 port。")

        timeout = self.spec.connect_timeout or self.spec.timeout
        return remote(self.target.host, int(self.target.port), timeout=timeout)

    def _open_ssh_process(self) -> Any:
        ssh_host = self.target.ssh_host or self.target.host
        if ssh_host is None or self.target.ssh_user is None:
            raise TransportConfigError(
                "ssh.process 模式必须提供 ssh_host 和 ssh_user。"
            )

        argv = list(self.target.argv)
        if not argv:
            if self.target.binary is None:
                raise TransportConfigError("ssh.process 模式至少需要 binary 或 argv。")
            argv = [self.target.binary]

        self._ssh_client = ssh(
            host=ssh_host,
            user=self.target.ssh_user,
            port=int(self.target.ssh_port),
            password=self.target.ssh_password,
            keyfile=self.target.ssh_keyfile,
            key_password=self.target.ssh_key_password,
            cache=False,
        )
        return self._ssh_client.process(
            argv, env=self.target.env or None, cwd=self.target.cwd
        )

    def _close(self) -> None:
        if self._tube is not None and hasattr(self._tube, "close"):
            self._tube.close()
        if self._ssh_client is not None and hasattr(self._ssh_client, "close"):
            self._ssh_client.close()
        self._tube = None
        self._ssh_client = None

    def adopt_tube(self, tube: Any) -> None:
        """接管一个已由外部创建好的 pwntools tube。"""
        self._configure_context()
        self._tube = tube
        self._is_open = True

    @property
    def raw(self) -> Any:
        return self._tube

    def __getattr__(self, name: str) -> Any:
        """将未显式声明的常用 tube 方法透传到底层 pwntools 对象。"""
        if name.startswith("_"):
            raise AttributeError(name)
        self._require_open()
        return getattr(self._tube, name)

    def send(self, data: bytes) -> None:
        self._require_open()
        self._tube.send(data)
        self._emit_replay("send", payload=bytes(data))

    def sendline(self, data: bytes) -> None:
        self._require_open()
        self._tube.sendline(data)
        self._emit_replay("sendline", payload=bytes(data))

    def sendafter(self, delim: bytes, data: bytes) -> None:
        self._require_open()
        self._tube.sendafter(delim, data)
        self._emit_replay("expect", payload=self._ensure_bytes(delim), drop=False)
        self._emit_replay("send", payload=bytes(data))

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        self._require_open()
        self._tube.sendlineafter(delim, data)
        self._emit_replay("expect", payload=self._ensure_bytes(delim), drop=False)
        self._emit_replay("sendline", payload=bytes(data))

    def recv(self, n: int = 4096) -> bytes:
        self._require_open()
        return self._tube.recv(n)

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        self._require_open()
        result = self._tube.recvuntil(delim, drop=drop)
        self._emit_replay("expect", payload=self._ensure_bytes(delim), drop=bool(drop))
        return result

    def interactive(self) -> None:
        self._require_open()
        self._tube.interactive()

    @staticmethod
    def _ensure_bytes(value: bytes | str) -> bytes:
        if isinstance(value, bytes):
            return value
        return value.encode()


__all__ = ["PwntoolsTubeTransport"]
