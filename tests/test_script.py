from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from chun import CHun
from chun.core.models import TargetSpec
import chun.script as script_mod


@dataclass
class DummyDbg:
    attach_calls: list[dict[str, Any]] = field(default_factory=list)

    def attach(
        self,
        io: object | None = None,
        script: str | None = None,
        *,
        api: bool = True,
    ) -> str:
        self.attach_calls.append({"io": io, "script": script, "api": api})
        return "attached"


@dataclass
class DummyIO:
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = field(
        default_factory=list
    )

    def send(self, data: bytes) -> None:
        self.calls.append(("send", (data,), {}))

    def sendline(self, data: bytes) -> None:
        self.calls.append(("sendline", (data,), {}))

    def sendafter(self, delim: bytes, data: bytes) -> None:
        self.calls.append(("sendafter", (delim, data), {}))

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        self.calls.append(("sendlineafter", (delim, data), {}))

    def recv(self, n: int = 4096) -> bytes:
        self.calls.append(("recv", (n,), {}))
        return b"recv"

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        self.calls.append(("recvuntil", (delim,), {"drop": drop}))
        return b"until"

    def recvline(self, keepends: bool = True) -> bytes:
        self.calls.append(("recvline", (), {"keepends": keepends}))
        return b"line\n" if keepends else b"line"

    def interactive(self) -> None:
        self.calls.append(("interactive", (), {}))

    def clean(self) -> bytes:
        self.calls.append(("clean", (), {}))
        return b"clean"


@dataclass
class DummySession:
    kind: str
    io: DummyIO = field(default_factory=DummyIO)
    dbg: DummyDbg = field(default_factory=DummyDbg)
    open_calls: int = 0
    close_calls: int = 0
    reconnect_calls: int = 0

    def __post_init__(self) -> None:
        self.target = type("Target", (), {"kind": self.kind})()
        self.rec = SimpleNamespace(name="rec")
        self.infer = SimpleNamespace(name="infer")
        self.resolve = SimpleNamespace(name="resolve", bind_defaults=lambda **_: None)
        self.crash = SimpleNamespace(name="crash")

    def open(self) -> DummySession:
        self.open_calls += 1
        return self

    def close(self) -> None:
        self.close_calls += 1

    def reconnect(self) -> None:
        self.reconnect_calls += 1


@dataclass
class FakeELF:
    path: str
    libc: Any = None


@pytest.fixture
def fake_pwntools_env(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    loaded: list[tuple[str, bool]] = []
    auto_libc = FakeELF("/glibc/libc.so.6")

    def fake_elf(path: str, checksec: bool = False) -> FakeELF:
        loaded.append((path, checksec))
        if path == "./challenge":
            return FakeELF(path, libc=auto_libc)
        return FakeELF(path)

    monkeypatch.setattr(script_mod, "ELF", fake_elf)
    tls = getattr(script_mod.context, "_tls", None)
    if isinstance(tls, dict) and "binary" in tls:
        del tls["binary"]
    if hasattr(script_mod.context, "binary"):
        monkeypatch.setattr(script_mod.context, "binary", None)
    monkeypatch.setattr(script_mod.context, "log_level", "info")
    monkeypatch.setattr(script_mod.context, "terminal", [])
    return {"loaded": loaded, "auto_libc": auto_libc}


def test_script_initializes_target_and_runtime_defaults(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script(
        "./challenge", host="example.com", port=31337, log_level="debug", terminal=()
    )

    assert isinstance(entry.target, TargetSpec)
    assert entry.target.binary == "./challenge"
    assert entry.target.host == "example.com"
    assert entry.target.port == 31337
    assert entry.target.argv == ["./challenge"]
    assert entry.elf.path == "./challenge"
    assert entry.libc is fake_pwntools_env["auto_libc"]
    assert entry.target.libc == "/glibc/libc.so.6"
    assert script_mod.context.binary is entry.elf
    assert script_mod.context.log_level in ("debug", 10)
    assert script_mod.context.terminal == ["tmux", "splitw", "-h"]
    assert fake_pwntools_env["loaded"] == [("./challenge", False)]


def test_script_start_uses_process_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        calls.append({"target": target, "transport": transport})
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script(
        "./challenge",
        host="example.com",
        port=31337,
        libc="./libc.so.6",
        argv=["./challenge", "--fast"],
        env={"MODE": "1"},
        cwd="/tmp/challenge",
    )

    result = entry.start()

    assert result is entry
    assert entry.session is session
    assert entry.io is session.io
    assert len(calls) == 1
    assert calls[0]["target"].kind == "process"
    assert calls[0]["target"].binary == "./challenge"
    assert calls[0]["target"].argv == ["./challenge", "--fast"]
    assert calls[0]["target"].libc == "./libc.so.6"
    assert calls[0]["target"].env == {"MODE": "1"}
    assert calls[0]["target"].cwd == "/tmp/challenge"
    assert calls[0]["target"].metadata == {
        "log_level": "debug",
        "terminal": ["tmux", "splitw", "-h"],
    }
    assert calls[0]["transport"].kind == "pwntools-tube"
    assert calls[0]["transport"].timeout is None
    assert entry.rec is session.rec
    assert entry.infer is session.infer
    assert entry.resolve is session.resolve
    assert entry.dbg is session.dbg
    assert entry.crash is session.crash


def test_script_start_uses_remote_when_remote_flag_is_set(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="remote")
    calls: list[dict[str, Any]] = []

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        calls.append({"target": target, "transport": transport})
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", True)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script(
        "./challenge",
        host="example.com",
        port=31337,
        libc="./libc.so.6",
        timeout=1.5,
    )

    result = entry.start()

    assert result is entry
    assert len(calls) == 1
    assert calls[0]["target"].kind == "remote"
    assert calls[0]["target"].host == "example.com"
    assert calls[0]["target"].port == 31337
    assert calls[0]["target"].binary == "./challenge"
    assert calls[0]["target"].libc == "./libc.so.6"
    assert calls[0]["target"].metadata == {
        "log_level": "info",
        "terminal": ["tmux", "splitw", "-h"],
    }
    assert calls[0]["transport"].kind == "pwntools-tube"
    assert calls[0]["transport"].timeout == 1.5


def test_script_gdb_attaches_for_local_process(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        assert target.kind == "process"
        assert target.binary == "./challenge"
        assert transport.kind == "pwntools-tube"
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge")
    entry.start()
    result = entry.gdb("b *main\nc")

    assert result == "attached"
    assert session.dbg.attach_calls == [
        {"io": None, "script": "b *main\nc", "api": True}
    ]


def test_script_gdb_warns_for_remote_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="remote")
    warnings: list[str] = []

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        assert target.kind == "remote"
        assert (target.host, target.port) == ("example.com", 31337)
        assert transport.kind == "pwntools-tube"
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", True)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge", host="example.com", port=31337)
    entry.start()
    result = entry.gdb("b *main")

    assert result is None
    assert session.dbg.attach_calls == []
    assert warnings == ["当前为 REMOTE 模式，跳过 GDB attach。"]


def test_script_remote_gdb_keeps_process_log_level(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="remote")
    calls: list[dict[str, Any]] = []

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        calls.append({"target": target, "transport": transport})
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", True)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", host="example.com", port=31337)
    entry.start()

    assert calls[0]["target"].metadata["log_level"] == "debug"


def test_script_session_property_requires_start(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge")

    with pytest.raises(RuntimeError):
        _ = entry.session

    with pytest.raises(RuntimeError):
        _ = entry.rec


def test_script_uses_explicit_libc_when_provided(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge", libc="./libc.so.6")

    assert entry.libc.path == "./libc.so.6"
    assert entry.target.libc == "./libc.so.6"
    assert fake_pwntools_env["loaded"] == [
        ("./challenge", False),
        ("./libc.so.6", False),
    ]


def test_script_start_binds_default_elf_and_libc_to_resolve(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    bind_calls: list[dict[str, Any]] = []
    session.resolve = SimpleNamespace(
        name="resolve",
        bind_defaults=lambda **kwargs: bind_calls.append(kwargs),
    )

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", libc="./libc.so.6")
    entry.start()

    assert bind_calls == [{"elf": entry.elf, "libc_elf": entry.libc}]


def test_script_start_is_chainable(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.session is session
    assert entry.rec is session.rec
    assert entry.resolve is session.resolve


def test_script_context_manager_opens_and_closes_session(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    with CHun.script("./challenge") as entry:
        assert entry.session is session

    assert session.open_calls == 1
    assert session.close_calls == 1


def test_script_explicit_io_methods_and_aliases_forward_to_io(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        assert target.kind == "process"
        assert transport.kind == "pwntools-tube"
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge")
    entry.start()

    entry.send(b"A")
    entry.sendline(b"B")
    entry.sendafter(b":", b"C")
    entry.sendlineafter(b">", b"D")
    assert entry.recv(32) == b"recv"
    assert entry.recvuntil(b"!", drop=True) == b"until"
    assert entry.recvline(keepends=False) == b"line"
    entry.interactive()

    entry.sl(b"E")
    entry.sa(b"name", b"F")
    entry.sla(b"menu", b"G")
    assert entry.ru(b"done") == b"until"
    assert entry.rl() == b"line\n"
    entry.ia()

    assert session.io.calls == [
        ("send", (b"A",), {}),
        ("sendline", (b"B",), {}),
        ("sendafter", (b":", b"C"), {}),
        ("sendlineafter", (b">", b"D"), {}),
        ("recv", (32,), {}),
        ("recvuntil", (b"!",), {"drop": True}),
        ("recvline", (), {"keepends": False}),
        ("interactive", (), {}),
        ("sendline", (b"E",), {}),
        ("sendafter", (b"name", b"F"), {}),
        ("sendlineafter", (b"menu", b"G"), {}),
        ("recvuntil", (b"done",), {"drop": False}),
        ("recvline", (), {"keepends": True}),
        ("interactive", (), {}),
    ]


def test_script_getattr_falls_back_to_io_only(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge")
    entry.start()

    assert entry.clean() == b"clean"
    assert session.io.calls == [("clean", (), {})]

    with pytest.raises(AttributeError):
        _ = entry._hidden
