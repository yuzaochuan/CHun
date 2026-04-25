from __future__ import annotations

from dataclasses import dataclass, field
import re
import time
from types import SimpleNamespace
from typing import Any

import pytest

from chun import CHun
from chun.core.models import FactKind, RecordDomain
from chun.core.replay import VerificationResult
from chun.core.registry import EvidenceRegistry
from chun.core.models import TargetSpec
from chun.script.gadget import _ScriptGadgetFacade
import chun.script as script_mod


@dataclass
class DummyDbg:
    attach_calls: list[dict[str, Any]] = field(default_factory=list)
    bind_runtime_calls: list[dict[str, Any]] = field(default_factory=list)

    def attach(
        self,
        io: object | None = None,
        script: str | None = None,
        *,
        api: bool = True,
    ) -> str:
        self.attach_calls.append({"io": io, "script": script, "api": api})
        return "attached"

    def bind_runtime(
        self, *, controller: object | None = None, pid: object | None = None
    ) -> None:
        self.bind_runtime_calls.append({"controller": controller, "pid": pid})


@dataclass
class DummyIO:
    calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = field(
        default_factory=list
    )
    recv_values: list[bytes] = field(default_factory=list)
    recvline_values: list[bytes] = field(default_factory=list)
    recvregex_match: object | None = None

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
        if self.recv_values:
            return self.recv_values.pop(0)
        return b"recv"

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        self.calls.append(("recvuntil", (delim,), {"drop": drop}))
        return b"until"

    def recvline(self, keepends: bool = True) -> bytes:
        self.calls.append(("recvline", (), {"keepends": keepends}))
        if self.recvline_values:
            return self.recvline_values.pop(0)
        return b"line\n" if keepends else b"line"

    def recvregex(self, regex: bytes | str, capture: bool = False) -> object:
        self.calls.append(("recvregex", (regex,), {"capture": capture}))
        if self.recvregex_match is not None:
            return self.recvregex_match
        pattern = re.compile(regex) if isinstance(regex, str) else re.compile(regex)
        return pattern.search(b"0xdeadbeef")

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
    bind_binaries_calls: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.target = type("Target", (), {"kind": self.kind})()
        self.rec = SimpleNamespace(name="rec")
        self.fmt = SimpleNamespace(name="fmt")
        self.infer = SimpleNamespace(name="infer")
        self.resolve = SimpleNamespace(name="resolve")
        self.crash = SimpleNamespace(name="crash")
        self.elf = None
        self.libc_elf = None

    def open(self) -> DummySession:
        self.open_calls += 1
        return self

    def close(self) -> None:
        self.close_calls += 1

    def reconnect(self) -> None:
        self.reconnect_calls += 1

    def bind_binaries(self, *, elf: object | None = None, libc_elf: object | None = None) -> DummySession:
        self.bind_binaries_calls.append({"elf": elf, "libc_elf": libc_elf})
        self.elf = elf
        self.libc_elf = libc_elf
        return self

    @property
    def libc_base(self) -> int:
        fact = self.rec.get_fact("libc.base")
        if fact is None or not isinstance(fact.value, int):
            raise RuntimeError("libc.base 尚未推导，可能是多候选情况，请明确指定或编写爆破逻辑。")
        return fact.value

    @property
    def libc_version(self) -> str:
        fact = self.rec.get_fact("libc.version")
        if fact is None or not isinstance(fact.value, str):
            raise RuntimeError("libc.version 尚未确认。")
        return fact.value


@dataclass
class FakeELF:
    path: str
    libc: Any = None
    bits: int = 64
    bytes: int = 8
    little_endian: bool = True
    arch: str = "amd64"


@pytest.fixture
def fake_pwntools_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> dict[str, Any]:
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
    if isinstance(tls, dict):
        tls["binary"] = None
    monkeypatch.setattr(script_mod.context, "log_level", "info")
    monkeypatch.setattr(script_mod.context, "terminal", [])
    monkeypatch.setenv("CHUN_CACHE_DIR", str(tmp_path / ".chun_cache"))
    monkeypatch.delenv("CHUN_NO_CACHE", raising=False)
    monkeypatch.delenv("CHUN_CLEAR_CACHE", raising=False)
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
    assert entry.libc is None
    assert entry.target.libc is None
    tls = getattr(script_mod.context, "_tls", None)
    if isinstance(tls, dict):
        assert tls.get("binary") is entry.elf
    else:
        assert getattr(tls, "binary", None) is entry.elf or script_mod.context.binary is entry.elf
    assert script_mod.context.log_level in ("debug", 10)
    assert script_mod.context.terminal == ["tmux", "splitw", "-h"]
    assert fake_pwntools_env["loaded"] == []


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


def test_script_debug_starts_process_under_gdb_without_keypress_pause(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    class FakeController:
        pass

    class FakeDebugTube(DummyIO):
        def __init__(self) -> None:
            super().__init__()
            self.gdb = FakeController()

    created: list[dict[str, Any]] = []
    debug_tube = FakeDebugTube()

    def fake_debug(
        argv: list[str],
        gdbscript: str | None = None,
        exe: str | None = None,
        env: dict[str, str] | None = None,
        api: bool = False,
        cwd: str | None = None,
    ) -> FakeDebugTube:
        created.append(
            {
                "argv": argv,
                "gdbscript": gdbscript,
                "exe": exe,
                "env": env,
                "api": api,
                "cwd": cwd,
            }
        )
        return debug_tube

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", True)
    monkeypatch.setattr(script_mod.gdb, "debug", fake_debug)

    entry = CHun.script(
        "./challenge",
        argv=["./challenge", "--fast"],
        env={"MODE": "1"},
        cwd="/tmp/challenge",
    )
    result = entry.debug("b *main\nc")

    assert result is entry
    assert created == [
        {
            "argv": ["./challenge", "--fast"],
            "gdbscript": "b *main\nc",
            "exe": "./challenge",
            "env": {"MODE": "1"},
            "api": True,
            "cwd": "/tmp/challenge",
        }
    ]
    assert entry.dbg._controller is debug_tube.gdb
    assert entry.sendline(b"PING") is None
    assert debug_tube.calls[-1] == ("sendline", (b"PING",), {})


def test_script_debug_falls_back_to_start_when_gdb_flag_is_off(
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

    assert entry.debug("b *main") is entry
    assert entry.session is session


def test_script_fmt_facade_forwards_to_session_and_enables_loginfo_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_find_offset(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "offset"

    session.fmt = SimpleNamespace(find_offset=fake_find_offset, marker="fmt-service")

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.fmt.marker == "fmt-service"
    assert entry.fmt.find_offset(max_slots=8) == "offset"
    assert calls == [{"max_slots": 8, "loginfo": True}]


def test_script_fmt_facade_respects_explicit_loginfo_override(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_find_offset(**kwargs: Any) -> str:
        calls.append(kwargs)
        return "offset"

    session.fmt = SimpleNamespace(find_offset=fake_find_offset)

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.fmt.find_offset(loginfo=False) == "offset"
    assert calls == [{"loginfo": False}]


def test_script_fmt_facade_enables_compare_write_loginfo_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_compare_write(*args: Any, **kwargs: Any) -> str:
        calls.append({"args": args, "kwargs": kwargs})
        return "comparison"

    session.fmt = SimpleNamespace(compare_write=fake_compare_write)

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.fmt.compare_write(0x6010A0, 0x601018) == "comparison"
    assert calls == [
        {
            "args": (0x6010A0, 0x601018),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": None,
                "task_policy": script_mod.FmtTaskPolicy.PACKED,
                "data_offset": None,
                "buflen": None,
                "end": b"\n",
                "show_hex": False,
                "loginfo": True,
            },
        }
    ]


def test_script_fmt_write_builder_reuses_arguments_for_info_and_send(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    compare_calls: list[dict[str, Any]] = []
    plan_calls: list[dict[str, Any]] = []
    execute_calls: list[dict[str, Any]] = []
    recvuntil_calls: list[tuple[bytes, bool]] = []
    plan = object()

    def fake_compare_write(*args: Any, **kwargs: Any) -> str:
        compare_calls.append({"args": args, "kwargs": kwargs})
        return "info"

    def fake_plan_write(*args: Any, **kwargs: Any) -> object:
        plan_calls.append({"args": args, "kwargs": kwargs})
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 16,
                steps=(SimpleNamespace(padding=0),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        execute_calls.append({"args": args, "kwargs": kwargs})
        return "sent"

    fake_io = SimpleNamespace(
        recvuntil=lambda delim, drop=False: recvuntil_calls.append((delim, drop)) or delim
    )
    session.fmt = SimpleNamespace(
        compare_write=fake_compare_write,
        plan_write=fake_plan_write,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=fake_io),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    action = entry.fmt.write(
        0x6010A0,
        0x601018,
        b"name: ",
        6,
        strategy="byte",
        task_policy="by_atom",
        end=b" ",
    )

    assert action.info(48, show_hex=True) == "info"
    assert action.send(48, show_hex=True) == "sent"
    assert compare_calls == [
        {
            "args": (0x6010A0, 0x601018),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_ATOM,
                "data_offset": None,
                "buflen": 48,
                "end": b" ",
                "show_hex": True,
                "loginfo": False,
            },
        }
    ]
    assert recvuntil_calls == [(b"name: ", False)]
    assert plan_calls == [
        {
            "args": (0x6010A0, 0x601018),
            "kwargs": {
                "strategy": script_mod.FmtWriteStrategy.BYTE,
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_ATOM,
                "data_offset": None,
            },
        }
    ]
    assert execute_calls == [
        {
            "args": (plan,),
            "kwargs": {
                "offset": 6,
                "data_offset": None,
                "receive": False,
                "end": b" ",
            },
        }
    ]


def test_script_fmt_facade_enables_compare_writes_loginfo_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[dict[str, Any]] = []

    def fake_compare_writes(*args: Any, **kwargs: Any) -> str:
        calls.append({"args": args, "kwargs": kwargs})
        return "comparison"

    session.fmt = SimpleNamespace(compare_writes=fake_compare_writes)

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    writes = {0x6010A0: 0x601018, 0x6010B0: 0x601028}
    assert entry.fmt.compare_writes(writes) == "comparison"
    assert calls == [
        {
            "args": (writes,),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": None,
                "task_policy": script_mod.FmtTaskPolicy.PACKED,
                "data_offset": None,
                "buflen": None,
                "end": b"\n",
                "show_hex": False,
                "loginfo": True,
            },
        }
    ]


def test_script_fmt_writes_builder_reuses_arguments_for_info_and_send(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    compare_calls: list[dict[str, Any]] = []
    plan_calls: list[dict[str, Any]] = []
    execute_calls: list[dict[str, Any]] = []
    recvuntil_calls: list[tuple[bytes, bool]] = []
    plan = object()

    def fake_compare_writes(*args: Any, **kwargs: Any) -> str:
        compare_calls.append({"args": args, "kwargs": kwargs})
        return "info"

    def fake_plan_writes(*args: Any, **kwargs: Any) -> object:
        plan_calls.append({"args": args, "kwargs": kwargs})
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 16,
                steps=(SimpleNamespace(padding=0),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        execute_calls.append({"args": args, "kwargs": kwargs})
        return "sent"

    fake_io = SimpleNamespace(
        recvuntil=lambda delim, drop=False: recvuntil_calls.append((delim, drop)) or delim
    )
    session.fmt = SimpleNamespace(
        compare_writes=fake_compare_writes,
        plan_writes=fake_plan_writes,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=fake_io),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    writes = {0x6010A0: 0x601018, 0x6010B0: 0x601028}
    action = entry.fmt.writes(
        writes,
        b"choice> ",
        6,
        strategy="short",
        task_policy="by_target",
        end=b" ",
    )

    assert action.info(96, show_hex=True) == "info"
    assert action.send(96, show_hex=True) == "sent"
    assert compare_calls == [
        {
            "args": (writes,),
            "kwargs": {
                "strategies": (
                    script_mod.FmtWriteStrategy.AUTO,
                    script_mod.FmtWriteStrategy.BYTE,
                    script_mod.FmtWriteStrategy.SHORT,
                    script_mod.FmtWriteStrategy.INT,
                ),
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_TARGET,
                "data_offset": None,
                "buflen": 96,
                "end": b" ",
                "show_hex": True,
                "loginfo": True,
            },
        }
    ]
    assert recvuntil_calls == [(b"choice> ", False)]
    assert plan_calls == [
        {
            "args": (writes,),
            "kwargs": {
                "strategy": script_mod.FmtWriteStrategy.SHORT,
                "offset": 6,
                "task_policy": script_mod.FmtTaskPolicy.BY_TARGET,
                "data_offset": None,
            },
        }
    ]
    assert execute_calls == [
        {
            "args": (plan,),
            "kwargs": {
                "offset": 6,
                "data_offset": None,
                "receive": False,
                "end": b" ",
            },
        }
    ]


def test_script_fmt_send_logs_error_when_send_len_exceeds_buflen(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    errors: list[str] = []
    plan = SimpleNamespace(offset=6)

    def fake_plan_write(*args: Any, **kwargs: Any) -> object:
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 32,
                steps=(SimpleNamespace(padding=0),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        return "sent"

    session.fmt = SimpleNamespace(
        plan_write=fake_plan_write,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=SimpleNamespace(recvuntil=lambda *_args, **_kwargs: b"")),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))
    monkeypatch.setattr(script_mod.log, "error", errors.append)

    entry = CHun.script("./challenge").start()
    assert entry.fmt.write(0x6010A0, 0x601018).send(16) == "sent"
    assert errors == ["fmt 发送长度 33B 超过 buflen=16B，仍继续发送。"]


def test_script_fmt_send_logs_warning_for_high_pad_time(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    warnings: list[str] = []
    plan = SimpleNamespace(offset=6)

    def fake_plan_write(*args: Any, **kwargs: Any) -> object:
        return plan

    def fake_render_plan(*args: Any, **kwargs: Any) -> tuple[Any, ...]:
        return (
            SimpleNamespace(
                payload=b"A" * 8,
                steps=(SimpleNamespace(padding=0x1000),),
            ),
        )

    def fake_execute_plan(*args: Any, **kwargs: Any) -> str:
        return "sent"

    session.fmt = SimpleNamespace(
        plan_write=fake_plan_write,
        render_plan=fake_render_plan,
        execute_plan=fake_execute_plan,
        session=SimpleNamespace(io=SimpleNamespace(recvuntil=lambda *_args, **_kwargs: b"")),
    )

    def fake_from_specs(
        cls: type[CHun],
        target: TargetSpec,
        transport: Any,
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    assert entry.fmt.write(0x6010A0, 0x601018).send() == "sent"
    assert warnings == ["fmt 的 pad_time 为 HIGH（max_pad=4096），服务端可能变慢或超时。"]


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
    assert fake_pwntools_env["loaded"] == []


def test_script_does_not_auto_detect_local_libc_by_default(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge")

    assert entry.libc is None
    assert entry.target.libc is None


def test_script_auto_local_libc_is_opt_in(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)

    entry = CHun.script("./challenge", auto_local_libc=True)

    libc = entry.libc
    assert libc is not None
    assert libc.path == "/glibc/libc.so.6"
    assert entry.target.libc == "/glibc/libc.so.6"


def test_script_start_binds_default_elf_and_libc_to_session(
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

    entry = CHun.script("./challenge", libc="./libc.so.6")
    entry.start()

    assert session.bind_binaries_calls == [{"elf": entry.elf, "libc_elf": entry.libc}]


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


def test_script_exposes_libc_fact_shortcuts(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    registry = EvidenceRegistry()
    registry.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    registry.record_fact(
        "libc.version",
        "glibc-test",
        kind=FactKind.VERSION,
        domain=RecordDomain.LIBC,
    )
    session.rec = registry

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.libc_base == 0x7F0000000000
    assert entry.libc_version == "glibc-test"


def test_script_libc_base_raises_when_missing(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(RuntimeError, match="libc.base 尚未推导"):
        _ = entry.libc_base


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


def test_script_replay_sugar_uses_prefix_before_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    captured: dict[str, Any] = {}

    checkpoint_entry = SimpleNamespace(event_seq=42)

    class _RecStub:
        replay = SimpleNamespace(
            checkpoints={"io_node_1": checkpoint_entry},
            blob_store=object(),
            cursor_seq=99,
        )

        def run_replay(self, **kwargs: Any) -> VerificationResult:
            captured.update(kwargs)
            old_level = script_mod.context.log_level
            try:
                script_mod.context.log_level = "error"
                expected_error_level = script_mod.context.log_level
                assert kwargs["predicate"](b"xxokyy") is True
                assert script_mod.context.log_level == expected_error_level
            finally:
                script_mod.context.log_level = old_level
            return VerificationResult(
                run_id="run-id",
                ok=True,
                reason="predicate_pass",
            )

    session.rec = _RecStub()
    session.make_replay_session = lambda: object()  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    messages: list[str] = []
    monkeypatch.setattr(script_mod.log, "info", messages.append)

    entry = CHun.script("./challenge").start()
    result = entry.replay(
        b"7",
        checkpoint="io_node_1",
        expected=b"ok",
        show_recv=True,
        capture_replay_registry=True,
    )

    assert result.ok is True
    assert captured["probe"] == b"7"
    assert captured["end_seq_exclusive"] == 42
    assert captured["capture_replay_registry"] is True
    assert captured["session_factory"] is session.make_replay_session
    assert any(line.startswith("[replay recv] len=") for line in messages)
    assert any("00000000" in line for line in messages)


def test_script_replay_sugar_defaults_to_current_position(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    captured: dict[str, Any] = {}

    class _RecStub:
        replay = SimpleNamespace(
            checkpoints={},
            blob_store=object(),
            cursor_seq=73,
        )

        def run_replay(self, **kwargs: Any) -> VerificationResult:
            captured.update(kwargs)
            assert kwargs["predicate"](b"anything") is True
            return VerificationResult(
                run_id="run-id",
                ok=True,
                reason="predicate_pass",
            )

    session.rec = _RecStub()
    session.make_replay_session = lambda: object()  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    result = entry.replay(b"7")

    assert result.ok is True
    assert captured["probe"] == b"7"
    assert captured["end_seq_exclusive"] == 73


def test_script_replay_sugar_supports_callable_with_multi_args_and_kwargs(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    replay_session = DummySession(kind="process")
    replay_session.rec = EvidenceRegistry()
    registry = EvidenceRegistry()
    registry.append_event("sendline", payload=b"warmup\n")
    session.rec = registry
    session.make_replay_session = lambda: replay_session  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    def _menu(choice: int) -> None:
        s.sla(b"> ", str(choice).encode())

    def _show(index: int, suffix: bytes, *, with_menu: bool = True) -> None:
        if with_menu:
            _menu(3)
        s.sla(b"Index: ", str(index).encode() + suffix)

    marker = object()
    had_global_s = "s" in globals()
    old_global_s = globals().get("s", marker)
    globals()["s"] = marker
    try:
        entry = CHun.script("./challenge").start()
        result = entry.replay(
            _show,
            7,
            b"!",
            action_kwargs={"with_menu": True},
            expected=b"recv",
            show_recv=True,
        )
    finally:
        if had_global_s:
            globals()["s"] = old_global_s
        else:
            globals().pop("s", None)

    assert result.ok is True
    assert result.reason == "predicate_pass"
    assert session.io.calls == []
    assert replay_session.io.calls == [
        ("sendline", (b"warmup\n",), {}),
        ("sendlineafter", (b"> ", b"3"), {}),
        ("sendlineafter", (b"Index: ", b"7!"), {}),
        ("recv", (4096,), {}),
    ]


def test_script_replay_sugar_raises_for_missing_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = SimpleNamespace(
        replay=SimpleNamespace(checkpoints={}, blob_store=object(), cursor_seq=0),
    )
    session.make_replay_session = lambda: object()  # type: ignore[attr-defined]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    with pytest.raises(KeyError, match="replay checkpoint 不存在：io_node_1"):
        entry.replay(b"7", checkpoint="io_node_1")


def test_script_recv_leak_reads_raw_bytes_and_records_symbol_leak(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"\xa0\x0a\x58\x34\x12\x7f"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    messages: list[str] = []
    monkeypatch.setattr(script_mod.log, "success", messages.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("puts", delim=b"puts: ")

    assert value == 0x7F1234580AA0
    observation = session.rec.get_observation("puts")
    assert observation is not None
    assert observation.value == value
    assert observation.domain == RecordDomain.LIBC
    assert observation.source == "leak"
    assert messages == [f"Leak [puts] captured: {hex(value)}"]
    assert session.io.calls == [
        ("recvuntil", (b"puts: ",), {"drop": False}),
        ("recv", (6,), {}),
    ]


def test_script_recv_leak_reads_hex_and_applies_offset(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvline_values = [b"0x7f1234580aa0\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "puts",
        delim="puts: ",
        mode="hex",
        offset=0x0AA0,
        source="printf",
    )

    assert value == 0x7F1234580000
    observation = session.rec.get_observation("puts")
    assert observation is not None
    assert observation.value == value
    assert observation.source == "printf"
    assert session.io.calls == [
        ("recvuntil", ("puts: ",), {"drop": False}),
        ("recvline", (), {"keepends": False}),
    ]


def test_script_recv_leak_extracts_first_hex_token_from_dirty_line(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvline_values = [b"0x7f1234580aa0 saved-rbp=0x7ffe3748e060\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("puts", delim="puts: ", mode="hex")

    assert value == 0x7F1234580AA0
    assert warnings == [
        "共匹配到 2 个地址：0x7f1234580aa0,0x7ffe3748e060|默认选 0x7f1234580aa0"
    ]
    assert session.io.calls == [
        ("recvuntil", ("puts: ",), {"drop": False}),
        ("recvline", (), {"keepends": False}),
    ]


def test_script_recv_leak_supports_hex_index_selection(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvline_values = [b"0x7f1234580aa0 0x7ffe3748e060\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak("saved_rbp", delim="puts: ", mode="hex", index=1)

    assert value == 0x7FFE3748E060
    assert warnings == [
        "共匹配到 2 个地址：0x7f1234580aa0,0x7ffe3748e060|默认选 0x7ffe3748e060"
    ]


def test_script_recv_leak_supports_hex_delim_end_window(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()

    def fake_recvuntil(delim: bytes, drop: bool = False) -> bytes:
        session.io.calls.append(("recvuntil", (delim,), {"drop": drop}))
        if delim == b"Hello,":
            return b"Hello,"
        if delim == b" world":
            return b"0x7f1234580aa0 and 0x7ffe3748e060 world"
        return b"until"

    session.io.recvuntil = fake_recvuntil

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    warnings: list[str] = []
    monkeypatch.setattr(script_mod.log, "warning", warnings.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "saved_rbp",
        b"Hello,",
        mode="hex",
        delim_end=b" world",
        index=1,
    )

    assert value == 0x7FFE3748E060
    assert warnings == [
        "共匹配到 2 个地址：0x7f1234580aa0,0x7ffe3748e060|默认选 0x7ffe3748e060"
    ]
    assert session.io.calls == [
        ("recvuntil", (b"Hello,",), {"drop": False}),
        ("recvuntil", (b" world",), {"drop": True}),
    ]


def test_script_recv_leak_rejects_out_of_range_hex_index(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvline_values = [b"0x7f1234580aa0 0x7ffe3748e060\n"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(
        ValueError,
        match=r"共匹配到 2 个地址：0x7f1234580aa0,0x7ffe3748e060，index=2 越界。",
    ):
        entry.recv_leak("puts", mode="hex", index=2)


def test_script_recv_leak_rejects_delim_end_with_regex(
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

    with pytest.raises(ValueError, match="delim_end 和 regex 不能同时提供。"):
        entry.recv_leak("puts", delim_end=b"!", regex=rb"(0x[0-9a-f]+)", mode="hex")


def test_script_recv_leak_reads_regex_capture_and_allows_custom_domain(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recvregex_match = re.search(rb"leak=(0x[0-9a-f]+)", b"leak=0x401000")
    assert session.io.recvregex_match is not None

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    messages: list[str] = []
    monkeypatch.setattr(script_mod.log, "success", messages.append)

    entry = CHun.script("./challenge").start()
    value = entry.recv_leak(
        "main",
        regex=rb"leak=(0x[0-9a-f]+)",
        mode="hex",
        domain=RecordDomain.ELF,
    )

    assert value == 0x401000
    observation = session.rec.get_observation("main")
    assert observation is not None
    assert observation.value == value
    assert observation.domain == RecordDomain.ELF
    assert messages == [f"Leak [main] captured: {hex(value)}"]
    assert session.io.calls == [
        ("recvregex", (rb"leak=(0x[0-9a-f]+)",), {"capture": True}),
    ]


def test_script_recv_leak_supports_direct_stream_read_without_delim_or_regex(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.io.recv_values = [b"\x78\x56\x34\x12"]

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()
    entry.elf.bits = 32
    entry.elf.bytes = 4
    value = entry.recv_leak("puts")

    assert value == 0x12345678
    observation = session.rec.get_observation("puts")
    assert observation is not None
    assert observation.value == value
    assert session.io.calls == [
        ("recv", (4,), {}),
    ]


def test_script_recv_leak_validates_delim_and_regex_exclusivity(
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

    with pytest.raises(ValueError):
        entry.recv_leak("puts", delim=b":", regex=rb"(.*)")


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


def test_script_gadget_sugar_parses_register_token_in_order(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[tuple[object, tuple[str, ...]]] = []

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, image: object) -> None:
            self._image = image

        def find_gadget(self, items: list[str]) -> FakeGadget:
            calls.append((self._image, tuple(items)))
            return FakeGadget(0x401234)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.gadget["rsi_r15"] == 0x401234
    assert calls == [(entry.elf.materialize_raw(), ("pop rsi", "pop r15", "ret"))]


def test_script_gadget_sugar_supports_leave_and_ret(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    calls: list[tuple[str, ...]] = []

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, items: list[str]) -> FakeGadget:
            calls.append(tuple(items))
            return FakeGadget(0x401000 + len(calls))

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    assert entry.gadget["ret"] == 0x401001
    assert entry.gadget["leave"] == 0x401002
    assert calls == [("ret",), ("leave", "ret")]


def test_script_gadget_non_pie_offset_result_is_normalized_to_vaddr_and_cached(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    class BaseFakeELF(FakeELF):
        def __init__(self, path: str, *, libc: Any = None) -> None:
            super().__init__(path=path, libc=libc)
            self.address = 0x400000
            self.pie = False
            self.nx = True
            self.canary = False
            self.relro = "Partial RELRO"
            self.stripped = False
            self.static = False

    auto_libc = BaseFakeELF("/glibc/libc.so.6")

    def base_loader(path: str, checksec: bool = False) -> BaseFakeELF:
        _ = checksec
        if path == "./challenge":
            return BaseFakeELF(path, libc=auto_libc)
        return BaseFakeELF(path)

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class OffsetROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, _items: list[str]) -> FakeGadget:
            # 模拟某些场景下 ROP 返回 offset，而非 vaddr。
            return FakeGadget(0x1234)

    class BombROP:
        def __init__(self, _image: object) -> None:
            raise AssertionError("ROP should not be initialized on gadget cache hit")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", base_loader)
    monkeypatch.setattr(script_mod, "ROP", OffsetROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()
    assert entry.gadget["rdi"] == 0x401234

    monkeypatch.setattr(script_mod, "ROP", BombROP)
    assert entry.gadget["rdi"] == 0x401234


def test_script_gadget_sugar_supports_libc_source_and_runtime_base(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")
    session.rec = EvidenceRegistry()
    session.rec.record_fact("libc.base", 0x7F1200000000)
    calls: list[object] = []

    class FakeGadget:
        def __init__(self, address: int) -> None:
            self.address = address

    class FakeROP:
        def __init__(self, image: object) -> None:
            self._image = image

        def find_gadget(self, items: list[str]) -> FakeGadget:
            _ = items
            calls.append(self._image)
            return FakeGadget(0x1234)

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", libc="./libc.so.6").start()

    assert entry.gadget["libc:rdi"] == 0x7F1200001234
    assert calls == [entry.libc.materialize_raw()]


def test_script_gadget_sugar_rejects_invalid_token(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
) -> None:
    session = DummySession(kind="process")

    class FakeROP:
        def __init__(self, _image: object) -> None:
            pass

        def find_gadget(self, items: list[str]) -> object:
            _ = items
            return object()

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", FakeROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge").start()

    with pytest.raises(ValueError):
        _ = entry.gadget["libc:"]


def test_script_gadget_cache_hit_skips_rop_init(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    class BombROP:
        def __init__(self, _image: object) -> None:
            raise AssertionError("ROP should not be initialized on cache hit")

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", BombROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()
    version = _ScriptGadgetFacade._pwntools_version()
    entry._cache.set_gadget_query(
        entry.elf.path,
        source="elf",
        token="elf:pop rdi; ret",
        arch=entry.elf.arch,
        bits=entry.elf.bits,
        pwntools_version=version,
        found=True,
        value=0x401111,
        address_mode="vaddr",
    )

    assert entry.gadget["rdi"] == 0x401111


def test_script_gadget_not_found_is_cached(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    tmp_path,
) -> None:
    session = DummySession(kind="process")
    init_count = {"value": 0}

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    class MissROP:
        def __init__(self, _image: object) -> None:
            init_count["value"] += 1

        def find_gadget(self, _items: list[str]) -> object | None:
            return None

    class BombROP:
        def __init__(self, _image: object) -> None:
            raise AssertionError("ROP should not be initialized after not-found cache")

        def find_gadget(self, _items: list[str]) -> object | None:
            return None

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ROP", MissROP)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    entry = CHun.script("./challenge", cache_dir=str(tmp_path / "cache")).start()
    with pytest.raises(LookupError):
        _ = entry.gadget["ret"]
    assert init_count["value"] == 1

    monkeypatch.setattr(script_mod, "ROP", BombROP)
    with pytest.raises(LookupError):
        _ = entry.gadget["ret"]


def test_script_timing_includes_cache_stages(
    monkeypatch: pytest.MonkeyPatch,
    fake_pwntools_env: dict[str, Any],
    capsys: pytest.CaptureFixture[str],
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    _ = CHun.script("./challenge", libc="./libc.so.6").start()
    output = capsys.readouterr().out

    assert "script.elf.cache_prepare" in output
    assert "script.start.cache_prepare" in output
    assert "script.libc.cache_prepare" in output


def test_script_cache_hit_is_faster_than_first_start(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
) -> None:
    session = DummySession(kind="process")

    def fake_from_specs(
        cls: type[CHun], target: TargetSpec, transport: Any
    ) -> DummySession:
        return session

    class SlowFakeELF(FakeELF):
        pass

    def slow_loader(path: str, checksec: bool = False) -> SlowFakeELF:
        _ = checksec
        time.sleep(0.02)
        return SlowFakeELF(path=path)

    monkeypatch.setattr(script_mod.args, "REMOTE", False)
    monkeypatch.setattr(script_mod.args, "GDB", False)
    monkeypatch.setattr(script_mod, "ELF", slow_loader)
    monkeypatch.setattr(CHun, "from_specs", classmethod(fake_from_specs))

    cache_dir = tmp_path / ".time_cache"
    first_start = time.perf_counter()
    _ = CHun.script("./challenge", libc="./libc.so.6", cache_dir=str(cache_dir)).start()
    first_elapsed = time.perf_counter() - first_start

    second_start = time.perf_counter()
    _ = CHun.script("./challenge", libc="./libc.so.6", cache_dir=str(cache_dir)).start()
    second_elapsed = time.perf_counter() - second_start

    assert second_elapsed < first_elapsed * 0.6
