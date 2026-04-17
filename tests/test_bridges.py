from __future__ import annotations

from dataclasses import dataclass, field

from chun import CHunSession
from chun.bridges.gdb import GdbMiBridge, PwntoolsGdbBridge
from chun.core.analysis import CorefileAnalyzer
from chun.core.models import TargetSpec, TransportSpec


@dataclass
class DummyTransport:
    is_open: bool = False
    raw: object = field(default_factory=object)

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def reconnect(self) -> None:
        self.is_open = True


class FakeGdbController:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def execute(self, command: str) -> str:
        self.commands.append(command)
        if command == "info registers":
            return "rip 0x401000\nrsp 0x7fffffffe000\n"
        if command == "info proc mappings":
            return "0x400000 0x401000 0x1000 0x0 /bin/challenge\n"
        return f"ok:{command}"


def _build_session() -> CHunSession:
    return CHunSession(
        target=TargetSpec(kind="process", binary="./challenge"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=DummyTransport(),
    )


def test_pwntools_gdb_bridge_attach_and_execute_write_back_to_registry() -> None:
    session = _build_session()
    controller = FakeGdbController()

    def fake_attach(
        target: object, gdbscript: str = "", exe: str | None = None, api: bool = False
    ) -> object:
        assert target is session.transport.raw
        assert exe == "./challenge"
        assert "b *main" in gdbscript
        if api:
            return (4242, controller)
        return 4242

    session.dbg = PwntoolsGdbBridge(
        session.registry, session.target, lambda: session.raw, attach_fn=fake_attach
    )
    session.transport.open()

    result = session.dbg.attach(script="b *main\nc", api=True)
    output = session.dbg.execute("echo test")
    regs = session.dbg.snapshot_regs()
    maps = session.dbg.snapshot_maps()

    assert result[0] == 4242
    assert output == "ok:echo test"
    assert regs["rip"] == 0x401000
    assert maps[0]["start"] == 0x400000
    assert session.registry.get_context("debugger.attach.pid").value == 4242
    assert session.registry.get_artifact("debugger.gdbscript") is not None


def test_pwntools_gdb_bridge_bind_runtime_updates_controller_context() -> None:
    session = _build_session()
    controller = FakeGdbController()

    session.dbg.bind_runtime(controller=controller, pid=5150)

    assert session.registry.get_context("debugger.attached").value is True
    assert session.registry.get_context("debugger.attach.pid").value == 5150


class FakeStdout:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines

    def readline(self) -> str:
        if not self.lines:
            return ""
        return self.lines.pop(0)


class FakeStdin:
    def __init__(self) -> None:
        self.writes: list[str] = []

    def write(self, data: str) -> None:
        self.writes.append(data)

    def flush(self) -> None:
        return None


class FakeMiProcess:
    def __init__(self, lines: list[str]) -> None:
        self.stdin = FakeStdin()
        self.stdout = FakeStdout(lines)
        self.stderr = FakeStdout([])
        self.terminated = False

    def terminate(self) -> None:
        self.terminated = True


def test_gdb_mi_bridge_returns_structured_results_separately_from_interactive_bridge() -> (
    None
):
    session = _build_session()

    def fake_process_factory(*_args: object, **_kwargs: object) -> FakeMiProcess:
        return FakeMiProcess(
            [
                "(gdb)\n",
                '~"hello\\n"\n',
                '^done,register-values=[{number="0",value="0x1"}]\n',
                "(gdb)\n",
            ]
        )

    session.gdb_mi = GdbMiBridge(
        session.registry, session.target, process_factory=fake_process_factory
    )
    result = session.gdb_mi.execute("-data-list-register-values x")

    assert result.result_class == "done"
    assert result.payload["register-values"][0]["number"] == "0"
    assert result.console == ["hello\n"]
    assert session.gdb_mi is not session.dbg
    assert session.registry.get_observation("gdb.mi.command.1") is not None


def test_corefile_analyzer_reads_crash_context_and_writes_registry() -> None:
    session = _build_session()

    class DummyCore:
        path = "/tmp/core.1234"
        signal = 11
        fault_addr = 0x41414141
        pc = 0x6161616C
        sp = 0x7FFFFFFFE000
        registers = {"rip": 0x6161616C, "rsp": 0x7FFFFFFFE000, "rax": 1}
        maps = [{"start": 0x400000, "end": 0x401000, "path": "/bin/challenge"}]

    session.crash = CorefileAnalyzer(session.registry, cyclic_finder=lambda _subseq: 72)
    result = session.crash.analyze(DummyCore())

    assert result.core_path == "/tmp/core.1234"
    assert result.cyclic_offset == 72
    assert session.registry.get_fact("crash.pc").value == 0x6161616C
    assert session.registry.get_fact("crash.cyclic_offset").value == 72
    assert session.registry.get_context("crash.signal").value == 11
