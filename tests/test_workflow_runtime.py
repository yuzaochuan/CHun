from __future__ import annotations

from types import SimpleNamespace

from chun import (
    AnalysisNode,
    CHunSession,
    ContextKind,
    ExprNode,
    LiteralNode,
    ProcessLauncher,
    ProcessWorkflowRuntime,
    RecordDomain,
    TargetSpec,
    TransportSpec,
    WorkflowCheckpoint,
    WorkflowExecutor,
    WorkflowPrimitive,
    WorkflowStepReceipt,
    WorkflowTranscript,
)
from pwnlib.util.packing import p64


class DummyWorkflowTransport:
    def __init__(self) -> None:
        self.is_open = False
        self.raw = object()
        self.sent: list[tuple[str, bytes]] = []
        self.recv_queue = [b"> ", b"ok\n"]

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def reconnect(self) -> None:
        self.is_open = False

    def send(self, data: bytes) -> None:
        self.sent.append(("send", data))

    def sendline(self, data: bytes) -> None:
        self.sent.append(("sendline", data))

    def recv(self, n: int = 4096) -> bytes:
        if not self.recv_queue:
            return b""
        return self.recv_queue.pop(0)[:n]

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        if not self.recv_queue:
            return b""
        data = self.recv_queue.pop(0)
        return data[:-len(delim)] if drop and data.endswith(delim) else data


class DummyLauncher:
    def __init__(self) -> None:
        self.transport = DummyWorkflowTransport()
        self.last_session: CHunSession | None = None

    def launch(self, primitive: object | None = None) -> CHunSession:
        self.last_session = CHunSession(
            target=TargetSpec(kind="process", binary="./chall"),
            transport_spec=TransportSpec(kind="pwntools-tube"),
            transport=self.transport,
        )
        return self.last_session


def test_workflow_executor_runs_handwritten_transcript_and_records_registry() -> None:
    transcript = WorkflowTranscript(
        entry_action="exp.__block__.0",
        primitives=(
            WorkflowPrimitive(kind="session_init", payload="./chall"),
            WorkflowPrimitive(
                kind="expect",
                payload=b"> ",
                source_action="exp.__block__.0",
                source_node="expect",
            ),
            WorkflowPrimitive(
                kind="sendline",
                payload=b"1",
                source_action="exp.__block__.0",
                source_node="sendline",
            ),
            WorkflowPrimitive(
                kind="recv",
                payload=4,
                source_action="exp.__block__.0",
                source_node="recv",
            ),
            WorkflowPrimitive(
                kind="checkpoint",
                checkpoint=WorkflowCheckpoint(
                    name="menu.after_add",
                    source_action="exp.__block__.0",
                    source_node="checkpoint",
                ),
                source_action="exp.__block__.0",
                source_node="checkpoint",
            ),
        ),
    )

    launcher = DummyLauncher()
    result = WorkflowExecutor(runtime=ProcessWorkflowRuntime()).execute(
        transcript,
        launcher=launcher,
    )

    assert result.total_steps == 5
    assert result.final_checkpoint is not None
    assert result.final_checkpoint.name == "menu.after_add"
    assert launcher.transport.sent == [("sendline", b"1")]
    assert launcher.last_session is not None
    assert launcher.last_session.rec.get_artifact("workflow.exec.result") is not None
    assert (
        launcher.last_session.rec.get_context("workflow.current_checkpoint").value
        == "menu.after_add"
    )


def test_process_runtime_checkpoint_updates_session_context() -> None:
    launcher = DummyLauncher()
    session = launcher.launch()
    receipt = ProcessWorkflowRuntime().checkpoint(
        session,
        WorkflowCheckpoint(name="menu.after_add"),
        step_index=3,
    )

    assert isinstance(receipt, WorkflowStepReceipt)
    assert receipt.success is True
    ctx = session.rec.get_context("workflow.current_checkpoint")
    assert ctx is not None
    assert ctx.value == "menu.after_add"
    assert ctx.domain == RecordDomain.WORKFLOW
    assert ctx.kind == ContextKind.SESSION


def test_process_launcher_delegates_to_chun_process(monkeypatch) -> None:
    captured: dict[str, object] = {}

    def fake_process(binary: str, **kwargs: object) -> object:
        captured["binary"] = binary
        captured["kwargs"] = kwargs
        return object()

    monkeypatch.setattr("chun.core.workflow.launchers.CHun.process", fake_process)

    launcher = ProcessLauncher(binary="./chall", argv=["./chall", "arg"])
    launched = launcher.launch()

    assert launched is not None
    assert captured["binary"] == "./chall"
    assert captured["kwargs"]["argv"] == ["./chall", "arg"]


def test_process_launcher_binds_inferred_libc_from_binary(monkeypatch, tmp_path) -> None:
    session = CHunSession(
        target=TargetSpec(kind="process", binary="./chall"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=DummyWorkflowTransport(),
    )

    def fake_process(_binary: str, **_kwargs: object) -> CHunSession:
        return session

    chall_path = tmp_path / "chall"
    chall_path.write_bytes(b"\x7fELF")
    libc_path = tmp_path / "libc.so.6"
    libc_path.write_bytes(b"\x7fELF")
    fake_libc = SimpleNamespace(path=str(libc_path), sym={"puts": 0x80000})
    fake_elf = SimpleNamespace(path=str(chall_path), libc=fake_libc)

    def fake_elf_loader(path: str, checksec: bool = False) -> object:
        assert checksec is False
        if path == str(chall_path):
            return fake_elf
        if path == str(libc_path):
            return fake_libc
        raise AssertionError(path)

    monkeypatch.setattr("chun.core.workflow.launchers.CHun.process", fake_process)
    monkeypatch.setattr("chun.core.workflow.launchers.ELF", fake_elf_loader)

    launcher = ProcessLauncher(binary=str(chall_path))
    launched = launcher.launch()

    assert launched is session
    assert session.elf is fake_elf
    assert session.libc_elf is fake_libc


def test_workflow_executor_replays_dynamic_ret2libc_flow() -> None:
    expected_base = 0x7F1234500000
    expected_system = expected_base + 0x4C490

    class Ret2libcLauncher(DummyLauncher):
        def launch(self, primitive: object | None = None) -> CHunSession:
            session = super().launch(primitive)
            state: dict[str, int | None] = {"base": None}
            self.transport.recv_queue = [b"puts: ", (expected_base + 0x80000).to_bytes(8, "little")]
            session.bind_binaries(libc_elf=SimpleNamespace(sym={"puts": 0x80000}))

            def fake_infer(name: str, *, symbol_offset: int) -> SimpleNamespace:
                assert name == "puts"
                assert symbol_offset == 0x80000
                state["base"] = expected_base
                return SimpleNamespace(value=expected_base)

            def fake_symbol(symbol: str) -> int:
                assert symbol == "system"
                assert state["base"] == expected_base
                return expected_system

            session.infer = SimpleNamespace(libc_base_from_symbol_leak=fake_infer)
            session.resolve = SimpleNamespace(symbol=fake_symbol)
            return session

    transcript = WorkflowTranscript(
        entry_action="exp.__block__.0",
        primitives=(
            WorkflowPrimitive(kind="session_init", payload="./chall", metadata={"bind_target": "s"}),
            WorkflowPrimitive(
                kind="assign",
                payload=AnalysisNode(
                    callee="s.recv_leak",
                    metadata={"source_text": 's.recv_leak("puts", "puts: ", offset=0)'},
                ),
                metadata={"target": "leak"},
            ),
            WorkflowPrimitive(
                kind="call",
                payload=AnalysisNode(
                    callee="s.infer.libc_base_from_symbol_leak",
                    metadata={
                        "source_text": 's.infer.libc_base_from_symbol_leak("puts", symbol_offset=s.libc.sym["puts"])'
                    },
                ),
            ),
            WorkflowPrimitive(
                kind="sendline",
                payload=LiteralNode(
                    value='p64(s.resolve.symbol("system"))',
                    value_type="expr_source",
                ),
            ),
        ),
    )

    launcher = Ret2libcLauncher()
    result = WorkflowExecutor(runtime=ProcessWorkflowRuntime()).execute(
        transcript,
        launcher=launcher,
    )

    assert result.total_steps == 4
    assert launcher.transport.sent == [("sendline", p64(expected_system))]


def test_process_runtime_reports_unresolved_expr_payload_clearly() -> None:
    runtime = ProcessWorkflowRuntime()
    unresolved = ExprNode(
        kind="call",
        callee="p64",
        metadata={"source_text": 'p64(s.resolve.symbol("system"))'},
    )

    try:
        runtime._coerce_bytes(unresolved)
    except TypeError as exc:
        assert str(exc) == (
            'workflow payload is not bytes-compatible: ExprNode(p64(s.resolve.symbol("system")))'
        )
    else:
        raise AssertionError("expected TypeError for unresolved workflow payload")


def test_process_runtime_ignores_script_cache_kwargs_in_session_init_metadata() -> None:
    runtime = ProcessWorkflowRuntime()
    primitive = WorkflowPrimitive(
        kind="session_init",
        payload="./chall",
        metadata={
            "launcher_kwargs": {
                "cache": True,
                "cache_dir": "./.chun_cache",
                "auto_local_libc": False,
            }
        },
    )

    session = runtime.start_session(primitive=primitive)
    assert isinstance(session, CHunSession)
