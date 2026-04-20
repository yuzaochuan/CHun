from __future__ import annotations

from types import SimpleNamespace

from chun import (
    CHunSession,
    ContextKind,
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
