from __future__ import annotations

from pathlib import Path

from chun.cli import main
from chun.core.models import TargetSpec, TransportSpec
from chun.core.session import CHunSession


class DummyWorkflowTransport:
    def __init__(self) -> None:
        self.is_open = False
        self.raw = object()
        self.sent: list[tuple[str, bytes]] = []
        self.recv_queue = [b"menu> ", b"ok"]

    def open(self) -> None:
        self.is_open = True

    def reconnect(self) -> None:
        self.is_open = False

    def send(self, payload: bytes) -> None:
        self.sent.append(("send", payload))

    def sendline(self, payload: bytes) -> None:
        self.sent.append(("sendline", payload))

    def recv(self, size: int = 4096) -> bytes:
        if not self.recv_queue:
            return b""
        return self.recv_queue.pop(0)[:size]

    def recvuntil(self, delim: bytes) -> bytes:
        if not self.recv_queue:
            return b""
        return self.recv_queue.pop(0)

    def close(self) -> None:
        self.is_open = False


def _make_session() -> CHunSession:
    transport = DummyWorkflowTransport()
    return CHunSession(
        target=TargetSpec(kind="process", binary="./fm"),
        transport_spec=TransportSpec(kind="process"),
        transport=transport,
    )


def test_workflow_cli_export_writes_action_ir_and_transcript(tmp_path: Path) -> None:
    source = tmp_path / "exp.py"
    source.write_text(
        "\n".join(
            [
                "from chun import CHun",
                's = CHun.script("./fm").start()',
                's.recvuntil(b"> ")',
                's.sendline(b"1")',
            ]
        ),
        encoding="utf-8",
    )

    code = main(["workflow", "export", str(source)])

    assert code == 0
    assert (tmp_path / "exp.action_ir.json").exists()
    assert (tmp_path / "exp.workflow.json").exists()


def test_workflow_cli_run_executes_exported_transcript(monkeypatch, tmp_path: Path) -> None:
    source = tmp_path / "exp.py"
    source.write_text(
        "\n".join(
            [
                "from chun import CHun",
                's = CHun.script("./fm").start()',
                's.recvuntil(b"> ")',
                's.sendline(b"1")',
            ]
        ),
        encoding="utf-8",
    )

    assert main(["workflow", "export", str(source)]) == 0

    session = _make_session()

    def fake_process(_binary: str, **_kwargs) -> CHunSession:
        return session

    monkeypatch.setattr("chun.core.workflow.launchers.CHun.process", fake_process)

    code = main(["workflow", "run", str(tmp_path / "exp.workflow.json")])

    assert code == 0
    assert session.transport.sent == [("sendline", b"1")]
    assert session.rec.get_artifact("workflow.exec.result") is not None
    assert session.rec.get_context("workflow.current_checkpoint").value == "exp.__block__.0"
