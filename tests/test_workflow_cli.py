from __future__ import annotations

import json
from pathlib import Path

from chun.cli import main
from chun.core.cache import CACHE_SCHEMA_VERSION, file_cache_key, file_sha256
from chun.core.models import TargetSpec, TransportSpec
from chun.core.registry import EvidenceRegistry
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


def test_workflow_cli_run_prints_registry_summary(monkeypatch, tmp_path: Path) -> None:
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
    show_calls: list[dict[str, object]] = []

    def fake_process(_binary: str, **_kwargs) -> CHunSession:
        return session

    def fake_show(self: EvidenceRegistry, **kwargs: object) -> list[str]:
        show_calls.append(kwargs)
        return []

    monkeypatch.setattr("chun.core.workflow.launchers.CHun.process", fake_process)
    monkeypatch.setattr(EvidenceRegistry, "show", fake_show)

    code = main(["workflow", "run", str(tmp_path / "exp.workflow.json")])

    assert code == 0
    assert show_calls == [
        {
            "layers": ("context", "facts"),
            "detail": "standard",
            "emit": "info",
        }
    ]


def test_cache_cli_state_reports_hit_for_elf_libc_and_gadget(tmp_path: Path, capsys) -> None:
    target = tmp_path / "chall"
    target.write_bytes(b"fake-binary")
    target_sha = file_sha256(target)

    cache_root = tmp_path / ".cache"
    elf_key = file_cache_key(target, namespace="elf", schema=CACHE_SCHEMA_VERSION)
    libc_key = file_cache_key(target, namespace="libc", schema=CACHE_SCHEMA_VERSION)
    gadget_key = file_cache_key(
        target,
        namespace="gadget",
        schema=CACHE_SCHEMA_VERSION,
        extra="elf-amd64-64-pwntools-4.14.1",
    )

    (cache_root / "elf").mkdir(parents=True, exist_ok=True)
    (cache_root / "libc").mkdir(parents=True, exist_ok=True)
    (cache_root / "gadget").mkdir(parents=True, exist_ok=True)

    (cache_root / "elf" / f"{elf_key}.json").write_text(
        json.dumps(
            {
                "schema": CACHE_SCHEMA_VERSION,
                "path": str(target),
                "sha256": target_sha,
                "arch": "amd64",
                "bits": 64,
                "pie": False,
                "address_mode": "vaddr",
                "symbols": {"main": 0x401000},
                "got": {"puts": 0x404018},
                "plt": {"puts": 0x401030},
            }
        ),
        encoding="utf-8",
    )
    (cache_root / "libc" / f"{libc_key}.json").write_text(
        json.dumps(
            {
                "schema": CACHE_SCHEMA_VERSION,
                "path": str(target),
                "sha256": target_sha,
                "source": "specified",
                "trusted": True,
                "usable_for_remote": True,
                "core_symbols": {"system": 0x4C490},
                "extra_symbols": {},
                "strings": {"/bin/sh": 0x196031},
            }
        ),
        encoding="utf-8",
    )
    (cache_root / "gadget" / f"{gadget_key}.json").write_text(
        json.dumps(
            {
                "schema": CACHE_SCHEMA_VERSION,
                "path": str(target),
                "sha256": target_sha,
                "source": "elf",
                "arch": "amd64",
                "bits": 64,
                "pwntools_version": "4.14.1",
                "queries": {
                    "elf:pop rdi; ret": {"found": True, "value": 0x40123A, "address_mode": "vaddr"},
                    "elf:leave; ret": {"found": False, "value": None, "address_mode": "vaddr"},
                },
            }
        ),
        encoding="utf-8",
    )

    code = main(["cache", "state", str(target), "--cache-dir", str(cache_root)])
    output = capsys.readouterr().out

    assert code == 0
    assert "elf: hit" in output
    assert "elf.symbols[main]=0x401000" in output
    assert "elf.got[puts]=0x404018" in output
    assert "elf.plt[puts]=0x401030" in output
    assert "libc: hit" in output
    assert "gadget: hit records=1 total_queries=2 found=1 not_found=1" in output
    assert "gadget.query[1][elf:leave; ret]: found=false value=null mode=vaddr" in output
    assert "gadget.query[1][elf:pop rdi; ret]: found=true value=0x40123a mode=vaddr" in output


def test_cache_cli_state_resolves_linked_libc_when_target_is_binary(tmp_path: Path, capsys) -> None:
    target = tmp_path / "chall"
    target.write_bytes(b"fake-binary")
    libc = tmp_path / "libc.so.6"
    libc.write_bytes(b"fake-libc")

    target_sha = file_sha256(target)
    libc_sha = file_sha256(libc)
    cache_root = tmp_path / ".cache"
    elf_key = file_cache_key(target, namespace="elf", schema=CACHE_SCHEMA_VERSION)
    libc_key = file_cache_key(libc, namespace="libc", schema=CACHE_SCHEMA_VERSION)

    (cache_root / "elf").mkdir(parents=True, exist_ok=True)
    (cache_root / "libc").mkdir(parents=True, exist_ok=True)

    (cache_root / "elf" / f"{elf_key}.json").write_text(
        json.dumps(
            {
                "schema": CACHE_SCHEMA_VERSION,
                "path": str(target),
                "sha256": target_sha,
                "arch": "amd64",
                "bits": 64,
                "pie": True,
                "address_mode": "offset",
                "symbols": {},
                "got": {},
                "plt": {},
                "linked_libc_path": str(libc),
                "linked_libc_sha256": libc_sha,
                "linked_libc_source": "specified",
            }
        ),
        encoding="utf-8",
    )
    (cache_root / "libc" / f"{libc_key}.json").write_text(
        json.dumps(
            {
                "schema": CACHE_SCHEMA_VERSION,
                "path": str(libc),
                "sha256": libc_sha,
                "source": "specified",
                "trusted": True,
                "usable_for_remote": True,
                "core_symbols": {"system": 0x4C490},
                "extra_symbols": {},
                "strings": {"/bin/sh": 0x196031},
            }
        ),
        encoding="utf-8",
    )

    code = main(["cache", "state", str(target), "--cache-dir", str(cache_root)])
    output = capsys.readouterr().out
    expected_libc_cache_path = cache_root / "libc" / f"{libc_key}.json"

    assert code == 0
    assert "elf: hit" in output
    assert "libc: hit" in output
    assert f"path={expected_libc_cache_path}" in output


def test_cache_cli_state_reports_miss_when_no_cache(tmp_path: Path, capsys) -> None:
    target = tmp_path / "chall"
    target.write_bytes(b"fake-binary")
    cache_root = tmp_path / ".cache"
    cache_root.mkdir(parents=True, exist_ok=True)

    code = main(["cache", "state", str(target), "--cache-dir", str(cache_root)])
    output = capsys.readouterr().out

    assert code == 0
    assert "elf: miss" in output
    assert "libc: miss" in output
    assert "gadget: miss records=0 total_queries=0 found=0 not_found=0" in output
