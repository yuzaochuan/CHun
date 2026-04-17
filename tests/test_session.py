from __future__ import annotations

from dataclasses import dataclass

from chun import CHun, CHunSession
from chun.core.inference import InferenceService
from chun.core.models import FactKind, RecordDomain, TargetSpec, TransportSpec
from chun.core.registry import EvidenceRegistry
from chun.transports import (
    BlindReconnectTransport,
    HttpxTransport,
    PwntoolsTubeTransport,
)


class DummyTransport:
    def __init__(self) -> None:
        self.is_open = False
        self.raw = object()
        self.calls: list[str] = []

    def open(self) -> None:
        self.calls.append("open")
        self.is_open = True

    def close(self) -> None:
        self.calls.append("close")
        self.is_open = False

    def reconnect(self) -> None:
        self.calls.append("reconnect")


@dataclass
class DummyBinary:
    path: str
    arch: str
    bits: int
    bytes: int
    endian: str


def test_process_factory_builds_session_with_pwntools_transport() -> None:
    session = CHun.process("./challenge")

    assert isinstance(session, CHunSession)
    assert session.target.kind == "process"
    assert session.transport_spec.kind == "pwntools-tube"
    assert isinstance(session.transport, PwntoolsTubeTransport)
    assert isinstance(session.registry, EvidenceRegistry)
    assert isinstance(session.infer, InferenceService)
    assert session.dbg is not None
    assert session.gdb_mi is not None
    assert session.resolve is not None
    assert session.crash is not None


def test_http_factory_builds_httpx_transport() -> None:
    session = CHun.http("http://example.com")

    assert session.target.kind == "http"
    assert session.transport_spec.kind == "httpx"
    assert isinstance(session.transport, HttpxTransport)


def test_blind_factory_builds_blind_transport() -> None:
    session = CHun.blind(lambda: object())

    assert session.target.kind == "blind"
    assert session.transport_spec.kind == "blind-reconnect"
    assert isinstance(session.transport, BlindReconnectTransport)


def test_session_io_opens_transport_lazily() -> None:
    transport = DummyTransport()
    session = CHunSession(
        target=TargetSpec(kind="blind"),
        transport_spec=TransportSpec(kind="blind-reconnect"),
        transport=transport,
    )

    assert transport.is_open is False
    assert session.io is transport
    assert transport.calls == ["open"]
    assert session.raw is transport.raw


def test_session_exposes_registry_alias_and_seeded_context() -> None:
    session = CHun.remote("example.com", 31337)

    assert session.rec is session.registry
    assert session.registry.get_context("session.target.kind") is not None
    assert session.registry.get_context("session.transport.kind") is not None


def test_session_minimal_inference_loop_writes_fact_back_to_registry() -> None:
    session = CHun.process("./challenge")
    expected_base = 0x7F1234500000
    puts_offset = 0x080000
    leak = expected_base + puts_offset

    session.rec.record_symbol_leak(
        "puts",
        leak,
        domain=RecordDomain.LIBC,
        source="got",
        confidence=0.90,
    )
    result = session.infer.libc_base_from_symbol_leak("puts", symbol_offset=puts_offset)

    fact = session.registry.get_fact("libc.base")
    assert fact is not None
    assert fact.kind == FactKind.BASE_ADDRESS
    assert fact.value == expected_base
    assert result.stored_fact is fact
    assert result.aligned_base == expected_base


def test_session_exposes_libc_shortcuts() -> None:
    session = CHun.process("./challenge")
    session.rec.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    session.rec.record_fact(
        "libc.version",
        "glibc-test",
        kind=FactKind.VERSION,
        domain=RecordDomain.LIBC,
    )

    assert session.libc_base == 0x7F0000000000
    assert session.libc_version == "glibc-test"


def test_session_bind_binaries_keeps_objects_on_session_and_only_writes_scalar_context() -> None:
    session = CHunSession(
        target=TargetSpec(kind="process"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=DummyTransport(),
    )
    elf = DummyBinary(
        path="./challenge",
        arch="amd64",
        bits=64,
        bytes=8,
        endian="little",
    )
    libc_elf = DummyBinary(
        path="./libc.so.6",
        arch="amd64",
        bits=64,
        bytes=8,
        endian="little",
    )

    session.bind_binaries(elf=elf, libc_elf=libc_elf)

    assert session.elf is elf
    assert session.libc_elf is libc_elf
    assert session.rec.require_context("binary.path").value == "./challenge"
    assert session.rec.require_context("binary.arch").value == "amd64"
    assert session.rec.require_context("binary.bits").value == 64
    assert session.rec.require_context("arch.bits").value == 64
    assert session.rec.require_context("arch.endian").value == "little"
    assert session.rec.require_context("arch.pointer_size").value == 8
    assert session.rec.require_context("libc.path").value == "./libc.so.6"
    assert session.rec.require_context("libc.arch").value == "amd64"
    assert session.rec.require_context("libc.bits").value == 64
    assert session.rec.get_context("resolve.default.elf") is None
    assert session.rec.get_context("resolve.default.libc_elf") is None
