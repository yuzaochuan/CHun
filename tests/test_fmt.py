from __future__ import annotations

import importlib
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import pytest
from pwnlib.context import context as pwntools_context
from pwnlib.fmtstr import fmtstr_split

import chun.plugins.fmt.service as fmt_service_mod
from chun import CHunSession
from chun.core.models import (
    FactKind,
    FmtExecutionMethod,
    FmtExecutionResult,
    FmtExecutionReceipt,
    FmtLayoutPolicy,
    FmtOffsetProbeMode,
    FmtOffsetProbeResult,
    FmtReadMode,
    FmtWriteRequest,
    FmtValueRef,
    FmtTargetRef,
    FmtWritePlan as CoreFmtWritePlan,
    FmtWriteTask,
    RecordDomain,
    TargetSpec,
    TransportSpec,
)
from chun.plugins.fmt import (
    DefaultFmtReadExecutor,
    DefaultFmtPlanExecutor,
    DefaultFmtWritePlanner,
    DefaultFmtTaskRenderer,
    FmtExecutionError,
    FmtOffsetMissingError,
    FmtReadError,
    FmtService,
    FmtOffsetNotFoundError,
    FmtOffsetProbe,
    FmtSymbolResolveError,
    FmtTaskPolicy,
    FmtWriteAtom,
    FmtWriteError,
    FmtWriteStrategy,
)
from chun.transports.blind_reconnect import BlindReconnectTransport


class DummyTransport:
    def __init__(self) -> None:
        self.is_open = False
        self.raw = object()

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def reconnect(self) -> None:
        self.is_open = False


class DummyExecTransport:
    def __init__(self, response: bytes = b"ok") -> None:
        self.is_open = False
        self.raw = object()
        self.sent: list[tuple[str, bytes]] = []
        self.response = response

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
        return self.response[:n]

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        data = self.response
        if delim in data:
            end = data.index(delim) + len(delim)
            if drop:
                return data[: end - len(delim)]
            return data[:end]
        return data


class DummyBlindRawConnection:
    def __init__(self, response: bytes) -> None:
        self.response = response
        self.sent: list[tuple[str, bytes]] = []

    def send(self, data: bytes) -> None:
        self.sent.append(("send", data))

    def sendline(self, data: bytes) -> None:
        self.sent.append(("sendline", data))

    def recv(self, n: int = 4096) -> bytes:
        return self.response[:n]

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        data = self.response
        if delim in data:
            end = data.index(delim) + len(delim)
            if drop:
                return data[: end - len(delim)]
            return data[:end]
        return data

    def close(self) -> None:
        return None


class DummyProbeTransport:
    def __init__(self, response: bytes) -> None:
        self._response = response
        self.is_open = False
        self.raw = object()
        self.sent: list[bytes] = []

    def open(self) -> None:
        self.is_open = True

    def close(self) -> None:
        self.is_open = False

    def reconnect(self) -> None:
        self.is_open = False

    def sendline(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int = 4096) -> bytes:
        return self._response[:n]


def build_session() -> CHunSession:
    return CHunSession(
        target=TargetSpec(kind="blind"),
        transport_spec=TransportSpec(kind="blind-reconnect"),
        transport=DummyTransport(),
    )


def build_probe_session(response: bytes) -> CHunSession:
    return CHunSession(
        target=TargetSpec(kind="process"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=DummyProbeTransport(response),
    )


def build_exec_session(response: bytes = b"ok") -> CHunSession:
    return CHunSession(
        target=TargetSpec(kind="process"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=DummyExecTransport(response),
    )


def build_blind_exec_session(response: bytes = b"blind-ok") -> CHunSession:
    target = TargetSpec(kind="blind")
    spec = TransportSpec(
        kind="blind-reconnect",
        metadata={"connection_factory": lambda: DummyBlindRawConnection(response)},
    )
    return CHunSession(
        target=target,
        transport_spec=spec,
        transport=BlindReconnectTransport(target, spec),
    )


def test_fmt_package_is_importable_as_package() -> None:
    module = importlib.import_module("chun.plugins.fmt")
    service_module = importlib.import_module("chun.plugins.fmt.service")
    model_module = importlib.import_module("chun.core.models.fmt")

    assert hasattr(module, "__path__")
    assert service_module.FmtService is FmtService
    assert model_module.FmtWritePlan is CoreFmtWritePlan
    assert model_module.FmtOffsetProbeResult is FmtOffsetProbeResult


def test_session_exposes_fmt_service() -> None:
    session = build_session()

    assert isinstance(session.fmt, FmtService)
    assert session.fmt.session is session


def test_fmt_plan_writes_uses_bound_elf_and_libc_resolution() -> None:
    session = build_session()
    session.resolve.bind_defaults(
        elf=SimpleNamespace(got={"printf@got": 0x404018}, bits=64, little_endian=True),
        libc_elf=SimpleNamespace(sym={"system": 0x4C490}, address=0x7FFFF7DD0000),
    )
    service = FmtService(session)

    plan = service.plan_writes(
        {"printf@got": "system"},
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.BY_ATOM,
        store=True,
    )

    assert plan.requests[0].target.address == 0x404018
    assert plan.requests[0].value.value == 0x7FFFF7E1C490
    assert plan.pointer_size == 8
    assert plan.total_atoms == 3
    assert plan.total_tasks == 3
    assert plan.is_blind_safe is True
    stored = session.rec.get_artifact("fmt.plan")
    assert stored is not None
    assert stored.domain == RecordDomain.FMT
    assert stored.metadata["bits"] == 64
    assert stored.metadata["task_count"] == 3


def test_fmt_service_reads_arch_from_registry_context_when_no_elf_bound() -> None:
    session = build_session()
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    plan = session.fmt.plan_writes(
        {0x804A020: 0x11223344},
        strategy=FmtWriteStrategy.INT,
        task_policy=FmtTaskPolicy.BY_TARGET,
    )

    assert plan.bits == 32
    assert plan.pointer_size == 4
    assert plan.endian == "little"
    assert plan.total_atoms == 1


def test_fmt_service_normalization_uses_session_resolve_for_symbol_inputs() -> None:
    session = build_session()
    calls: list[str] = []
    mapping = {
        "printf@got": 0x404018,
        "system": 0x7FFFF7E1C490,
    }
    session.resolve = SimpleNamespace(
        symbol=lambda name: calls.append(name) or mapping[name],
        default_elf=None,
        default_libc_elf=None,
    )

    plan = session.fmt.plan_writes(
        {"printf@got": "system"},
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.BY_TARGET,
        store=False,
    )

    assert calls == ["printf@got", "system"]
    assert plan.requests[0].target.address == 0x404018
    assert plan.requests[0].value.value == 0x7FFFF7E1C490


def test_fmt_offset_roundtrip_uses_registry_fact() -> None:
    session = build_session()

    stored = session.fmt.set_offset(7, source="unit-test")
    loaded = session.fmt.get_offset(required=True)

    assert stored.index == 7
    assert loaded is not None
    assert loaded.index == 7
    fact = session.rec.get_fact("fmt.offset")
    assert fact is not None
    assert fact.kind == FactKind.OFFSET
    assert fact.domain == RecordDomain.FMT


def test_fmt_offset_probe_sequential_payload_uses_32bit_default_signature() -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    response = b"CHun0x1111.0x" + signature_hex + b".0x4444.0x5555"
    session = build_probe_session(response)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    result = FmtOffsetProbe().discover_offset(session, max_slots=4)

    assert result.index == 2
    assert result.method == FmtOffsetProbeMode.SEQUENTIAL
    assert result.signature == signature
    stored = session.rec.get_fact("fmt.offset")
    assert stored is not None
    assert stored.value == 2
    assert stored.domain == RecordDomain.FMT
    assert result.matched_token == f"0x{signature_hex.decode()}"
    assert result.raw_output == response
    assert result.sep == b"."
    assert result.window_start == 1
    assert result.window_end == 4
    assert session.rec.get_observation("fmt.offset.response") is not None
    assert session.rec.get_artifact("fmt.offset.probe") is not None
    assert session.transport.sent[0] == b"CHun%p.%p.%p.%p"  # type: ignore[attr-defined]


def test_fmt_offset_probe_sequential_payload_uses_64bit_default_signature() -> None:
    signature = b"CHunnnnn"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    response = b"CHunnnnn0x1111.0x" + signature_hex + b".0x3333"
    session = build_probe_session(response)
    session.rec.set_context("arch.bits", 64, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    result = FmtOffsetProbe().discover_offset(session, max_slots=3, store=False)

    assert result.index == 2
    assert result.signature == signature
    assert session.transport.sent[0] == b"CHunnnnn%p.%p.%p"  # type: ignore[attr-defined]


def test_fmt_offset_probe_positional_window_payload_restores_logical_slot() -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    response = b"CHun0x1111.0x" + signature_hex + b".0x3333.0x4444"
    session = build_probe_session(response)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    result = FmtOffsetProbe().discover_offset(
        session,
        mode=FmtOffsetProbeMode.POSITIONAL_WINDOW,
        window_start=17,
        window_size=4,
        store=False,
    )

    assert result.index == 18
    assert result.method == FmtOffsetProbeMode.POSITIONAL_WINDOW
    assert result.window_start == 17
    assert result.window_end == 20
    assert (
        session.transport.sent[0] == b"CHun%17$p.%18$p.%19$p.%20$p"  # type: ignore[attr-defined]
    )


def test_fmt_offset_probe_counts_nil_slots_when_matching_position() -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    response = b"CHun0xffe4e8ac.(nil).0x1.0x" + signature_hex + b".0x41414141\n"
    session = build_probe_session(response)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    result = FmtOffsetProbe().discover_offset(session, max_slots=5, store=False)

    assert result.index == 4
    assert result.tokens == ("0xffe4e8ac", "(nil)", "0x1", f"0x{signature_hex.decode()}", "0x41414141")


def test_fmt_offset_probe_supports_custom_separator() -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    response = b"CHun0x1111,0x" + signature_hex + b",0x3333"
    session = build_probe_session(response)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    result = FmtOffsetProbe().discover_offset(session, max_slots=3, sep=b",", store=False)

    assert result.index == 2
    assert result.sep == b","
    assert session.transport.sent[0] == b"CHun%p,%p,%p"  # type: ignore[attr-defined]


def test_fmt_offset_probe_allows_empty_separator_as_unstable_best_effort() -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    response = b"CHun(nil)0x" + signature_hex
    session = build_probe_session(response)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    result = FmtOffsetProbe().discover_offset(session, max_slots=2, sep=b"")

    assert result.index == 2
    assert result.confidence < 1.0
    assert result.metadata["unstable"] is True
    assert result.metadata["unstable_parse"] is True
    assert session.transport.sent[0] == b"CHun%p%p"  # type: ignore[attr-defined]


def test_fmt_offset_probe_rejects_unsafe_custom_signature() -> None:
    session = build_probe_session(b"")
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    with pytest.raises(ValueError):
        FmtOffsetProbe().discover_offset(session, signature=b"AA%A", store=False)


def test_fmt_offset_probe_raises_custom_error_when_not_found() -> None:
    session = build_probe_session(b"CHun0x1111.0x2222.0x3333")
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    with pytest.raises(FmtOffsetNotFoundError):
        FmtOffsetProbe().discover_offset(session, max_slots=3, store=False)


def test_fmt_service_find_offset_uses_default_prober() -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    session = build_probe_session(b"CHun0xaaa.0xbbb.0x" + signature_hex)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    result = session.fmt.find_offset()

    assert result.index == 3
    assert result.method == FmtOffsetProbeMode.SEQUENTIAL
    assert result.signature == signature
    stored = session.rec.get_fact("fmt.offset")
    assert stored is not None
    assert stored.value == 3


def test_fmt_service_find_offset_is_silent_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    session = build_probe_session(b"CHun0xaaa.0xbbb.0x" + signature_hex)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)
    messages: list[tuple[str, str]] = []

    monkeypatch.setattr(
        fmt_service_mod.log,
        "success",
        lambda message: messages.append(("success", message)),
    )
    monkeypatch.setattr(
        fmt_service_mod.log,
        "info",
        lambda message: messages.append(("info", message)),
    )

    result = session.fmt.find_offset()

    assert result.index == 3
    assert messages == []


def test_fmt_service_find_offset_logs_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signature = b"CHun"
    signature_hex = format(int.from_bytes(signature, "little"), "x").encode()
    session = build_probe_session(b"CHun0xaaa.0xbbb.0x" + signature_hex)
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)
    messages: list[tuple[str, str]] = []

    monkeypatch.setattr(
        fmt_service_mod.log,
        "success",
        lambda message: messages.append(("success", message)),
    )
    monkeypatch.setattr(
        fmt_service_mod.log,
        "info",
        lambda message: messages.append(("info", message)),
    )

    result = session.fmt.find_offset(loginfo=True)

    assert result.index == 3
    assert messages == [
        (
            "success",
            "fmt offset found: index=3 method=sequential token=0x6e754843",
        ),
        (
            "info",
            "fmt offset detail: signature=b'CHun' sep=b'.' window=1-32 confidence=0.95",
        ),
    ]
    assert session.rec.get_artifact("fmt.offset.probe") is not None


def test_fmt_blind_facade_defaults_to_atom_tasks() -> None:
    session = build_session()
    session.resolve.bind_defaults(
        elf=SimpleNamespace(got={"printf@got": 0x404018}, bits=64, little_endian=True),
        libc_elf=SimpleNamespace(sym={"system": 0x4C490}, address=0x7FFFF7DD0000),
    )
    session.fmt = FmtService(session)

    plan = session.fmt.blind().plan_writes({"printf@got": "system"})

    assert plan.task_policy == FmtTaskPolicy.BY_ATOM


def test_default_reader_reads_raw_bytes_via_string_primitive() -> None:
    session = build_exec_session(b"ABCD::CHUN::tail")
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)
    reader = DefaultFmtReadExecutor()
    target = FmtTargetRef(raw=0x804A020, address=0x804A020)

    leak = reader.read(
        session,
        target,
        size=4,
        mode=FmtReadMode.RAW,
        offset=7,
    )

    assert leak.raw == b"ABCD"
    assert leak.decoded == b"ABCD"
    assert leak.metadata["dispatch"] == "sendline"
    assert leak.metadata["primitive"] == "memory_string"
    assert leak.metadata["body"] == b"ABCD"
    assert session.transport.sent == [  # type: ignore[attr-defined]
        ("sendline", b"%7$s::CHUN::" + (0x804A020).to_bytes(4, "little"))
    ]


def test_fmt_service_read_uses_default_reader_and_records_observation() -> None:
    session = build_exec_session(b"WXYZ::CHUN::")
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)
    session.fmt.set_offset(6)

    leak = session.fmt.read(0x804A030, size=4, mode=FmtReadMode.POINTER)

    assert leak.raw == b"WXYZ"
    assert leak.decoded == int.from_bytes(b"WXYZ", "little")
    stored = session.rec.get_observation("fmt.leak.0x804a030")
    assert stored is not None
    assert stored.domain == RecordDomain.FMT
    assert stored.value == leak


def test_default_reader_supports_custom_fmt_for_pointer_text() -> None:
    session = build_exec_session(b"0x41424344")
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    leak = DefaultFmtReadExecutor().read(
        session,
        FmtTargetRef(raw=0xDEADBEEF, address=0xDEADBEEF),
        size=4,
        mode=FmtReadMode.POINTER,
        offset=6,
        fmt="%6$p",
        append_target=False,
        recv_until=None,
        strict_terminator=False,
    )

    assert leak.decoded == 0x41424344
    assert leak.metadata["primitive"] == "custom"
    assert leak.metadata["append_target"] is False
    assert session.transport.sent == [("sendline", b"%6$p")]  # type: ignore[attr-defined]


def test_fmt_service_write_convenience_executes_plan_directly() -> None:
    session = build_exec_session(b"write-ok\n")
    session.resolve.bind_defaults(
        elf=SimpleNamespace(got={"printf@got": 0x404018}, bits=64, little_endian=True),
        libc_elf=SimpleNamespace(sym={"system": 0x4C490}, address=0x7FFFF7DD0000),
    )
    session.fmt.set_offset(6)

    result = session.fmt.write(
        "printf@got",
        "system",
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.BY_ATOM,
    )

    assert isinstance(result, FmtExecutionResult)
    assert result.total_tasks == 3
    assert result.task_indexes == (0, 1, 2)
    assert all(response == b"write-ok\n" for response in result.responses)
    assert session.rec.get_artifact("fmt.write.plan") is not None
    assert session.rec.get_artifact("fmt.write.task.0") is not None
    assert session.rec.get_observation("fmt.write.response.0") is not None


def test_default_planner_uses_pwntools_backend_and_sorts_byte_atoms() -> None:
    planner = DefaultFmtWritePlanner()
    request = FmtWriteRequest(
        target=FmtTargetRef(raw=0x404018, address=0x404018),
        value=FmtValueRef(raw=0xDEADBEEF, value=0xDEADBEEF),
        strategy=FmtWriteStrategy.BYTE,
    )

    plan = planner.plan(
        (request,),
        bits=64,
        endian="little",
        pointer_size=8,
        task_policy=FmtTaskPolicy.BY_ATOM,
    )

    assert plan.backend == "pwntools"
    assert [(atom.address, atom.value, atom.shift) for atom in plan.atoms] == [
        (0x40401A, 0xAD, 16),
        (0x404019, 0xBE, 8),
        (0x40401B, 0xDE, 24),
        (0x404018, 0xEF, 0),
    ]
    assert plan.total_tasks == 4
    assert plan.data_offset is None


def test_default_planner_uses_pwntools_backend_and_sorts_short_atoms() -> None:
    planner = DefaultFmtWritePlanner()
    request = FmtWriteRequest(
        target=FmtTargetRef(raw=0x404020, address=0x404020),
        value=FmtValueRef(raw=0x41424344, value=0x41424344),
        strategy=FmtWriteStrategy.SHORT,
    )

    plan = planner.plan(
        (request,),
        bits=64,
        endian="little",
        pointer_size=8,
        task_policy=FmtTaskPolicy.BY_TARGET,
    )

    assert plan.backend == "pwntools"
    assert [(atom.address, atom.value, atom.shift) for atom in plan.atoms] == [
        (0x404022, 0x4142, 16),
        (0x404020, 0x4344, 0),
    ]
    assert plan.total_tasks == 1


def test_native_planner_rejects_unaligned_ptr_writes() -> None:
    planner = DefaultFmtWritePlanner()
    request = FmtWriteRequest(
        target=FmtTargetRef(raw=0x404019, address=0x404019),
        value=FmtValueRef(raw=0x4141414141414141, value=0x4141414141414141),
        strategy=FmtWriteStrategy.PTR,
    )

    with pytest.raises(ValueError, match="unaligned fmt target address"):
        planner.plan(
            (request,),
            bits=64,
            endian="little",
            pointer_size=8,
            task_policy=FmtTaskPolicy.PACKED,
            backend="native",
        )


def test_default_renderer_renders_hhn_stream_with_internal_counter() -> None:
    renderer = DefaultFmtTaskRenderer()
    atoms = (
        FmtWriteAtom(
            request_index=0,
            piece_index=0,
            address=0x404018,
            value=0x41,
            width=1,
            order_key=0,
        ),
        FmtWriteAtom(
            request_index=0,
            piece_index=1,
            address=0x404019,
            value=0x44,
            width=1,
            order_key=1,
        ),
    )
    task = FmtWriteTask(task_index=0, atoms=atoms, independent=True)
    plan = CoreFmtWritePlan(
        bits=64,
        pointer_size=8,
        endian="little",
        offset=None,
        data_offset=None,
        backend="native",
        strategy=FmtWriteStrategy.BYTE,
        task_policy=FmtTaskPolicy.BY_TARGET,
        requests=(),
        atoms=atoms,
        tasks=(task,),
    )

    rendered = renderer.render(
        task,
        plan=plan,
        offset=6,
        layout=FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter=0,
    )

    assert [(step.arg_index, step.specifier, step.padding) for step in rendered.steps] == [
        (6, "hhn", 65),
        (7, "hhn", 3),
    ]
    assert rendered.final_counter == 68
    assert rendered.backend == "native"
    assert rendered.data_offset == 6
    assert rendered.fmt_bytes.startswith(b"%65c%6$hhn%3c%7$hhn")
    assert rendered.data_bytes == (
        (0x404018).to_bytes(8, "little") + (0x404019).to_bytes(8, "little")
    )
    assert rendered.payload.startswith(b"%65c%6$hhn%3c%7$hhn")
    assert rendered.payload.endswith(
        (0x404018).to_bytes(8, "little") + (0x404019).to_bytes(8, "little")
    )


def test_default_renderer_applies_modulo_padding_wrap() -> None:
    renderer = DefaultFmtTaskRenderer()
    atom = FmtWriteAtom(
        request_index=0,
        piece_index=0,
        address=0x404018,
        value=0x02,
        width=1,
    )
    task = FmtWriteTask(task_index=0, atoms=(atom,), independent=True)
    plan = CoreFmtWritePlan(
        bits=64,
        pointer_size=8,
        endian="little",
        offset=None,
        data_offset=None,
        backend="native",
        strategy=FmtWriteStrategy.BYTE,
        task_policy=FmtTaskPolicy.BY_ATOM,
        requests=(),
        atoms=(atom,),
        tasks=(task,),
    )

    rendered = renderer.render(
        task,
        plan=plan,
        offset=10,
        layout=FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter=0xFE,
    )

    step = rendered.steps[0]
    assert step.padding == 4
    assert step.modulus == 0x100
    assert step.counter_before == 0xFE
    assert step.counter_after == 0x102
    assert rendered.final_counter == 0x102
    assert rendered.payload.startswith(b"%4c%10$hhn")


def test_default_renderer_uses_pwntools_fmt_and_data_split() -> None:
    session = build_session()
    session.resolve.bind_defaults(
        elf=SimpleNamespace(got={"printf@got": 0x404018}, bits=64, little_endian=True),
        libc_elf=SimpleNamespace(sym={"system": 0x4C490}, address=0x7FFFF7DD0000),
    )
    plan = session.fmt.plan_writes(
        {"printf@got": "system"},
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.BY_ATOM,
        offset=6,
        data_offset=6,
        store=False,
    )

    rendered = session.fmt.render_task(plan.tasks[0], plan=plan, offset=6, data_offset=6)

    assert rendered.backend == "pwntools"
    assert rendered.fmt_bytes
    assert rendered.data_bytes
    assert rendered.payload == rendered.fmt_bytes + rendered.data_bytes
    assert rendered.data_offset == 6


def test_pwntools_backend_render_matches_fmtstr_split_ground_truth() -> None:
    session = build_session()
    plan = session.fmt.plan_writes(
        {0x404018: 0x11223344},
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.PACKED,
        offset=6,
        data_offset=6,
        store=False,
    )

    rendered = session.fmt.render_task(plan.tasks[0], plan=plan, offset=6, data_offset=6)
    with pwntools_context.local(bits=64, endian="little"):
        expected_fmt, expected_data = fmtstr_split(
            6,
            {0x404018: b"\x44\x33\x22\x11"},
            write_size="short",
        )

    assert rendered.backend == "pwntools"
    assert rendered.fmt_bytes == expected_fmt
    assert rendered.data_bytes == expected_data
    assert rendered.payload == expected_fmt + expected_data


def test_fmt_service_passes_no_dollars_to_pwntools_backend() -> None:
    session = build_session()

    plan = session.fmt.plan_writes(
        {0x404018: 0x11223344},
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.PACKED,
        offset=6,
        data_offset=6,
        no_dollars=True,
        store=False,
    )
    rendered = session.fmt.render_task(plan.tasks[0], plan=plan, offset=6, data_offset=6)

    assert plan.metadata["no_dollars"] is True
    assert rendered.backend == "pwntools"
    assert b"$" not in rendered.fmt_bytes


def test_fmt_service_wraps_pwntools_badbytes_failures_with_fmt_write_error() -> None:
    session = build_session()

    with pytest.raises(FmtWriteError):
        session.fmt.plan_writes(
            {0x404018: 0x41},
            strategy=FmtWriteStrategy.BYTE,
            badbytes=b"\x18",
            store=False,
        )


def test_default_executor_dispatches_rendered_payload_on_pwntools_transport() -> None:
    session = build_exec_session(b"done\n")
    atom = FmtWriteAtom(
        request_index=0,
        piece_index=0,
        address=0x404018,
        value=0x41,
        width=1,
    )
    task = FmtWriteTask(task_index=0, atoms=(atom,), independent=True)
    plan = CoreFmtWritePlan(
        bits=64,
        pointer_size=8,
        endian="little",
        offset=6,
        data_offset=6,
        backend="native",
        strategy=FmtWriteStrategy.BYTE,
        task_policy=FmtTaskPolicy.BY_ATOM,
        requests=(),
        atoms=(atom,),
        tasks=(task,),
    )
    rendered = DefaultFmtTaskRenderer().render(task, plan=plan, offset=6)

    receipt = DefaultFmtPlanExecutor().execute_task(
        session,
        task,
        plan=plan,
        offset=6,
        rendered=rendered,
    )

    assert receipt.dispatch == FmtExecutionMethod.SENDLINE
    assert receipt.payload == rendered.payload
    assert receipt.response == b"done\n"
    assert receipt.transport_kind == "pwntools-tube"
    assert session.transport.sent == [("sendline", rendered.payload)]  # type: ignore[attr-defined]


def test_default_executor_uses_exchange_for_blind_transport() -> None:
    session = build_blind_exec_session(b"blind-result")
    atom = FmtWriteAtom(
        request_index=0,
        piece_index=0,
        address=0x404018,
        value=0x41,
        width=1,
    )
    task = FmtWriteTask(task_index=0, atoms=(atom,), independent=True)
    plan = CoreFmtWritePlan(
        bits=64,
        pointer_size=8,
        endian="little",
        offset=6,
        data_offset=6,
        backend="native",
        strategy=FmtWriteStrategy.BYTE,
        task_policy=FmtTaskPolicy.BY_ATOM,
        requests=(),
        atoms=(atom,),
        tasks=(task,),
    )
    rendered = DefaultFmtTaskRenderer().render(task, plan=plan, offset=6)

    receipt = DefaultFmtPlanExecutor().execute_task(
        session,
        task,
        plan=plan,
        offset=6,
        rendered=rendered,
    )

    assert receipt.dispatch == FmtExecutionMethod.EXCHANGE
    assert receipt.response == b"blind-result"


def test_service_execute_plan_uses_default_executor_and_records_results() -> None:
    session = build_exec_session(b"exec-ok\n")
    session.resolve.bind_defaults(
        elf=SimpleNamespace(got={"printf@got": 0x404018}, bits=64, little_endian=True),
        libc_elf=SimpleNamespace(sym={"system": 0x4C490}, address=0x7FFFF7DD0000),
    )
    session.fmt.set_offset(6)

    plan = session.fmt.plan_writes(
        {"printf@got": "system"},
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.BY_ATOM,
        store=False,
    )

    result = session.fmt.execute_plan(plan)

    assert isinstance(result, FmtExecutionResult)
    assert result.total_tasks == plan.total_tasks
    assert all(isinstance(item, FmtExecutionReceipt) for item in result.receipts)
    assert result.receipts[0].dispatch == FmtExecutionMethod.SENDLINE
    stored_result = session.rec.get_artifact("fmt.exec.task.0")
    stored_response = session.rec.get_observation("fmt.exec.response.0")
    stored_render = session.rec.get_artifact("fmt.exec.render.task.0")
    assert stored_result is not None
    assert stored_result.domain == RecordDomain.FMT
    assert stored_response is not None
    assert stored_response.value == b"exec-ok\n"
    assert stored_render is not None
    assert stored_render.domain == RecordDomain.FMT


def test_fmt_service_execute_plan_raises_explicit_offset_error_when_missing() -> None:
    session = build_exec_session(b"exec-ok\n")
    atom = FmtWriteAtom(
        request_index=0,
        piece_index=0,
        address=0x404018,
        value=0x41,
        width=1,
    )
    task = FmtWriteTask(task_index=0, atoms=(atom,), independent=True)
    plan = CoreFmtWritePlan(
        bits=64,
        pointer_size=8,
        endian="little",
        offset=None,
        data_offset=None,
        backend="native",
        strategy=FmtWriteStrategy.BYTE,
        task_policy=FmtTaskPolicy.BY_ATOM,
        requests=(),
        atoms=(atom,),
        tasks=(task,),
    )

    with pytest.raises(FmtOffsetMissingError):
        session.fmt.execute_plan(plan)


def test_fmt_service_plan_writes_raises_explicit_symbol_resolve_error() -> None:
    session = build_session()
    session.resolve = SimpleNamespace(
        symbol=lambda name: (_ for _ in ()).throw(KeyError(name)),
        default_elf=None,
        default_libc_elf=None,
    )

    with pytest.raises(FmtSymbolResolveError):
        session.fmt.plan_writes({"printf@got": "system"}, store=False)


def test_default_reader_raises_explicit_error_when_terminator_missing() -> None:
    session = build_exec_session(b"ABCD")
    session.rec.set_context("arch.bits", 32, domain=RecordDomain.FMT)
    session.rec.set_context("arch.endian", "little", domain=RecordDomain.FMT)

    with pytest.raises(FmtReadError):
        DefaultFmtReadExecutor().read(
            session,
            FmtTargetRef(raw=0x804A020, address=0x804A020),
            size=4,
            mode=FmtReadMode.RAW,
            offset=7,
        )


def test_default_executor_wraps_dispatch_failures_with_fmt_execution_error() -> None:
    class BrokenExecTransport(DummyExecTransport):
        def sendline(self, data: bytes) -> None:
            raise OSError("boom")

    session = CHunSession(
        target=TargetSpec(kind="process"),
        transport_spec=TransportSpec(kind="pwntools-tube"),
        transport=BrokenExecTransport(),
    )
    atom = FmtWriteAtom(
        request_index=0,
        piece_index=0,
        address=0x404018,
        value=0x41,
        width=1,
    )
    task = FmtWriteTask(task_index=0, atoms=(atom,), independent=True)
    plan = CoreFmtWritePlan(
        bits=64,
        pointer_size=8,
        endian="little",
        offset=6,
        data_offset=6,
        backend="native",
        strategy=FmtWriteStrategy.BYTE,
        task_policy=FmtTaskPolicy.BY_ATOM,
        requests=(),
        atoms=(atom,),
        tasks=(task,),
    )

    with pytest.raises(FmtExecutionError):
        DefaultFmtPlanExecutor().execute_task(session, task, plan=plan, offset=6)


def test_service_render_plan_records_rendered_artifacts() -> None:
    session = build_session()
    session.resolve.bind_defaults(
        elf=SimpleNamespace(got={"printf@got": 0x404018}, bits=64, little_endian=True),
        libc_elf=SimpleNamespace(sym={"system": 0x4C490}, address=0x7FFFF7DD0000),
    )
    session.fmt.set_offset(6)

    plan = session.fmt.plan_writes(
        {"printf@got": "system"},
        strategy=FmtWriteStrategy.SHORT,
        task_policy=FmtTaskPolicy.BY_ATOM,
        store=False,
    )
    rendered = session.fmt.render_plan(plan, store=True)

    assert len(rendered) == plan.total_tasks
    assert all(item.layout == FmtLayoutPolicy.ADDRESSES_LAST for item in rendered)
    stored = session.rec.get_artifact("fmt.render.task.0")
    assert stored is not None
    assert stored.domain == RecordDomain.FMT


def test_fmt_models_are_frozen_value_objects() -> None:
    target = FmtTargetRef(raw="printf@got", address=0x404018, metadata={"source": "unit"})

    with pytest.raises(FrozenInstanceError):
        target.address = 0x404020  # type: ignore[misc]

    with pytest.raises(TypeError):
        target.metadata["source"] = "mutated"  # type: ignore[index]


def test_fmt_models_normalize_sequence_fields_to_tuple() -> None:
    atom = FmtWriteAtom(
        request_index=0,
        piece_index=0,
        address=0x404018,
        value=0x41,
        width=1,
    )
    task = FmtWriteTask(task_index=0, atoms=[atom])  # type: ignore[arg-type]

    assert isinstance(task.atoms, tuple)
