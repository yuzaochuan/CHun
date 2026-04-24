from __future__ import annotations

from pwnlib.util.packing import p64

from chun._compat import context
from chun import CHunSession
from chun.core.models import FactKind, ObservationKind, RecordDomain, TargetSpec, TransportSpec
from chun.core.replay import ReplayExecutor
from chun.transports.base import BaseTransport


class ReplayDummyTransport(BaseTransport):
    def __init__(self, target: TargetSpec, spec: TransportSpec, *, probe_response: bytes) -> None:
        super().__init__(target, spec)
        self._probe_response = probe_response
        self.sent: list[tuple[str, bytes]] = []
        self._recv_count = 0

    def _open(self) -> None:
        return None

    def _close(self) -> None:
        return None

    @property
    def raw(self) -> object:
        return self

    def send(self, data: bytes) -> None:
        self._require_open()
        payload = bytes(data)
        self.sent.append(("send", payload))
        self._emit_replay("send", payload=payload)

    def sendline(self, data: bytes) -> None:
        self._require_open()
        payload = bytes(data)
        self.sent.append(("sendline", payload))
        self._emit_replay("sendline", payload=payload)

    def recv(self, n: int = 4096) -> bytes:
        self._require_open()
        if self._recv_count > 0:
            return b""
        self._recv_count += 1
        return self._probe_response[:n]

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        self._require_open()
        self._emit_replay("expect", payload=bytes(delim), drop=drop)
        return b"" if drop else bytes(delim)


def _build_session(*, probe_response: bytes) -> CHunSession:
    target = TargetSpec(kind="process", binary="./chall")
    spec = TransportSpec(kind="pwntools-tube")
    transport = ReplayDummyTransport(target, spec, probe_response=probe_response)
    return CHunSession(target=target, transport_spec=spec, transport=transport)


def test_replay_validation_can_promote_observation_to_fact() -> None:
    session = _build_session(probe_response=b"aabb0x62626161\n")
    _ = session.io
    session.io.recvuntil(b"> ")
    session.io.sendline(b"1")
    session.rec.record_observation(
        "fmt.offset.candidate",
        6,
        kind=ObservationKind.SCALAR,
        domain=RecordDomain.FMT,
        source="unit-test",
        confidence=0.70,
    )

    executor = ReplayExecutor(session.rec.replay.blob_store)
    result = session.rec.validate_observation(
        "fmt.offset.candidate",
        session_factory=lambda: _build_session(probe_response=b"aabb0x62626161\n"),
        executor=executor,
        probe=b"aabb%6$p",
        predicate=lambda out: b"0x62626161" in out,
        promote_to_fact=True,
        fact_name="fmt.offset",
        fact_kind=FactKind.OFFSET,
        fact_source="unit-test.verify",
    )

    assert result.ok is True
    fact = session.rec.get_fact("fmt.offset")
    assert fact is not None
    assert fact.value == 6
    assert fact.kind == FactKind.OFFSET
    observation = session.rec.get_observation("fmt.offset.candidate")
    assert observation is not None
    assert observation.metadata["verification_status"] == "passed"


def test_replay_trace_supports_dynamic_ret2libc_style_payload_bytes() -> None:
    expected_system = 0x7F1234500000 + 0x4C490
    dynamic_payload = b"A" * 8 + p64(expected_system)
    created: list[CHunSession] = []

    def _factory() -> CHunSession:
        fresh = _build_session(probe_response=b"aabb0x62626161\n")
        created.append(fresh)
        return fresh

    session = _build_session(probe_response=b"aabb0x62626161\n")
    _ = session.io
    session.io.sendline(dynamic_payload)
    session.rec.record_observation(
        "fmt.offset.candidate",
        6,
        kind=ObservationKind.SCALAR,
        domain=RecordDomain.FMT,
        source="ret2libc",
        confidence=0.70,
    )

    executor = ReplayExecutor(session.rec.replay.blob_store)
    result = session.rec.validate_observation(
        "fmt.offset.candidate",
        session_factory=_factory,
        executor=executor,
        probe=b"aabb%6$p",
        predicate=lambda out: b"0x62626161" in out,
        promote_to_fact=False,
    )

    assert result.ok is True
    assert created
    replay_sent = created[0].transport.sent  # type: ignore[attr-defined]
    assert ("sendline", dynamic_payload) in replay_sent
    assert ("sendline", b"aabb%6$p") in replay_sent


def test_replay_executor_restores_pwntools_log_level() -> None:
    session = _build_session(probe_response=b"ok\n")
    executor = ReplayExecutor(session.rec.replay.blob_store)
    old_level = context.log_level
    context.log_level = "debug"
    expected_level = context.log_level

    def _factory() -> CHunSession:
        context.log_level = "error"
        return _build_session(probe_response=b"ok\n")

    try:
        result = executor.replay(
            tuple(),
            session_factory=_factory,
            probe=b"ping",
            predicate=lambda out: b"ok" in out,
        )
        assert result.ok is True
        assert context.log_level == expected_level
    finally:
        context.log_level = old_level


def test_replay_executor_can_capture_replay_session_registry_lines() -> None:
    session = _build_session(probe_response=b"ok\n")
    executor = ReplayExecutor(session.rec.replay.blob_store)

    result = executor.replay(
        tuple(),
        session_factory=lambda: _build_session(probe_response=b"ok\n"),
        probe=b"ping",
        predicate=lambda out: b"ok" in out,
        capture_registry=True,
    )

    lines = result.metadata.get("replay_registry_lines")
    assert isinstance(lines, tuple)
    assert lines
    assert str(lines[0]).startswith("[Registry]")
