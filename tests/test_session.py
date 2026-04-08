from __future__ import annotations

from chun import CHun, CHunSession
from chun.core.models import TargetSpec, TransportSpec
from chun.transports import BlindReconnectTransport, HttpxTransport, PwntoolsTubeTransport


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


def test_process_factory_builds_session_with_pwntools_transport() -> None:
    session = CHun.process("./challenge")

    assert isinstance(session, CHunSession)
    assert session.target.kind == "process"
    assert session.transport_spec.kind == "pwntools-tube"
    assert isinstance(session.transport, PwntoolsTubeTransport)


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
