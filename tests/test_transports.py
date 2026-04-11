from __future__ import annotations

from dataclasses import dataclass, field

import pytest

import chun.transports.pwntools_tube as tube_mod
from chun import CHun
from chun.core.errors import TransportCapabilityError, TransportConfigError
from chun.core.models import TargetSpec, TransportSpec
from chun.transports import BlindReconnectTransport, build_transport


@dataclass
class DummyTube:
    sent: list[bytes] = field(default_factory=list)
    recv_data: bytes = b"hello\n"
    interactive_calls: int = 0
    closed: bool = False
    recvuntil_calls: list[bytes] = field(default_factory=list)
    recvline_calls: int = 0

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def sendline(self, data: bytes) -> None:
        self.sent.append(data + b"\n")

    def sendafter(self, delim: bytes, data: bytes) -> None:
        self.recvuntil_calls.append(delim)
        self.send(data)

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        self.recvuntil_calls.append(delim)
        self.sendline(data)

    def recv(self, n: int = 4096) -> bytes:
        return self.recv_data[:n]

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        payload = self.recv_data
        index = payload.find(delim)
        if index < 0:
            return payload
        end = index if drop else index + len(delim)
        return payload[:end]

    def recvline(self, keepends: bool = True) -> bytes:
        self.recvline_calls += 1
        if keepends:
            return self.recv_data
        return self.recv_data.rstrip(b"\n")

    def interactive(self) -> None:
        self.interactive_calls += 1

    def close(self) -> None:
        self.closed = True


def test_build_transport_rejects_invalid_pairing() -> None:
    with pytest.raises(TransportConfigError):
        build_transport(
            TargetSpec(kind="http", base_url="http://example.com"),
            TransportSpec(kind="pwntools-tube"),
        )


def test_pwntools_tube_transport_supports_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[dict[str, object]] = []
    dummy = DummyTube()

    def fake_process(
        argv: list[str], env: dict[str, str] | None, cwd: str | None
    ) -> DummyTube:
        created.append({"argv": argv, "env": env, "cwd": cwd})
        return dummy

    monkeypatch.setattr(tube_mod, "process", fake_process)

    session = CHun.process(
        "./challenge", argv=["./challenge", "--fast"], env={"A": "1"}, cwd="/tmp"
    )
    io = session.io

    io.sendline(b"ping")
    assert created == [
        {"argv": ["./challenge", "--fast"], "env": {"A": "1"}, "cwd": "/tmp"}
    ]
    assert dummy.sent == [b"ping\n"]


def test_pwntools_tube_transport_supports_remote(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: list[tuple[str, int, float | None]] = []
    dummy = DummyTube(recv_data=b"pong")

    def fake_remote(host: str, port: int, timeout: float | None = None) -> DummyTube:
        created.append((host, port, timeout))
        return dummy

    monkeypatch.setattr(tube_mod, "remote", fake_remote)

    session = CHun.remote("example.com", 31337, timeout=1.5)
    io = session.io

    assert io.recv() == b"pong"
    assert created == [("example.com", 31337, 1.5)]


def test_pwntools_tube_transport_supports_sendafter_helpers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dummy = DummyTube()

    def fake_remote(host: str, port: int, timeout: float | None = None) -> DummyTube:
        assert (host, port, timeout) == ("example.com", 31337, None)
        return dummy

    monkeypatch.setattr(tube_mod, "remote", fake_remote)

    session = CHun.remote("example.com", 31337)
    io = session.io

    io.sendafter(b"name:", b"A" * 4)
    io.sendlineafter(b"menu>", b"1")

    assert dummy.recvuntil_calls == [b"name:", b"menu>"]
    assert dummy.sent == [b"AAAA", b"1\n"]


def test_pwntools_tube_transport_passthroughs_other_tube_methods(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dummy = DummyTube(recv_data=b"line\n")

    def fake_remote(host: str, port: int, timeout: float | None = None) -> DummyTube:
        assert (host, port, timeout) == ("example.com", 31337, None)
        return dummy

    monkeypatch.setattr(tube_mod, "remote", fake_remote)

    session = CHun.remote("example.com", 31337)
    io = session.io

    assert io.recvline() == b"line\n"
    assert dummy.recvline_calls == 1


def test_pwntools_tube_transport_supports_ssh_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, object]] = []
    dummy = DummyTube()

    class DummySSHClient:
        def process(
            self, argv: list[str], env: dict[str, str] | None, cwd: str | None
        ) -> DummyTube:
            calls.append({"argv": argv, "env": env, "cwd": cwd})
            return dummy

        def close(self) -> None:
            calls.append({"closed": True})

    def fake_ssh(**kwargs: object) -> DummySSHClient:
        calls.append(kwargs)
        return DummySSHClient()

    monkeypatch.setattr(tube_mod, "ssh", fake_ssh)

    session = CHun.ssh_process(
        "ssh.example.com",
        user="ctf",
        binary="/home/ctf/challenge",
        argv=["/home/ctf/challenge", "--menu"],
        env={"MODE": "1"},
        cwd="/home/ctf",
    )
    session.open()
    session.close()

    assert calls[0]["host"] == "ssh.example.com"
    assert calls[0]["user"] == "ctf"
    assert calls[1] == {
        "argv": ["/home/ctf/challenge", "--menu"],
        "env": {"MODE": "1"},
        "cwd": "/home/ctf",
    }


def test_httpx_transport_manages_client_lifecycle() -> None:
    calls: list[tuple[str, str, dict[str, object]]] = []

    class DummyClient:
        def __init__(self) -> None:
            self.closed = False

        def request(
            self, method: str, path: str, **kwargs: object
        ) -> dict[str, object]:
            calls.append((method, path, kwargs))
            return {"ok": True, "path": path}

        def close(self) -> None:
            self.closed = True

    client = DummyClient()
    session = CHun.http(
        "http://example.com",
        headers={"X-Test": "1"},
        timeout=2.0,
        client_factory=lambda target, spec: client,
    )

    response = session.io.request("GET", "/health", params={"a": "1"})
    session.close()

    assert response == {"ok": True, "path": "/health"}
    assert calls == [("GET", "/health", {"params": {"a": "1"}})]
    assert client.closed is True


def test_websocket_transport_supports_send_recv_and_close() -> None:
    class DummySocket:
        def __init__(self) -> None:
            self.sent: list[str | bytes] = []
            self.closed = False

        def send(self, message: str | bytes) -> None:
            self.sent.append(message)

        def recv(self) -> str:
            return "pong"

        def close(self) -> None:
            self.closed = True

    socket = DummySocket()
    session = CHun.websocket(
        "ws://example.com/socket",
        connection_factory=lambda target, spec: socket,
    )

    io = session.io
    io.send_message("ping")
    assert io.recv_message() == "pong"
    session.close()

    assert socket.sent == ["ping"]
    assert socket.closed is True


def test_blind_reconnect_transport_rebuilds_connection_per_exchange() -> None:
    created: list[DummyTube] = []

    def factory() -> DummyTube:
        tube = DummyTube(recv_data=b"response")
        created.append(tube)
        return tube

    session = CHun.blind(factory)
    first = session.io.exchange(b"%1$p")
    second = session.io.exchange(b"%2$p")

    assert first == b"response"
    assert second == b"response"
    assert len(created) == 2
    assert created[0].closed is True
    assert created[1].closed is True


def test_blind_reconnect_transport_supports_custom_run() -> None:
    created: list[DummyTube] = []

    def factory() -> DummyTube:
        tube = DummyTube(recv_data=b"response")
        created.append(tube)
        return tube

    transport = BlindReconnectTransport(
        TargetSpec(kind="blind"),
        TransportSpec(
            kind="blind-reconnect",
            metadata={"connection_factory": factory},
        ),
    )
    transport.open()

    result = transport.run(lambda raw: raw.recvuntil(b"\n"))

    assert result == b"response"
    assert len(created) == 1
    assert created[0].closed is True


def test_blind_reconnect_transport_rejects_plain_recv() -> None:
    transport = BlindReconnectTransport(
        TargetSpec(kind="blind"),
        TransportSpec(
            kind="blind-reconnect", metadata={"connection_factory": lambda: DummyTube()}
        ),
    )
    transport.open()

    with pytest.raises(TransportCapabilityError):
        transport.recv()
