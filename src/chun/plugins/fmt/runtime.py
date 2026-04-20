from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from ...core.models import FmtExecutionMethod

if TYPE_CHECKING:
    from chun.core.session import CHunSession


def dispatch_fmt_payload(
    session: "CHunSession",
    payload: bytes,
    *,
    receive: bool,
    newline: bool,
    end: bytes | None,
    recv_bytes: int,
    recv_until: bytes | None,
) -> tuple[bytes | None, FmtExecutionMethod, dict[str, object]]:
    transport = session.io
    send_payload = payload if end is None else payload + end

    if _supports_exchange(session):
        receiver = _build_exchange_receiver(
            receive=receive,
            recv_until=recv_until,
            recv_bytes=recv_bytes,
        )
        response = transport.exchange(
            send_payload,
            receive=receiver,
            newline=(newline if end is None else False),
        )
        return response, FmtExecutionMethod.EXCHANGE, {
            "receive": receive,
            "recv_until": recv_until,
            "recv_bytes": recv_bytes,
            "newline": newline,
            "end": end,
        }

    if end is not None:
        transport.send(send_payload)
        dispatch = FmtExecutionMethod.SEND
    elif newline:
        transport.sendline(payload)
        dispatch = FmtExecutionMethod.SENDLINE
    else:
        transport.send(payload)
        dispatch = FmtExecutionMethod.SEND

    response = None
    if receive:
        if recv_until is not None:
            response = transport.recvuntil(recv_until)
        else:
            response = transport.recv(recv_bytes)

    return response, dispatch, {
        "receive": receive,
        "recv_until": recv_until,
        "recv_bytes": recv_bytes,
        "newline": newline,
        "end": end,
    }


def _supports_exchange(session: "CHunSession") -> bool:
    return bool(
        session.transport_spec.kind == "blind-reconnect"
        and hasattr(session.transport, "exchange")
    )


def _build_exchange_receiver(
    *,
    receive: bool,
    recv_until: bytes | None,
    recv_bytes: int,
) -> Callable[[Any], bytes | None] | None:
    if not receive:
        return None
    if recv_until is not None:
        return lambda raw: raw.recvuntil(recv_until)
    return lambda raw: raw.recv(recv_bytes)


__all__ = ["dispatch_fmt_payload"]
