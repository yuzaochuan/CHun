from __future__ import annotations

import re
from dataclasses import dataclass

from ...core.errors import CHunError
from ...core.models import (
    FactKind,
    FmtOffsetProbeMode,
    FmtOffsetProbeResult,
    RecordDomain,
)

_TOKEN_RE = re.compile(rb"\(nil\)|0x[0-9a-fA-F]+")
_POINTER_RE = re.compile(rb"0x[0-9a-fA-F]+")
_NIL_TOKEN = b"(nil)"


class FmtOffsetProbeError(CHunError):
    """FMT offset 探测基础异常。"""


class FmtOffsetNotFoundError(FmtOffsetProbeError):
    """在限定窗口内未命中 signature。"""


@dataclass(slots=True, frozen=True)
class FmtOffsetProbe:
    """无状态的 offset 探测器。"""

    signature32: bytes = b"CHun"
    signature64: bytes = b"CHunnnnn"
    max_slots: int = 32
    recv_size: int = 4096
    sep: bytes = b"."

    def find_offset(
        self,
        session: object,
        *,
        mode: FmtOffsetProbeMode | str = FmtOffsetProbeMode.SEQUENTIAL,
        max_slots: int | None = None,
        window_start: int | None = None,
        window_size: int | None = None,
        sep: bytes | None = None,
        signature: bytes | None = None,
        store: bool = True,
        store_fact: bool = True,
        source: str = "fmt.probe",
    ) -> FmtOffsetProbeResult:
        return self.discover_offset(
            session,
            mode=mode,
            max_slots=max_slots,
            window_start=window_start,
            window_size=window_size,
            sep=sep,
            signature=signature,
            store=store,
            store_fact=store_fact,
            source=source,
        )

    def discover_offset(
        self,
        session: object,
        *,
        mode: FmtOffsetProbeMode | str = FmtOffsetProbeMode.SEQUENTIAL,
        max_slots: int | None = None,
        window_start: int | None = None,
        window_size: int | None = None,
        recv_size: int | None = None,
        sep: bytes | None = None,
        signature: bytes | None = None,
        store: bool = True,
        store_fact: bool = True,
        source: str = "fmt.probe",
    ) -> FmtOffsetProbeResult:
        resolved_mode = FmtOffsetProbeMode(mode)
        size = recv_size if recv_size is not None else self.recv_size
        sep_bytes = self.sep if sep is None else sep
        pointer_size = self._pointer_size(session)
        endian = self._endian(session)
        signature_bytes = self._signature_bytes(pointer_size, signature)
        payload, logical_slots = self._build_payload(
            mode=resolved_mode,
            signature=signature_bytes,
            max_slots=max_slots,
            window_start=window_start,
            window_size=window_size,
            sep=sep_bytes,
        )

        io_obj = session.io
        io_obj.sendline(payload)
        response = io_obj.recv(size)

        result = self._parse_result(
            response,
            mode=resolved_mode,
            signature=signature_bytes,
            logical_slots=logical_slots,
            sep=sep_bytes,
            endian=endian,
            source=source,
            payload=payload,
        )
        if result.index is None:
            raise FmtOffsetNotFoundError(
                f"unable to locate fmt offset in {resolved_mode.value} mode"
            )

        if store:
            self._store_result(session, result, payload=payload, store_fact=store_fact)

        return result

    def _build_payload(
        self,
        *,
        mode: FmtOffsetProbeMode,
        signature: bytes,
        max_slots: int | None,
        window_start: int | None,
        window_size: int | None,
        sep: bytes,
    ) -> tuple[bytes, tuple[int, ...]]:
        if mode == FmtOffsetProbeMode.SEQUENTIAL:
            slot_count = max_slots if max_slots is not None else self.max_slots
            if slot_count <= 0:
                raise ValueError("max_slots must be positive")
            logical_slots = tuple(range(1, slot_count + 1))
            specifiers = [b"%p" for _ in logical_slots]
            return signature + sep.join(specifiers), logical_slots

        if window_start is None or window_size is None:
            raise ValueError("positional_window mode requires window_start and window_size")
        if window_start <= 0 or window_size <= 0:
            raise ValueError("window_start and window_size must be positive")
        logical_slots = tuple(range(window_start, window_start + window_size))
        specifiers = [f"%{index}$p".encode() for index in logical_slots]
        return signature + sep.join(specifiers), logical_slots

    def _parse_result(
        self,
        response: bytes,
        *,
        mode: FmtOffsetProbeMode,
        signature: bytes,
        logical_slots: tuple[int, ...],
        sep: bytes,
        endian: str,
        source: str,
        payload: bytes,
    ) -> FmtOffsetProbeResult:
        expected_value = int.from_bytes(signature, byteorder=endian)
        body = self._response_body(response, signature)
        unstable = sep == b""
        tokens = (
            self._tokenize_without_separator(body, limit=len(logical_slots))
            if unstable
            else self._tokenize_with_separator(body, sep=sep, limit=len(logical_slots))
        )

        matched_index: int | None = None
        matched_token: str | None = None
        for ordinal, token in enumerate(tokens):
            parsed_value = self._token_to_int(token)
            if parsed_value is None:
                continue
            if parsed_value == expected_value:
                matched_index = logical_slots[ordinal]
                matched_token = token
                break

        confidence = 0.0
        if matched_index is not None:
            confidence = 0.95 if not unstable else 0.70

        metadata: dict[str, object] = {
            "payload": payload,
            "expected_value": expected_value,
        }
        if unstable:
            metadata["unstable"] = True
            metadata["unstable_parse"] = True

        return FmtOffsetProbeResult(
            index=matched_index,
            method=mode,
            signature=signature,
            matched_token=matched_token,
            verified=False,
            confidence=confidence,
            raw_output=response,
            tokens=tokens,
            window_start=logical_slots[0] if logical_slots else None,
            window_end=logical_slots[-1] if logical_slots else None,
            sep=sep,
            source=source,
            metadata=metadata,
        )

    def _store_result(
        self,
        session: object,
        result: FmtOffsetProbeResult,
        *,
        payload: bytes,
        store_fact: bool,
    ) -> None:
        session.rec.record_observation(
            "fmt.offset.response",
            result.raw_output,
            domain=RecordDomain.FMT,
            source=result.source,
            confidence=result.confidence,
            tags=["fmt", "offset", "probe", "response"],
            metadata={
                "method": result.method.value,
                "signature": result.signature,
                "sep": result.sep,
                "window_start": result.window_start,
                "window_end": result.window_end,
                "payload": payload,
                **result.metadata,
            },
            overwrite=True,
        )
        session.rec.record_artifact(
            "fmt.offset.probe",
            result,
            domain=RecordDomain.FMT,
            source=result.source,
            tags=["fmt", "offset", "probe"],
            metadata={
                "method": result.method.value,
                "matched_token": result.matched_token,
                "verified": result.verified,
            },
            overwrite=True,
        )
        if result.index is not None and store_fact:
            session.rec.record_fact(
                "fmt.offset",
                result.index,
                kind=FactKind.OFFSET,
                domain=RecordDomain.FMT,
                source=result.source,
                confidence=result.confidence,
                tags=["fmt", "offset", "probe"],
                metadata={
                    "method": result.method.value,
                    "signature": result.signature,
                    "matched_token": result.matched_token,
                    "verified": result.verified,
                    "window_start": result.window_start,
                    "window_end": result.window_end,
                    "sep": result.sep,
                    **result.metadata,
                },
                overwrite=True,
            )

    @staticmethod
    def _response_body(response: bytes, signature: bytes) -> bytes:
        if response.startswith(signature):
            return response[len(signature) :]
        if signature in response:
            return response.split(signature, 1)[1]
        return response

    def _tokenize_with_separator(
        self,
        body: bytes,
        *,
        sep: bytes,
        limit: int,
    ) -> tuple[str, ...]:
        chunks = body.split(sep)
        out: list[str] = []
        for chunk in chunks[:limit]:
            token = chunk.strip()
            if not token:
                out.append("")
                continue
            if token.startswith(_NIL_TOKEN):
                out.append(_NIL_TOKEN.decode())
                continue
            match = _POINTER_RE.match(token)
            if match is not None:
                out.append(match.group(0).decode())
                continue
            out.append(token.decode(errors="ignore"))
        return tuple(out)

    def _tokenize_without_separator(self, body: bytes, *, limit: int) -> tuple[str, ...]:
        return tuple(
            match.group(0).decode(errors="ignore")
            for match in _TOKEN_RE.finditer(body)
        )[:limit]

    @staticmethod
    def _token_to_int(token: str) -> int | None:
        if token == _NIL_TOKEN.decode() or not token:
            return None
        try:
            return int(token, 16)
        except ValueError:
            return None

    def _signature_bytes(self, pointer_size: int, signature: bytes | None) -> bytes:
        resolved = (
            self.signature32
            if pointer_size == 4
            else self.signature64
            if pointer_size == 8
            else None
        ) if signature is None else signature
        if resolved is None:
            raise FmtOffsetProbeError(f"unsupported pointer size: {pointer_size}")
        if not resolved:
            raise ValueError("signature must not be empty")
        if b"\x00" in resolved or b"%" in resolved:
            raise ValueError("signature must not contain NUL or '%'")
        if len(resolved) != pointer_size:
            raise ValueError(
                f"signature length must match pointer size ({pointer_size} bytes)"
            )
        return resolved

    def _pointer_size(self, session: object) -> int:
        elf = getattr(session, "elf", None)
        if elf is not None and getattr(elf, "bits", None):
            return int(elf.bits) // 8

        entry = session.rec.get_context("arch.bits")
        if entry is not None:
            value = entry.value if hasattr(entry, "value") else entry
            return int(value) // 8

        return 8

    def _endian(self, session: object) -> str:
        elf = getattr(session, "elf", None)
        if elf is not None and hasattr(elf, "little_endian"):
            return "little" if bool(getattr(elf, "little_endian", True)) else "big"

        entry = session.rec.get_context("arch.endian")
        if entry is not None:
            value = entry.value if hasattr(entry, "value") else entry
            return str(value)

        return "little"


__all__ = [
    "FmtOffsetNotFoundError",
    "FmtOffsetProbe",
    "FmtOffsetProbeError",
]
