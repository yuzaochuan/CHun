from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from ...core.models import FmtLeak, FmtReadMode, FmtTargetRef
from .errors import FmtReadError
from .runtime import dispatch_fmt_payload

if TYPE_CHECKING:
    from chun.core.session import CHunSession


@dataclass(slots=True, frozen=True)
class _ReadPlan:
    """一次 fmt.read 的内部执行计划。"""

    payload: bytes
    recv_until: bytes | None
    primitive: str
    append_target: bool
    terminator: bytes


@dataclass(slots=True)
class DefaultFmtReadExecutor:
    """默认的 fmt 读取执行器。

    设计目标：
    1. 普通场景下保持 `session.fmt.read(addr, ...)` 直接可用。
    2. 默认仍然以“内存字符串泄漏”为主，因为它适合读取任意地址内容。
    3. 为高级场景预留 `fmt=` / `append_target=` / `recv_until=`，允许用户手动覆盖 payload
       与捕获边界，而不是把所有读场景都硬编码进 mode。
    """

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
        fmt: bytes | str | None = None,
        append_target: bool | None = None,
        terminator: bytes | None = None,
        recv_until: bytes | None = None,
        recv_bytes: int | None = None,
        strict_terminator: bool = True,
        newline: bool = True,
        source: str = "fmt.read",
    ) -> FmtLeak:
        """执行一次 fmt 读取。

        参数语义：
        - 默认路径：自动构造 `%<offset>$s + terminator + packed_address`
        - `fmt=`：显式覆盖格式串，适合高级用户手工指定 `%7$p` / `%9$s` 等
        - `append_target=`：
          - `None`：根据 payload 自动判断是否需要在尾部追加地址
          - `True/False`：强制指定
        - `recv_until=`：覆盖默认捕获边界；若给定，优先于 terminator
        - `strict_terminator=`：
          - 仅当实际使用 terminator 作为边界时生效
          - 为 True 时，回包里缺失 terminator 会抛异常
        """
        if size <= 0:
            raise FmtReadError("fmt read size must be positive")

        pointer_size = self._pointer_size(session)
        endian = self._endian(session)
        plan = self._build_plan(
            target=target,
            offset=offset,
            pointer_size=pointer_size,
            endian=endian,
            fmt=fmt,
            append_target=append_target,
            terminator=terminator,
            recv_until=recv_until,
        )

        response, dispatch, metadata = dispatch_fmt_payload(
            session,
            plan.payload,
            receive=True,
            newline=newline,
            end=None,
            recv_bytes=recv_bytes or self.default_recv_bytes,
            recv_until=plan.recv_until,
        )
        if response is None:
            raise FmtReadError("fmt read did not receive any response bytes")
        if (
            strict_terminator
            and plan.recv_until == plan.terminator
            and plan.terminator
            and plan.terminator not in response
        ):
            raise FmtReadError("fmt read response missing terminator")

        body = self._extract_body(
            response,
            recv_until=plan.recv_until,
            terminator=plan.terminator,
        )
        try:
            decoded = self._decode(body, size=size, mode=mode, endian=endian)
        except Exception as exc:
            raise FmtReadError("fmt read failed to decode response body") from exc

        return FmtLeak(
            target=target,
            address=target.address,
            size=size,
            mode=mode,
            raw=body[:size] if mode != FmtReadMode.STRING else body,
            decoded=decoded,
            offset=offset,
            source=source,
            metadata={
                "payload": plan.payload,
                "primitive": plan.primitive,
                "append_target": plan.append_target,
                "terminator": plan.terminator,
                "recv_until": plan.recv_until,
                "dispatch": dispatch.value,
                "transport_kind": session.transport_spec.kind,
                "raw_response": response,
                "body": body,
                **metadata,
            },
        )

    def _build_plan(
        self,
        *,
        target: FmtTargetRef,
        offset: int,
        pointer_size: int,
        endian: str,
        fmt: bytes | str | None,
        append_target: bool | None,
        terminator: bytes | None,
        recv_until: bytes | None,
    ) -> _ReadPlan:
        """根据输入推导一次读取计划。

        默认策略：
        - 未显式给 `fmt` 时，走“内存字符串泄漏” primitive
        - 显式给 `fmt` 时，只负责最小拼装；是否追加地址由 `append_target` 决定
        """
        if fmt is None:
            format_bytes = f"%{offset}$s".encode()
            primitive = "memory_string"
            resolved_append_target = True if append_target is None else append_target
            resolved_terminator = (
                self.default_terminator if terminator is None else terminator
            )
        else:
            format_bytes = fmt.encode() if isinstance(fmt, str) else fmt
            primitive = "custom"
            # 对高级自定义格式串，不做过度猜测。
            # 只有在用户显式要求时，才在尾部追加地址。
            resolved_append_target = bool(append_target)
            resolved_terminator = b"" if terminator is None else terminator

        if b"\x00" in format_bytes:
            raise FmtReadError("fmt read format bytes must not contain NUL")

        payload = format_bytes
        if resolved_terminator:
            payload += resolved_terminator
        if resolved_append_target:
            # TODO(fmt): read() 仍沿用 legacy append-address 拼接，
            # 尚未像 write path 一样区分 fmt_offset/data_offset 并做槽位对齐。
            payload += target.address.to_bytes(
                pointer_size, byteorder=endian, signed=False
            )

        resolved_recv_until = (
            recv_until if recv_until is not None else resolved_terminator or None
        )
        return _ReadPlan(
            payload=payload,
            recv_until=resolved_recv_until,
            primitive=primitive,
            append_target=resolved_append_target,
            terminator=resolved_terminator,
        )

    @staticmethod
    def _extract_body(
        response: bytes,
        *,
        recv_until: bytes | None,
        terminator: bytes,
    ) -> bytes:
        """从完整回包里提取真正的 leak body。

        约定：
        - 如果用了 terminator，就优先按 terminator 截断
        - 如果只给了 recv_until，没有 terminator，则移除尾部边界本身
        - 都没有时，直接返回完整 response
        """
        if terminator:
            marker = response.find(terminator)
            if marker >= 0:
                return response[:marker]
        if recv_until and response.endswith(recv_until):
            return response[: -len(recv_until)]
        return response

    @staticmethod
    def _decode(
        raw: bytes,
        *,
        size: int,
        mode: FmtReadMode,
        endian: str,
    ) -> int | bytes | str | None:
        """按 mode 解码 leak body。

        这里显式兼容两类 POINTER 来源：
        - `%s` 读到的原始字节
        - `%p` / 自定义格式串返回的 ASCII 指针文本，例如 `0x41414141`
        """
        if mode == FmtReadMode.RAW:
            return raw[:size]
        if mode == FmtReadMode.STRING:
            return raw.decode("latin-1", errors="replace")
        if mode == FmtReadMode.POINTER:
            token = raw.strip()
            if token == b"(nil)" or token == b"":
                return None
            if token.startswith(b"0x"):
                return int(token, 16)
            body = token[:size]
            if not body:
                return None
            return int.from_bytes(body, byteorder=endian, signed=False)
        raise FmtReadError(f"unsupported fmt read mode: {mode}")

    @staticmethod
    def _pointer_size(session: "CHunSession") -> int:
        """统一解析当前 session 的指针宽度。"""
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
        """统一解析当前 session 的字节序。"""
        elf = getattr(session, "elf", None)
        if elf is not None and getattr(elf, "little_endian", None) is not None:
            return "little" if bool(getattr(elf, "little_endian", True)) else "big"
        entry = session.rec.get_context("arch.endian")
        if entry is not None:
            value = entry.value if hasattr(entry, "value") else entry
            return str(value)
        return "little"


__all__ = ["DefaultFmtReadExecutor"]
