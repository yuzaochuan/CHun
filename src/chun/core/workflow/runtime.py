"""workflow runtime 抽象与 process backend。"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Protocol
import re

from pwnlib.util.cyclic import cyclic
from pwnlib.util.packing import flat, p8, p16, p32, p64, u8, u16, u32, u64

from ..models import (
    AnalysisNode,
    CallNode,
    ContextKind,
    ExprNode,
    LiteralNode,
    NameRefNode,
    ObservationKind,
    OpaqueCallNode,
    RecordDomain,
    WorkflowCheckpoint,
    WorkflowPrimitive,
    WorkflowStepReceipt,
)
from ..session import CHunSession
from .launchers import ProcessLauncher, WorkflowLauncher


_HEX_POINTER_RE = re.compile(rb"0x[0-9a-fA-F]+")


class WorkflowScriptFacade:
    """在 workflow run 时提供接近 ScriptEntry 的脚本态接口。"""

    def __init__(self, session: CHunSession) -> None:
        self.session = session

    @property
    def io(self):
        return self.session.io

    @property
    def raw(self):
        return self.session.raw

    @property
    def rec(self):
        return self.session.rec

    @property
    def infer(self):
        return self.session.infer

    @property
    def resolve(self):
        return self.session.resolve

    @property
    def dbg(self):
        return self.session.dbg

    @property
    def crash(self):
        return self.session.crash

    @property
    def fmt(self):
        return self.session.fmt

    @property
    def elf(self):
        return self.session.elf

    @property
    def libc(self):
        return self.session.libc_elf

    @property
    def target(self):
        return self.session.target

    @property
    def libc_base(self) -> int:
        return self.session.libc_base

    @property
    def libc_version(self) -> str:
        return self.session.libc_version

    def send(self, data: bytes) -> None:
        self.io.send(data)

    def sendline(self, data: bytes) -> None:
        self.io.sendline(data)

    def sendafter(self, delim: bytes, data: bytes) -> None:
        delim = self._ensure_bytes(delim)
        if hasattr(self.io, "sendafter"):
            self.io.sendafter(delim, data)
            return
        self.io.recvuntil(delim)
        self.io.send(data)

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        delim = self._ensure_bytes(delim)
        if hasattr(self.io, "sendlineafter"):
            self.io.sendlineafter(delim, data)
            return
        self.io.recvuntil(delim)
        self.io.sendline(data)

    def recv(self, n: int = 4096) -> bytes:
        return self.io.recv(n)

    def recvuntil(self, delim: bytes | str, drop: bool = False) -> bytes:
        return self.io.recvuntil(self._ensure_bytes(delim), drop=drop)

    def recvline(self, keepends: bool = True) -> bytes:
        if not hasattr(self.io, "recvline"):
            raise RuntimeError("workflow facade io 不支持 recvline()。")
        return self.io.recvline(keepends=keepends)

    def recvregex(self, regex: bytes | str, capture: bool = False):
        if not hasattr(self.io, "recvregex"):
            raise RuntimeError("workflow facade io 不支持 recvregex()。")
        return self.io.recvregex(regex, capture=capture)

    def interactive(self) -> None:
        if not hasattr(self.io, "interactive"):
            raise RuntimeError("workflow facade io 不支持 interactive()。")
        self.io.interactive()

    def sl(self, data: bytes) -> None:
        self.sendline(data)

    def sa(self, delim: bytes, data: bytes) -> None:
        self.sendafter(delim, data)

    def sla(self, delim: bytes, data: bytes) -> None:
        self.sendlineafter(delim, data)

    def ru(self, delim: bytes, drop: bool = False) -> bytes:
        return self.recvuntil(delim, drop=drop)

    def rl(self, keepends: bool = True) -> bytes:
        return self.recvline(keepends=keepends)

    def ia(self) -> None:
        self.interactive()

    @staticmethod
    def _coerce_delim_or_regex(value: bytes | str, *, field_name: str) -> bytes | str:
        if isinstance(value, (bytes, str)):
            return value
        raise ValueError(f"{field_name} 必须是 bytes 或 str。")

    @staticmethod
    def _extract_regex_capture(match: object) -> bytes:
        if isinstance(match, bytes):
            return match
        if isinstance(match, str):
            return match.encode()
        if hasattr(match, "group"):
            groups = match.groups()  # type: ignore[attr-defined]
            group = groups[0] if groups else match.group(1)  # type: ignore[attr-defined]
            if isinstance(group, bytes):
                return group
            if isinstance(group, str):
                return group.encode()
            raise ValueError("regex capture 必须是 bytes 或 str。")
        if isinstance(match, (tuple, list)) and match:
            group = match[0]
            if isinstance(group, bytes):
                return group
            if isinstance(group, str):
                return group.encode()
        raise ValueError("recvregex(capture=True) 未返回可用的捕获组。")

    def recv_leak(
        self,
        name: str,
        delim: bytes | str | None = None,
        *,
        delim_end: bytes | str | None = None,
        regex: bytes | str | None = None,
        domain: RecordDomain | None = None,
        offset: int = 0,
        source: str = "leak",
        mode: str = "raw",
        index: int = 0,
        size: int | None = None,
        strip_newline: bool = True,
    ) -> int:
        if delim is not None and regex is not None:
            raise ValueError("delim 和 regex 不能同时提供。")
        if delim_end is not None and regex is not None:
            raise ValueError("delim_end 和 regex 不能同时提供。")
        if mode not in {"raw", "hex"}:
            raise ValueError("mode 必须是 'raw' 或 'hex'。")
        if mode == "raw" and delim_end is not None:
            raise ValueError("mode='raw' 时不支持 delim_end。")

        resolved_domain = domain or RecordDomain.LIBC
        if regex is not None:
            compiled = self._coerce_delim_or_regex(regex, field_name="regex")
            matched = self.recvregex(compiled, capture=True)
            payload = self._extract_regex_capture(matched)
        else:
            if delim is not None:
                resolved_delim = self._coerce_delim_or_regex(delim, field_name="delim")
                self.recvuntil(resolved_delim)
            if mode == "raw":
                bits = int(getattr(self.elf, "bits", 64)) if self.elf is not None else 64
                default_size = 4 if bits <= 32 else 6
                payload = self.recv(size or default_size)
                if strip_newline:
                    payload = payload.rstrip(b"\r\n")
            else:
                if delim_end is not None:
                    payload = self.recvuntil(
                        self._coerce_delim_or_regex(delim_end, field_name="delim_end"),
                        drop=True,
                    )
                else:
                    payload = self.recvline(keepends=not strip_newline)
                    if strip_newline:
                        payload = payload.strip()

        if mode == "raw":
            pointer_width = int(getattr(self.elf, "bytes", 8)) if self.elf is not None else 8
            leak_bytes = payload[:pointer_width]
            leak_val = int.from_bytes(
                leak_bytes.ljust(pointer_width, b"\x00"), "little"
            )
        else:
            matches = _HEX_POINTER_RE.findall(payload)
            if not matches:
                raise ValueError("未读取到可解析的十六进制泄漏。")
            if not (-len(matches) <= index < len(matches)):
                tokens = ",".join(token.decode() for token in matches)
                raise ValueError(
                    f"共匹配到 {len(matches)} 个地址：{tokens}，index={index} 越界。"
                )
            leak_val = int(matches[index], 16)

        actual_val = leak_val - offset
        self.rec.record_symbol_leak(
            name,
            actual_val,
            domain=resolved_domain,
            source=source,
        )
        return actual_val

    def __getattr__(self, name: str):
        if hasattr(self.session, name):
            return getattr(self.session, name)
        if hasattr(self.io, name):
            return getattr(self.io, name)
        raise AttributeError(name)

    @staticmethod
    def _ensure_bytes(value: bytes | str) -> bytes:
        if isinstance(value, bytes):
            return value
        return value.encode()


class WorkflowRuntime(Protocol):
    """最小 workflow runtime 接口。"""

    def start_session(
        self,
        *,
        launcher: WorkflowLauncher | None = None,
        primitive: WorkflowPrimitive | None = None,
    ) -> CHunSession: ...

    def execute_primitive(
        self,
        session: CHunSession,
        primitive: WorkflowPrimitive,
        *,
        step_index: int,
        env: dict[str, object],
    ) -> WorkflowStepReceipt: ...

    def checkpoint(
        self,
        session: CHunSession,
        checkpoint: WorkflowCheckpoint,
        *,
        step_index: int,
    ) -> WorkflowStepReceipt: ...

    def close_session(self, session: CHunSession) -> None: ...


class ProcessWorkflowRuntime:
    """第一版本地 process runtime。"""

    def start_session(
        self,
        *,
        launcher: WorkflowLauncher | None = None,
        primitive: WorkflowPrimitive | None = None,
    ) -> CHunSession:
        resolved_launcher = launcher
        if resolved_launcher is None:
            if primitive is None or primitive.kind != "session_init":
                raise RuntimeError("workflow runtime requires launcher or session_init primitive")
            binary = primitive.payload
            if not isinstance(binary, str) or not binary:
                raise RuntimeError("session_init primitive requires binary path payload")
            launcher_kwargs = primitive.metadata.get("launcher_kwargs", {})
            if not isinstance(launcher_kwargs, Mapping):
                raise RuntimeError("session_init launcher_kwargs must be a mapping")
            resolved_launcher = ProcessLauncher(
                binary=binary,
                argv=launcher_kwargs.get("argv"),
                libc=launcher_kwargs.get("libc"),
                ld=launcher_kwargs.get("ld"),
                env=launcher_kwargs.get("env"),
                cwd=launcher_kwargs.get("cwd"),
                log_level=str(launcher_kwargs.get("log_level", "info")),
                terminal=launcher_kwargs.get("terminal"),
            )
        return resolved_launcher.launch(primitive)

    def execute_primitive(
        self,
        session: CHunSession,
        primitive: WorkflowPrimitive,
        *,
        step_index: int,
        env: dict[str, object],
    ) -> WorkflowStepReceipt:
        if primitive.kind == "send":
            payload = self._coerce_bytes(
                self._evaluate_value(primitive.payload, session=session, env=env)
            )
            session.io.send(payload)
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                transport_kind=session.transport_spec.kind,
                metadata={"sent": payload, "dispatch": "send"},
            )
        if primitive.kind == "sendline":
            payload = self._coerce_bytes(
                self._evaluate_value(primitive.payload, session=session, env=env)
            )
            session.io.sendline(payload)
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                transport_kind=session.transport_spec.kind,
                metadata={"sent": payload, "dispatch": "sendline"},
            )
        if primitive.kind == "expect":
            delim = self._coerce_bytes(
                self._evaluate_value(primitive.payload, session=session, env=env)
            )
            response = session.io.recvuntil(delim)
            target = primitive.metadata.get("bind_target")
            if isinstance(target, str) and target:
                env[target] = response
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                response=response,
                transport_kind=session.transport_spec.kind,
                metadata={
                    "delimiter": delim,
                    "dispatch": "recvuntil",
                    **({"target": target} if isinstance(target, str) and target else {}),
                },
            )
        if primitive.kind == "recv":
            resolved_size = self._evaluate_value(primitive.payload, session=session, env=env)
            size = resolved_size if isinstance(resolved_size, int) else 4096
            response = session.io.recv(size)
            target = primitive.metadata.get("bind_target")
            if isinstance(target, str) and target:
                env[target] = response
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                response=response,
                transport_kind=session.transport_spec.kind,
                metadata={
                    "size": size,
                    "dispatch": "recv",
                    **({"target": target} if isinstance(target, str) and target else {}),
                },
            )
        if primitive.kind == "assign":
            target = primitive.metadata.get("target")
            if not isinstance(target, str) or not target:
                raise RuntimeError("assign primitive requires metadata.target")
            value = self._evaluate_value(primitive.payload, session=session, env=env)
            env[target] = value
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                transport_kind=session.transport_spec.kind,
                metadata={
                    "dispatch": "assign",
                    "target": target,
                    "value_type": type(value).__name__,
                },
            )
        if primitive.kind == "call":
            value = self._evaluate_value(primitive.payload, session=session, env=env)
            target = primitive.metadata.get("target")
            if isinstance(target, str) and target:
                env[target] = value
            return WorkflowStepReceipt(
                step_index=step_index,
                primitive=primitive,
                success=True,
                transport_kind=session.transport_spec.kind,
                metadata={
                    "dispatch": "call",
                    **({"target": target} if isinstance(target, str) and target else {}),
                    "value_type": type(value).__name__,
                },
            )
        raise RuntimeError(f"unsupported workflow primitive for process runtime: {primitive.kind}")

    def checkpoint(
        self,
        session: CHunSession,
        checkpoint: WorkflowCheckpoint,
        *,
        step_index: int,
    ) -> WorkflowStepReceipt:
        session.rec.set_context(
            "workflow.current_checkpoint",
            checkpoint.name,
            kind=ContextKind.SESSION,
            domain=RecordDomain.WORKFLOW,
            source="workflow.checkpoint",
            overwrite=True,
        )
        return WorkflowStepReceipt(
            step_index=step_index,
            primitive=WorkflowPrimitive(
                kind="checkpoint",
                checkpoint=checkpoint,
                source_action=checkpoint.source_action,
                source_node=checkpoint.source_node,
                metadata=checkpoint.metadata,
            ),
            success=True,
            transport_kind=session.transport_spec.kind,
            checkpoint=checkpoint,
            metadata={"checkpoint": checkpoint.name},
        )

    def close_session(self, session: CHunSession) -> None:
        session.close()

    @staticmethod
    def _coerce_bytes(value: object | None) -> bytes:
        if value is None:
            return b""
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        if isinstance(value, str):
            return value.encode()
        detail = ProcessWorkflowRuntime._describe_unresolved_payload(value)
        raise TypeError(f"workflow payload is not bytes-compatible: {detail}")

    @staticmethod
    def _describe_unresolved_payload(value: object) -> str:
        if isinstance(value, ExprNode):
            source_text = value.metadata.get("source_text")
            if isinstance(source_text, str) and source_text:
                return f"ExprNode({source_text})"
            return f"ExprNode({value.callee})"
        if isinstance(value, LiteralNode) and value.value_type == "expr_source":
            return f"LiteralNode(expr_source={value.value})"
        callee = getattr(value, "callee", None)
        if isinstance(callee, str) and callee:
            return f"{type(value).__name__}({callee})"
        return type(value).__name__

    def _evaluate_value(
        self,
        value: object | None,
        *,
        session: CHunSession,
        env: Mapping[str, object],
    ) -> object | None:
        if value is None:
            return None
        if isinstance(value, (bytes, bytearray, str, int, float, bool)):
            return value
        if isinstance(value, LiteralNode):
            if value.value_type == "expr_source":
                return self._evaluate_source(str(value.value), session=session, env=env)
            return value.value
        if isinstance(value, NameRefNode):
            if value.name in env:
                return env[value.name]
            raise NameError(f"workflow name is not bound at runtime: {value.name}")
        if isinstance(value, ExprNode):
            if value.evaluated:
                return value.resolved_value
            source_text = value.metadata.get("source_text")
            if isinstance(source_text, str) and source_text:
                return self._evaluate_source(source_text, session=session, env=env)
            raise TypeError(f"workflow expr has no runtime source: {value.callee}")
        if isinstance(value, (AnalysisNode, OpaqueCallNode, CallNode)):
            source_text = value.metadata.get("source_text")
            if isinstance(source_text, str) and source_text:
                return self._evaluate_source(source_text, session=session, env=env)
            raise TypeError(f"workflow call has no runtime source: {value.callee}")
        return value

    def _evaluate_source(
        self,
        source_text: str,
        *,
        session: CHunSession,
        env: Mapping[str, object],
    ) -> object:
        globals_dict = self._build_eval_globals()
        locals_dict = dict(env)
        if "session" not in locals_dict:
            locals_dict["session"] = session
        return eval(source_text, globals_dict, locals_dict)

    @staticmethod
    def _build_eval_globals() -> dict[str, object]:
        safe_builtins = MappingProxyType(
            {
                "bool": bool,
                "bytearray": bytearray,
                "bytes": bytes,
                "dict": dict,
                "hex": hex,
                "int": int,
                "len": len,
                "list": list,
                "max": max,
                "min": min,
                "range": range,
                "str": str,
                "tuple": tuple,
            }
        )
        return {
            "__builtins__": safe_builtins,
            "flat": flat,
            "cyclic": cyclic,
            "p8": p8,
            "p16": p16,
            "p32": p32,
            "p64": p64,
            "u8": u8,
            "u16": u16,
            "u32": u32,
            "u64": u64,
        }


__all__ = ["ProcessWorkflowRuntime", "WorkflowRuntime", "WorkflowScriptFacade"]
