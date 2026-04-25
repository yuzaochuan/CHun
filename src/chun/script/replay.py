"""脚本态 replay 语法糖。"""

from __future__ import annotations

import sys
import time
import uuid
from typing import TYPE_CHECKING, Any, Callable, Literal, Mapping, Sequence

from ..bridges.gdb import PwntoolsGdbBridge
from ..core.analysis import CorefileAnalyzer
from ..core.inference import InferenceService
from ..core.registry import EvidenceRegistry
from ..core.replay import ReplayEvent, ReplayEventKind, ReplayExecutor, VerificationResult
from ..core.resolve import ResolveService
from .fmt import _ScriptFmtFacade

if TYPE_CHECKING:
    from ..core.session import CHunSession


def _script_module() -> Any:
    return sys.modules[__package__]


class _ReplayScriptProxy:
    """在 replay 子会话里复用脚本态调用习惯的轻量代理。"""

    def __init__(self, session: "CHunSession") -> None:
        self._session = session

    @property
    def session(self) -> "CHunSession":
        return self._session

    @property
    def io(self) -> Any:
        return self._session.io

    @property
    def rec(self) -> EvidenceRegistry:
        return self._session.rec

    @property
    def infer(self) -> InferenceService:
        return self._session.infer

    @property
    def resolve(self) -> ResolveService:
        return self._session.resolve

    @property
    def dbg(self) -> PwntoolsGdbBridge:
        return self._session.dbg

    @property
    def crash(self) -> CorefileAnalyzer:
        return self._session.crash

    @property
    def fmt(self) -> _ScriptFmtFacade:
        return _ScriptFmtFacade(self._session.fmt)

    @property
    def elf(self) -> Any:
        return self._session.elf

    @property
    def libc(self) -> Any:
        return self._session.libc_elf

    def checkpoint(self, name: str, *, metadata: dict[str, object] | None = None) -> object:
        return self._session.checkpoint(name, metadata=metadata or {})

    def send(self, data: bytes) -> None:
        self.io.send(data)

    def sendline(self, data: bytes) -> None:
        self.io.sendline(data)

    def sendafter(self, delim: bytes, data: bytes) -> None:
        self.io.sendafter(delim, data)

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        self.io.sendlineafter(delim, data)

    def recv(self, n: int = 4096) -> bytes:
        return self.io.recv(n)

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        return self.io.recvuntil(delim, drop=drop)

    def recvline(self, keepends: bool = True) -> bytes:
        return self.io.recvline(keepends=keepends)

    def interactive(self) -> None:
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

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.io, name)


class ReplayScriptMixin:
    """为 ScriptEntry 提供 replay 能力。"""

    @property
    def rec(self) -> EvidenceRegistry:
        raise NotImplementedError

    @property
    def session(self) -> "CHunSession":
        raise NotImplementedError

    def replay(
        self,
        payload_or_action: bytes | Callable[..., object],
        *action_args: object,
        checkpoint: str | None = None,
        action_kwargs: Mapping[str, object] | None = None,
        expected: bytes | None = None,
        show_recv: bool = False,
        recv_bytes: int = 4096,
        probe_dispatch: Literal["send", "sendline"] = "sendline",
        capture_replay_registry: bool = False,
        replay_registry_layers: Sequence[str] | str = (
            "context",
            "observations",
            "facts",
            "artifacts",
        ),
        replay_registry_detail: Literal["compact", "standard", "verbose"] = "standard",
        replay_registry_limit: int | None = None,
    ) -> object:
        """脚本态 replay 语法糖：默认按“当前位置前缀”回放，再注入 payload 或执行 action。"""
        _ = probe_dispatch
        if checkpoint is None:
            end_seq_exclusive = self.rec.replay.cursor_seq
        else:
            checkpoint_entry = self.rec.replay.checkpoints.get(checkpoint)
            if checkpoint_entry is None:
                raise KeyError(f"replay checkpoint 不存在：{checkpoint}")
            end_seq_exclusive = checkpoint_entry.event_seq

        def _predicate(output: bytes) -> bool:
            if show_recv:
                self._log_replay_recv(output)
            if expected is None:
                return True
            return expected in output

        if isinstance(payload_or_action, (bytes, bytearray, memoryview)):
            if action_args:
                raise ValueError("payload 模式不接受额外位置参数。")
            executor = ReplayExecutor(self.rec.replay.blob_store)
            result = self.rec.run_replay(
                session_factory=self.session.make_replay_session,
                executor=executor,
                probe=bytes(payload_or_action),
                predicate=_predicate,
                end_seq_exclusive=end_seq_exclusive,
                capture_replay_registry=capture_replay_registry,
                replay_registry_layers=replay_registry_layers,
                replay_registry_detail=replay_registry_detail,
                replay_registry_limit=replay_registry_limit,
            )
            return result

        if not callable(payload_or_action):
            raise TypeError("replay 第一个参数必须是 bytes 或可调用对象。")

        action = payload_or_action
        action_call_kwargs = dict(action_kwargs or {})
        trace = tuple(
            event
            for event in self.rec.slice_to_here()
            if event.seq < end_seq_exclusive
        )
        result = self._run_replay_action(
            trace=trace,
            action=action,
            action_args=action_args,
            action_kwargs=action_call_kwargs,
            predicate=_predicate,
            recv_bytes=recv_bytes,
            capture_replay_registry=capture_replay_registry,
            replay_registry_layers=replay_registry_layers,
            replay_registry_detail=replay_registry_detail,
            replay_registry_limit=replay_registry_limit,
        )
        return result

    def _run_replay_action(
        self,
        *,
        trace: Sequence[ReplayEvent],
        action: Callable[..., object],
        action_args: Sequence[object],
        action_kwargs: Mapping[str, object],
        predicate: Callable[[bytes], bool],
        recv_bytes: int,
        capture_replay_registry: bool,
        replay_registry_layers: Sequence[str] | str,
        replay_registry_detail: Literal["compact", "standard", "verbose"],
        replay_registry_limit: int | None,
    ) -> VerificationResult:
        context = _script_module().context
        previous_log_level = getattr(context, "log_level", None)
        replay_session = self.session.make_replay_session()
        run_id = str(uuid.uuid4())
        metadata: dict[str, object] = {}
        globals_dict = getattr(action, "__globals__", None)
        old_global_s: object | None = None
        had_global_s = False
        proxy = _ReplayScriptProxy(replay_session)
        try:
            self._replay_trace_events(trace, replay_session)
            if isinstance(globals_dict, dict):
                if "s" in globals_dict:
                    had_global_s = True
                    old_global_s = globals_dict["s"]
                globals_dict["s"] = proxy
            action(*action_args, **dict(action_kwargs))
            output = b""
            if recv_bytes > 0:
                output = replay_session.io.recv(recv_bytes)
            ok = bool(predicate(output))
            if capture_replay_registry:
                registry = getattr(replay_session, "rec", None)
                if registry is None:
                    metadata["replay_registry_capture_error"] = "session.rec 不存在"
                else:
                    try:
                        lines = registry.render(  # type: ignore[attr-defined]
                            layers=replay_registry_layers,
                            detail=replay_registry_detail,
                            limit=replay_registry_limit,
                        )
                    except Exception as exc:  # pragma: no cover - 防御性分支
                        metadata["replay_registry_capture_error"] = str(exc)
                    else:
                        metadata["replay_registry_lines"] = tuple(lines)
            return VerificationResult(
                run_id=run_id,
                ok=ok,
                reason="predicate_pass" if ok else "predicate_fail",
                output_preview=output[:256],
                completed_ns=time.time_ns(),
                metadata=metadata,
            )
        finally:
            if isinstance(globals_dict, dict):
                if had_global_s:
                    globals_dict["s"] = old_global_s
                else:
                    globals_dict.pop("s", None)
            try:
                replay_session.close()
            finally:
                if previous_log_level is not None:
                    context.log_level = previous_log_level

    def _replay_trace_events(
        self,
        trace: Sequence[ReplayEvent],
        replay_session: "CHunSession",
    ) -> None:
        io_obj = replay_session.io
        blob_store = self.rec.replay.blob_store
        for event in trace:
            if event.kind == ReplayEventKind.SEND and event.payload is not None:
                io_obj.send(blob_store.get(event.payload))
                continue
            if event.kind == ReplayEventKind.SENDLINE and event.payload is not None:
                io_obj.sendline(blob_store.get(event.payload))
                continue
            if event.kind == ReplayEventKind.EXPECT and event.payload is not None:
                io_obj.recvuntil(blob_store.get(event.payload), drop=event.drop)

    @staticmethod
    def _log_replay_recv(output: bytes) -> None:
        script_mod = _script_module()
        context = script_mod.context
        log = script_mod.log
        previous_log_level = getattr(context, "log_level", None)
        try:
            context.log_level = "info"
            log.info(f"[replay recv] len={len(output)}")
            if not output:
                log.info("<empty>")
            else:
                try:
                    from pwnlib.util.fiddling import hexdump as _hexdump

                    log.info(_hexdump(output))
                except Exception:
                    log.info(output.hex())
        finally:
            if previous_log_level is not None:
                context.log_level = previous_log_level
