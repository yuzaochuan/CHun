"""Compact replay trace 执行器。"""

from __future__ import annotations

import time
import uuid
from typing import Callable, Protocol

from ..._compat import context
from .models import ReplayEvent, ReplayEventKind, VerificationResult
from .store import ReplayBlobStore


class ReplaySessionLike(Protocol):
    io: object

    def close(self) -> None: ...


class ReplayExecutor:
    """按事件序列重放并执行注入验证。"""

    def __init__(self, blob_store: ReplayBlobStore) -> None:
        self._blob_store = blob_store

    def replay(
        self,
        events: tuple[ReplayEvent, ...],
        *,
        session_factory: Callable[[], ReplaySessionLike],
        probe: bytes,
        predicate: Callable[[bytes], bool],
        probe_dispatch: str = "sendline",
        recv_bytes: int = 4096,
    ) -> VerificationResult:
        run_id = str(uuid.uuid4())
        previous_log_level = getattr(context, "log_level", None)
        session = session_factory()
        io_obj = session.io
        try:
            for event in events:
                if event.kind == ReplayEventKind.SEND and event.payload is not None:
                    io_obj.send(self._blob_store.get(event.payload))
                    continue
                if event.kind == ReplayEventKind.SENDLINE and event.payload is not None:
                    io_obj.sendline(self._blob_store.get(event.payload))
                    continue
                if event.kind == ReplayEventKind.EXPECT and event.payload is not None:
                    io_obj.recvuntil(self._blob_store.get(event.payload), drop=event.drop)
                    continue

            if probe_dispatch == "send":
                io_obj.send(probe)
            else:
                io_obj.sendline(probe)
            response = io_obj.recv(recv_bytes)
            ok = bool(predicate(response))
            return VerificationResult(
                run_id=run_id,
                ok=ok,
                reason="predicate_pass" if ok else "predicate_fail",
                output_preview=response[:256],
                completed_ns=time.time_ns(),
            )
        finally:
            try:
                session.close()
            finally:
                if previous_log_level is not None:
                    context.log_level = previous_log_level


__all__ = ["ReplayExecutor", "ReplaySessionLike"]
