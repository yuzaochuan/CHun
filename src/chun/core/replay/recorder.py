"""Replay trace 记录器。"""

from __future__ import annotations

import hashlib
import time
from typing import Iterable, Mapping

from .models import PayloadRef, ReplayCheckpoint, ReplayEvent, ReplayEventKind
from .store import InMemoryBlobStore, ReplayBlobStore


class ReplayRecorder:
    """只记录可重放的最小外部动作。"""

    def __init__(self, *, blob_store: ReplayBlobStore | None = None) -> None:
        self.blob_store: ReplayBlobStore = blob_store if blob_store is not None else InMemoryBlobStore()
        self.events: list[ReplayEvent] = []
        self.checkpoints: dict[str, ReplayCheckpoint] = {}

    @property
    def cursor_seq(self) -> int:
        return len(self.events)

    def append_event(
        self,
        kind: ReplayEventKind | str,
        *,
        payload: bytes | None = None,
        drop: bool = False,
        metadata: Mapping[str, object] | None = None,
    ) -> ReplayEvent:
        ref: PayloadRef | None = None
        if payload is not None:
            ref = self.blob_store.put(payload)
        event = ReplayEvent(
            seq=self.cursor_seq,
            ts_ns=time.time_ns(),
            kind=ReplayEventKind(kind),
            payload=ref,
            drop=drop,
            metadata=metadata or {},
        )
        self.events.append(event)
        return event

    def checkpoint(
        self,
        name: str,
        *,
        metadata: Mapping[str, object] | None = None,
    ) -> ReplayCheckpoint:
        digest = hashlib.sha256(
            ",".join(f"{event.seq}:{event.kind.value}" for event in self.events).encode()
        ).hexdigest()
        checkpoint = ReplayCheckpoint(
            name=name,
            event_seq=self.cursor_seq,
            trace_digest=digest,
            metadata=metadata or {},
        )
        self.checkpoints[name] = checkpoint
        self.append_event(
            ReplayEventKind.CHECKPOINT,
            metadata={"name": name, **dict(metadata or {})},
        )
        return checkpoint

    def slice_to_here(self, *, from_checkpoint: str | None = None) -> tuple[ReplayEvent, ...]:
        if from_checkpoint is None:
            start = 0
        else:
            checkpoint = self.checkpoints.get(from_checkpoint)
            if checkpoint is None:
                raise KeyError(f"replay checkpoint 不存在：{from_checkpoint}")
            start = checkpoint.event_seq
        return tuple(self.events[start:])

    def replay_from_checkpoint(self, checkpoint_name: str) -> tuple[ReplayEvent, ...]:
        return self.slice_to_here(from_checkpoint=checkpoint_name)

    def iter_events(self) -> Iterable[ReplayEvent]:
        return tuple(self.events)


__all__ = ["ReplayRecorder"]
