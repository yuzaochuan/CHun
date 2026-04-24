"""Replay payload 的轻量 blob 存储。"""

from __future__ import annotations

import hashlib
from typing import Protocol

from .models import PayloadRef


class ReplayBlobStore(Protocol):
    def put(self, data: bytes) -> PayloadRef: ...
    def get(self, ref: PayloadRef) -> bytes: ...


class InMemoryBlobStore:
    """默认内存实现：按 sha256 去重。"""

    def __init__(self) -> None:
        self._by_id: dict[str, bytes] = {}

    def put(self, data: bytes) -> PayloadRef:
        payload = bytes(data)
        digest = hashlib.sha256(payload).hexdigest()
        blob_id = digest[:16]
        self._by_id.setdefault(blob_id, payload)
        return PayloadRef(blob_id=blob_id, sha256=digest, size=len(payload))

    def get(self, ref: PayloadRef) -> bytes:
        return self._by_id[ref.blob_id]


__all__ = ["InMemoryBlobStore", "ReplayBlobStore"]
