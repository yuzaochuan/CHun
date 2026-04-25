"""JSON 文件缓存存储。"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any


class JsonCacheStore:
    """简单 JSON 磁盘缓存。"""

    def __init__(self, root: str | Path, *, enabled: bool = True) -> None:
        self.root = Path(root).expanduser()
        self.enabled = bool(enabled)
        if self.enabled:
            try:
                self.root.mkdir(parents=True, exist_ok=True)
            except Exception:
                fallback = Path("/tmp/chun-cache")
                try:
                    fallback.mkdir(parents=True, exist_ok=True)
                    self.root = fallback
                except Exception:
                    self.enabled = False

    def get(self, namespace: str, key: str) -> Any | None:
        if not self.enabled:
            return None
        path = self._path(namespace, key)
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None

    def set(self, namespace: str, key: str, value: Any) -> None:
        if not self.enabled:
            return
        path = self._path(namespace, key)
        path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = path.with_suffix(path.suffix + ".tmp")
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True)
        temp_path.write_text(payload, encoding="utf-8")
        temp_path.replace(path)

    def clear(self, namespace: str | None = None) -> None:
        if not self.enabled:
            return
        if namespace is None:
            shutil.rmtree(self.root, ignore_errors=True)
            self.root.mkdir(parents=True, exist_ok=True)
            return
        target = self.root / namespace
        shutil.rmtree(target, ignore_errors=True)

    def _path(self, namespace: str, key: str) -> Path:
        safe_key = key.replace("/", "_")
        return self.root / namespace / f"{safe_key}.json"


__all__ = ["JsonCacheStore"]
