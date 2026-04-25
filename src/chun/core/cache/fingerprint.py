"""cache key / 文件指纹工具。"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

CACHE_SCHEMA_VERSION = 3


def default_cache_dir() -> Path:
    """解析默认缓存目录。"""
    explicit = os.getenv("CHUN_CACHE_DIR")
    if explicit:
        return Path(explicit).expanduser()

    xdg_home = os.getenv("XDG_CACHE_HOME")
    if xdg_home:
        return Path(xdg_home).expanduser() / "chun"
    return Path("~/.cache/chun").expanduser()


def file_sha256(path: str | Path) -> str:
    """基于文件内容计算 sha256。"""
    digest = hashlib.sha256()
    file_path = Path(path).expanduser()
    try:
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except FileNotFoundError:
        # 测试替身或尚未落盘场景：退化为稳定路径指纹，避免流程崩溃。
        digest.update(f"missing:{file_path}".encode("utf-8"))
        return digest.hexdigest()


def file_cache_key(
    path: str | Path,
    *,
    namespace: str,
    schema: int = CACHE_SCHEMA_VERSION,
    extra: str = "",
) -> str:
    """生成 cache key。"""
    sha = file_sha256(path)
    suffix = f"-{extra}" if extra else ""
    return f"{sha}-{namespace}-schema{schema}{suffix}"


__all__ = [
    "CACHE_SCHEMA_VERSION",
    "default_cache_dir",
    "file_cache_key",
    "file_sha256",
]
