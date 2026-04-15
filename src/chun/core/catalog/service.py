"""Libc catalog 服务层。"""

from __future__ import annotations

from pathlib import Path
from typing import Mapping

from ..models.catalog import LibcCandidate, LibcSearchResult
from .repository import LibcCatalogRepository


class LibcCatalogService:
    """对 inference 暴露的 libc catalog 查询服务。"""

    def __init__(
        self,
        repository: LibcCatalogRepository | None = None,
        *,
        db_path: str | Path | None = None,
    ) -> None:
        self.repository = repository or LibcCatalogRepository(db_path=db_path)

    def find_candidates(
        self,
        leaks: Mapping[str, int],
        *,
        arch: str | None = None,
        require_all: bool = True,
        min_match_count: int | None = None,
        limit: int = 50,
    ) -> LibcSearchResult:
        """查询 libc 候选。"""
        return self.repository.find_candidates(
            leaks,
            arch=arch,
            require_all=require_all,
            min_match_count=min_match_count,
            limit=limit,
        )

    def get_symbol_offset(self, libc_id: int, symbol_name: str) -> int | None:
        """查询指定 libc 的符号偏移。"""
        return self.repository.get_symbol_offset(libc_id, symbol_name)

    def get_libc_by_name(self, name: str) -> LibcCandidate | None:
        """按名称查询 libc。"""
        return self.repository.get_libc_by_name(name)

    def close(self) -> None:
        """关闭底层 repository。"""
        self.repository.close()

    def __enter__(self) -> "LibcCatalogService":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()


__all__ = ["LibcCatalogService"]
