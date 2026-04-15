"""Libc catalog 服务层。"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Mapping

from ..errors import RegistryNotFoundError
from ..models.catalog import LibcCandidate, LibcSearchResult
from .builder import load_symbol_policy
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
        self._symbol_policy = load_symbol_policy()

    def _normalize_name(self, raw_name: str) -> str:
        """对用户输入的 symbol 名称做动态归一化。"""
        stripped = re.split(r"[@_](got|plt|got\.plt)", raw_name, flags=re.IGNORECASE)[0]
        normalized = stripped.strip()
        return self._symbol_policy.alias_to_canonical.get(normalized, normalized)

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
        normalized_leaks = {
            self._normalize_name(symbol_name): leaked_value
            for symbol_name, leaked_value in leaks.items()
        }
        return self.repository.find_candidates(
            normalized_leaks,
            arch=arch,
            require_all=require_all,
            min_match_count=min_match_count,
            limit=limit,
        )

    def get_offset(self, libc_id: int, symbol_name: str) -> int:
        """查询指定 libc 的符号偏移。"""
        normalized_name = self._normalize_name(symbol_name)
        offset = self.repository.get_symbol_offset(libc_id, normalized_name)
        if offset is None:
            raise RegistryNotFoundError(f"catalog 中不存在符号：{normalized_name}")
        return offset

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
