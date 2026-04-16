"""Libc catalog repository。"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Mapping

from ..models.catalog import LibcCandidate, LibcLeakConstraint, LibcSearchResult


DEFAULT_DB_PATH = Path(__file__).resolve().parents[4] / "data" / "libc" / "libc.db"


class LibcCatalogRepository:
    """封装 libc catalog 的 SQLite 查询逻辑。"""

    def __init__(
        self,
        db_path: str | Path | None = None,
        *,
        connection: sqlite3.Connection | None = None,
    ) -> None:
        self._owns_connection = connection is None
        if connection is None:
            resolved_path = Path(db_path) if db_path is not None else DEFAULT_DB_PATH
            uri = f"file:{resolved_path.resolve()}?mode=ro"
            connection = sqlite3.connect(uri, uri=True)
        connection.row_factory = sqlite3.Row
        self._connection = connection

    def close(self) -> None:
        """关闭 repository 自己创建的连接。"""
        if self._owns_connection:
            self._connection.close()

    def __enter__(self) -> "LibcCatalogRepository":
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.close()

    def find_candidates(
        self,
        leaks: Mapping[str, int],
        *,
        arch: str | None = None,
        require_all: bool = True,
        min_match_count: int | None = None,
        limit: int = 50,
    ) -> LibcSearchResult:
        """按泄漏约束检索 libc 候选。"""
        constraints = tuple(
            LibcLeakConstraint(symbol_name=symbol_name, leaked_value=leaked_value)
            for symbol_name, leaked_value in leaks.items()
        )
        query_mode = "strict" if require_all else "ranked"
        if not constraints:
            return LibcSearchResult(
                constraints=constraints,
                candidates=[],
                exact_match=False,
                query_mode=query_mode,
            )

        values_sql = ", ".join("(?, ?, ?)" for _ in constraints)
        query_params: list[object] = []
        symbol_order = {constraint.symbol_name: index for index, constraint in enumerate(constraints)}

        for index, constraint in enumerate(constraints):
            query_params.extend((index, constraint.symbol_name, constraint.offset_12bit))

        having_sql = "COUNT(*) = (SELECT COUNT(*) FROM leak)"
        if not require_all:
            having_sql = "COUNT(*) >= ?"

        order_by_sql = "v.name"
        if not require_all:
            order_by_sql = "total_score DESC, matched_count DESC, v.name"

        sql = f"""
        WITH leak(position, symbol_name, offset_12bit) AS (
            VALUES {values_sql}
        )
        SELECT
            v.id,
            v.name,
            v.arch,
            v.build_id,
            v.sha256,
            v.source,
            v.source_ref,
            COUNT(*) AS matched_count,
            SUM(s.score) AS total_score,
            GROUP_CONCAT(l.symbol_name, '|') AS matched_symbols
        FROM leak l
        JOIN symbols s
          ON s.symbol_name = l.symbol_name
         AND s.offset_12bit = l.offset_12bit
        JOIN libc_versions v
          ON v.id = s.libc_id
        WHERE (? IS NULL OR v.arch = ?)
        GROUP BY v.id, v.name, v.arch, v.build_id, v.sha256, v.source, v.source_ref
        HAVING {having_sql}
        ORDER BY {order_by_sql}
        LIMIT ?
        """

        query_params.extend((arch, arch))
        if not require_all:
            query_params.append(max(1, min_match_count or 1))
        query_params.append(limit)

        rows = self._connection.execute(sql, query_params).fetchall()
        candidates = [
            self._row_to_candidate(row, symbol_order=symbol_order)
            for row in rows
        ]
        exact_match = any(candidate.matched_count == len(constraints) for candidate in candidates)
        return LibcSearchResult(
            constraints=constraints,
            candidates=candidates,
            exact_match=exact_match,
            query_mode=query_mode,
        )

    def get_symbol_offset(self, libc_id: int, symbol_name: str) -> int | None:
        """查询指定 libc 的符号偏移。"""
        row = self._connection.execute(
            """
            SELECT offset
            FROM symbols
            WHERE libc_id = ? AND symbol_name = ?
            """,
            (libc_id, symbol_name),
        ).fetchone()
        if row is None:
            return None
        return int(row["offset"])

    def get_libc_by_name(self, name: str) -> LibcCandidate | None:
        """按 libc 名称查询版本元信息。"""
        row = self._connection.execute(
            """
            SELECT
                id,
                name,
                arch,
                build_id,
                sha256,
                source,
                source_ref
            FROM libc_versions
            WHERE name = ?
            """,
            (name,),
        ).fetchone()
        if row is None:
            return None
        return self._row_to_candidate(row, symbol_order={})

    @staticmethod
    def _row_to_candidate(
        row: sqlite3.Row,
        *,
        symbol_order: dict[str, int],
    ) -> LibcCandidate:
        raw_symbols = row["matched_symbols"] if "matched_symbols" in row.keys() else None
        matched_symbols = (
            tuple(
                sorted(
                    (part for part in str(raw_symbols).split("|") if part),
                    key=lambda symbol_name: symbol_order.get(symbol_name, len(symbol_order)),
                )
            )
            if raw_symbols
            else ()
        )
        metadata = {
            key: value
            for key in ("sha256", "source", "source_ref", "total_score")
            if key in row.keys() and (value := row[key]) is not None
        }
        return LibcCandidate(
            libc_id=int(row["id"]),
            name=str(row["name"]),
            arch=str(row["arch"]),
            build_id=row["build_id"],
            matched_symbols=matched_symbols,
            matched_count=int(row["matched_count"]) if "matched_count" in row.keys() else 0,
            metadata=metadata,
        )


__all__ = ["LibcCatalogRepository"]
