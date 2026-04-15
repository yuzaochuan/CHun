from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from chun.core.catalog import LibcCatalogRepository, LibcCatalogService, build_libc_database, load_schema
from chun.core.errors import RegistryNotFoundError
from chun.core.models import LibcLeakConstraint


def test_libc_leak_constraint_exposes_low_bits() -> None:
    constraint = LibcLeakConstraint("puts", 0x7F123456789A)

    assert constraint.offset_12bit == 0x89A


def test_schema_can_initialize_symbols_table_with_generated_column() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        connection.executescript(load_schema())
        columns = {
            row[1]: row
            for row in connection.execute("PRAGMA table_xinfo(symbols)").fetchall()
        }

        assert "offset_12bit" in columns
        assert columns["offset_12bit"][6] == 3
        assert "score" in columns
    finally:
        connection.close()


def test_build_and_repository_queries_work_end_to_end(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    raw_payload = [
        {
            "name": "glibc-2.31-amd64",
            "arch": "x86_64",
            "build_id": "build-a",
            "source": "unit-test",
            "symbols": {
                "puts": "0x080aa0",
                "scanf": "0x021ab0",
                "mystery_symbol": "0x044444",
            },
        },
        {
            "name": "glibc-2.35-amd64",
            "arch": "amd64",
            "build_id": "build-b",
            "source": "unit-test",
            "symbols": {
                "gets": "0x080aa0",
                "strcpy": "0x021ab0",
            },
        },
        {
            "name": "glibc-2.31-i386",
            "arch": "i386",
            "build_id": "build-c",
            "source": "unit-test",
            "symbols": {
                "puts": "0x067890",
            },
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(raw_payload), encoding="utf-8")

    summary = build_libc_database(raw_dir=raw_dir, output_path=output_path)

    assert summary.output_path == output_path
    assert summary.libc_count == 3
    assert summary.symbol_count == 5

    repository_connection = sqlite3.connect(output_path)
    repository = LibcCatalogRepository(connection=repository_connection)
    try:
        strict_result = repository.find_candidates(
            {
                "puts": 0x7F0000000000 + 0x080AA0,
                "__isoc99_scanf": 0x7F0000000000 + 0x021AB0,
            },
            arch="amd64",
            require_all=True,
        )

        assert strict_result.query_mode == "strict"
        assert strict_result.exact_match is True
        assert [candidate.name for candidate in strict_result.candidates] == ["glibc-2.31-amd64"]
        assert strict_result.candidates[0].matched_symbols == ("puts", "__isoc99_scanf")
        assert strict_result.candidates[0].matched_count == 2
        assert strict_result.candidates[0].metadata["source"] == "unit-test"

        ranked_result = repository.find_candidates(
            {
                "puts": 0x7F0000000000 + 0x080AA0,
                "gets": 0x7F0000000000 + 0x080AA0,
                "strcpy": 0x7F0000000000 + 0x021AB0,
            },
            arch="amd64",
            require_all=False,
            min_match_count=1,
        )

        assert ranked_result.query_mode == "ranked"
        assert ranked_result.exact_match is False
        assert [candidate.name for candidate in ranked_result.candidates] == [
            "glibc-2.31-amd64",
            "glibc-2.35-amd64",
        ]
        assert ranked_result.candidates[0].matched_symbols == ("puts",)
        assert ranked_result.candidates[0].matched_count == 1
        assert ranked_result.candidates[0].metadata["total_score"] == 10.0
        assert ranked_result.candidates[1].matched_symbols == ("gets", "strcpy")
        assert ranked_result.candidates[1].matched_count == 2
        assert ranked_result.candidates[1].metadata["total_score"] == 2.0

        assert repository.get_symbol_offset(1, "puts") == 0x080AA0
        assert repository.get_symbol_offset(1, "system") is None

        libc = repository.get_libc_by_name("glibc-2.35-amd64")
        assert libc is not None
        assert libc.libc_id == 2
        assert libc.arch == "amd64"
        assert libc.build_id == "build-b"

        connection = sqlite3.connect(output_path)
        try:
            row = connection.execute(
                """
                SELECT offset_12bit, score
                FROM symbols
                WHERE libc_id = 1 AND symbol_name = '__isoc99_scanf'
                """
            ).fetchone()
            assert row is not None
            assert row[0] == 0xAB0
            assert row[1] == 10.0

            meta_rows = dict(connection.execute("SELECT key, value FROM dataset_meta").fetchall())
            assert meta_rows["script_version"] == "1"
            assert meta_rows["libc_count"] == "3"
            assert meta_rows["build_mode"] == "core-only"

            mystery = connection.execute(
                """
                SELECT 1
                FROM symbols
                WHERE libc_id = 1 AND symbol_name = 'mystery_symbol'
                """
            ).fetchone()
            assert mystery is None
        finally:
            connection.close()
    finally:
        repository.close()
        repository_connection.close()


def test_build_all_mode_keeps_unknown_symbols_with_low_score(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc-all.db"
    payload = [
        {
            "name": "glibc-all-amd64",
            "arch": "amd64",
            "symbols": {
                "puts": "0x080aa0",
                "mystery_symbol": "0x044444",
            },
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")

    summary = build_libc_database(
        raw_dir=raw_dir,
        output_path=output_path,
        include_all=True,
    )

    assert summary.symbol_count == 2

    connection = sqlite3.connect(output_path)
    try:
        rows = connection.execute(
            """
            SELECT symbol_name, score
            FROM symbols
            ORDER BY symbol_name
            """
        ).fetchall()
        assert rows == [
            ("mystery_symbol", 0.1),
            ("puts", 10.0),
        ]
        meta_rows = dict(connection.execute("SELECT key, value FROM dataset_meta").fetchall())
        assert meta_rows["build_mode"] == "all"
    finally:
        connection.close()


def test_catalog_service_normalizes_aliases_and_suffixes(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-service-amd64",
            "arch": "amd64",
            "symbols": {
                "puts": "0x080aa0",
                "scanf": "0x021ab0",
                "str_bin_sh": "0x044444",
            },
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path, include_all=True)

    service = LibcCatalogService(db_path=output_path)
    try:
        result = service.find_candidates(
            {
                "puts@got": 0x7F0000000000 + 0x080AA0,
                "scanf_plt": 0x7F0000000000 + 0x021AB0,
            },
            arch="amd64",
        )
        assert [candidate.name for candidate in result.candidates] == ["glibc-service-amd64"]

        assert service.get_offset(1, "puts@got") == 0x080AA0
        assert service.get_offset(1, "scanf_plt") == 0x021AB0
        assert service.get_offset(1, "str_bin_sh") == 0x044444

        try:
            service.get_offset(1, "system")
        except RegistryNotFoundError:
            pass
        else:
            raise AssertionError("expected RegistryNotFoundError")
    finally:
        service.close()
