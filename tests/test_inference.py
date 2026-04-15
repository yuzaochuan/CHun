from __future__ import annotations

import json
from pathlib import Path

from chun.core.catalog import LibcCatalogService, build_libc_database
from chun.core.errors import InferenceInputError, ResolverError
from chun.core.inference import InferenceService
from chun.core.resolve import ResolveService
from chun.core.models import ArtifactKind, ObservationKind, FactKind, RecordDomain
from chun.core.registry import EvidenceRegistry


def test_libc_base_inference_creates_fact_from_symbol_leak_observation() -> None:
    registry = EvidenceRegistry()
    expected_base = 0x7F1234500000
    puts_offset = 0x080000
    registry.record_symbol_leak(
        "puts",
        expected_base + puts_offset,
        domain=RecordDomain.LIBC,
        source="got",
        confidence=0.85,
    )

    infer = InferenceService(registry)
    result = infer.libc_base_from_symbol_leak("puts", symbol_offset=puts_offset)

    fact = registry.get_fact("libc.base")
    assert fact is not None
    assert fact.kind == FactKind.BASE_ADDRESS
    assert fact.domain == RecordDomain.LIBC
    assert fact.value == expected_base
    assert fact.metadata["symbol_offset"] == puts_offset
    assert result.raw_base == expected_base
    assert result.aligned_base == expected_base


def test_libc_candidates_from_leaks_requires_catalog_dependency() -> None:
    registry = EvidenceRegistry()
    infer = InferenceService(registry)

    try:
        infer.libc_candidates_from_leaks({"puts": 0x7F0000000000 + 0x080AA0})
    except InferenceInputError:
        pass
    else:
        raise AssertionError("expected InferenceInputError")


def test_libc_candidates_from_leaks_writes_artifact_and_fact_for_unique_match(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-2.31-amd64",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {
                "puts": "0x080aa0",
                "scanf": "0x021ab0",
            },
        },
        {
            "name": "glibc-2.35-amd64",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {
                "puts": "0x080aa0",
            },
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)

    result = infer.libc_candidates_from_leaks(
        {
            "puts": 0x7F0000000000 + 0x080AA0,
            "__isoc99_scanf": 0x7F0000000000 + 0x021AB0,
        }
    )

    assert len(result.candidates) == 1

    artifact = registry.get_artifact("libc.candidates")
    assert artifact is not None
    assert artifact.kind == ArtifactKind.CATALOG_RESULT
    assert artifact.domain == RecordDomain.LIBC
    assert artifact.source == "sqlite-catalog"
    assert artifact.value is result
    assert artifact.metadata["candidate_count"] == 1
    assert artifact.metadata["query_mode"] == "strict"

    fact = registry.get_fact("libc.version")
    assert fact is not None
    assert fact.kind == FactKind.VERSION
    assert fact.domain == RecordDomain.LIBC
    assert fact.source == "sqlite-catalog"
    assert fact.value == "glibc-2.31-amd64"
    assert fact.evidence == ["puts", "__isoc99_scanf"]
    assert fact.metadata["libc_id"] == 1
    assert fact.metadata["build_id"] == "build-a"
    assert fact.metadata["arch"] == "amd64"

    base_fact = registry.get_fact("libc.base")
    assert base_fact is not None
    assert base_fact.kind == FactKind.BASE_ADDRESS
    assert base_fact.value == 0x7F0000000000
    assert base_fact.metadata["libc_id"] == 1
    assert base_fact.metadata["symbol"] == "puts"

    service.close()


def test_search_libc_scans_registry_and_prefers_higher_confidence_symbol_leaks(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-2.31-amd64",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {
                "puts": "0x080aa0",
                "scanf": "0x021ab0",
            },
        },
        {
            "name": "glibc-2.35-amd64",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {
                "puts": "0x090aa0",
                "scanf": "0x031bb0",
            },
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path, include_all=True)

    registry = EvidenceRegistry()
    registry.record_symbol_leak(
        "puts",
        0x7F0000000000 + 0x090AA0,
        domain=RecordDomain.LIBC,
        confidence=0.20,
        source="got-low",
    )
    registry.record_symbol_leak(
        "puts",
        0x7F0000000000 + 0x080AA0,
        domain=RecordDomain.LIBC,
        confidence=0.95,
        source="got-high",
    )
    registry.record_observation(
        "scanf.bad",
        "not-an-int",
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        metadata={"symbol": "__isoc99_scanf"},
        source="bad",
    )
    registry.record_observation(
        "scanf.good",
        0x7F0000000000 + 0x021AB0,
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        metadata={"symbol": "__isoc99_scanf"},
        confidence=0.80,
        source="good",
    )
    registry.record_symbol_leak(
        "main",
        0x555555554000,
        domain=RecordDomain.ELF,
        source="elf",
    )

    service = LibcCatalogService(db_path=output_path)
    infer = InferenceService(registry, libc_catalog=service)
    result = infer.search_libc()

    assert [candidate.name for candidate in result.candidates] == ["glibc-2.31-amd64"]

    artifact = registry.get_artifact("libc.candidates")
    assert artifact is not None
    assert artifact.metadata["candidate_count"] == 1

    fact = registry.get_fact("libc.version")
    assert fact is not None
    assert fact.value == "glibc-2.31-amd64"
    assert fact.evidence == ["puts", "__isoc99_scanf"]

    base_fact = registry.get_fact("libc.base")
    assert base_fact is not None
    assert base_fact.value == 0x7F0000000000

    service.close()


def test_search_libc_raises_when_no_usable_libc_symbol_leak_exists() -> None:
    registry = EvidenceRegistry()
    registry.record_observation(
        "puts",
        "not-an-int",
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        source="bad",
    )
    registry.record_symbol_leak(
        "main",
        0x555555554000,
        domain=RecordDomain.ELF,
        source="elf",
    )

    infer = InferenceService(registry)
    try:
        infer.search_libc()
    except InferenceInputError:
        pass
    else:
        raise AssertionError("expected InferenceInputError")


def test_libc_candidates_from_leaks_can_confirm_candidate_by_index_and_auto_record_base(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-b",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {"puts": "0x080aa0"},
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    result = infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
        index=1,
    )

    assert len(result.candidates) == 2

    fact = registry.get_fact("libc.version")
    assert fact is not None
    assert fact.source == "sqlite-catalog"
    assert fact.value == "glibc-b"
    assert fact.metadata["libc_id"] == 2
    assert fact.metadata["build_id"] == "build-b"

    base_fact = registry.get_fact("libc.base")
    assert base_fact is not None
    assert base_fact.value == 0x7F0000000000
    assert base_fact.metadata["libc_id"] == 2

    service.close()


def test_libc_candidates_from_leaks_raises_when_index_is_out_of_range(
    tmp_path: Path,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    try:
        infer.libc_candidates_from_leaks(
            {"puts": 0x7F0000000000 + 0x080AA0},
            index=99,
        )
    except InferenceInputError:
        pass
    else:
        raise AssertionError("expected InferenceInputError")
    finally:
        service.close()


def test_libc_candidates_from_leaks_prints_candidates_when_multiple_and_unconfirmed(
    tmp_path: Path,
    capsys,
) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-a",
            "arch": "amd64",
            "build_id": "build-a",
            "symbols": {"puts": "0x080aa0"},
        },
        {
            "name": "glibc-b",
            "arch": "amd64",
            "build_id": "build-b",
            "symbols": {"puts": "0x080aa0"},
        },
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    infer = InferenceService(registry, libc_catalog=service)
    result = infer.libc_candidates_from_leaks(
        {"puts": 0x7F0000000000 + 0x080AA0},
        require_all=False,
    )

    captured = capsys.readouterr()
    assert len(result.candidates) == 2
    assert registry.get_fact("libc.version") is None
    assert registry.get_fact("libc.base") is None
    assert "libc candidates:" in captured.out
    assert "id=1 name=glibc-a" in captured.out
    assert "id=2 name=glibc-b" in captured.out

    service.close()


def test_resolve_symbol_uses_catalog_offsets_and_alias_normalization(tmp_path: Path) -> None:
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    output_path = tmp_path / "libc.db"
    payload = [
        {
            "name": "glibc-resolve",
            "arch": "amd64",
            "build_id": "build-r",
            "symbols": {
                "puts": "0x080aa0",
                "str_bin_sh": "0x044444",
            },
        }
    ]
    (raw_dir / "sample.json").write_text(json.dumps(payload), encoding="utf-8")
    build_libc_database(raw_dir=raw_dir, output_path=output_path, include_all=True)

    service = LibcCatalogService(db_path=output_path)
    registry = EvidenceRegistry()
    registry.record_fact(
        "libc.base",
        0x7F0000000000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    registry.record_fact(
        "libc.version",
        "glibc-resolve",
        kind=FactKind.VERSION,
        domain=RecordDomain.LIBC,
        metadata={"libc_id": 1, "build_id": "build-r", "arch": "amd64"},
    )
    resolve = ResolveService(
        registry,
        InferenceService(registry, libc_catalog=service),
        catalog_service=service,
    )

    assert resolve.symbol("puts@got") == 0x7F0000000000 + 0x080AA0
    assert resolve.symbol("str_bin_sh") == 0x7F0000000000 + 0x044444

    service.close()


def test_resolve_symbol_raises_when_required_facts_are_missing() -> None:
    registry = EvidenceRegistry()
    resolve = ResolveService(registry, InferenceService(registry))

    try:
        resolve.symbol("system")
    except ResolverError:
        pass
    else:
        raise AssertionError("expected ResolverError")
