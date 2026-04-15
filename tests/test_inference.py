from __future__ import annotations

import json
from pathlib import Path

from chun.core.catalog import LibcCatalogService, build_libc_database
from chun.core.errors import InferenceInputError
from chun.core.inference import InferenceService
from chun.core.models import ArtifactKind, FactKind, RecordDomain
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

    service.close()
