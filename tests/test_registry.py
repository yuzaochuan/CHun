from __future__ import annotations

import pytest

from chun.core.errors import RegistryConflictError
from chun.core.models import (
    ArtifactKind,
    ContextKind,
    FactKind,
    ObservationKind,
    RecordDomain,
)
from chun.core.registry import EvidenceRegistry


def test_registry_can_record_all_four_buckets() -> None:
    registry = EvidenceRegistry()

    observation = registry.record_observation(
        "puts",
        0x7F0001234000,
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        source="got",
    )
    fact = registry.record_fact(
        "libc.base",
        0x7F0001200000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
        evidence=["puts"],
    )
    artifact = registry.record_artifact(
        "ret2libc.payload",
        b"AAAA",
        kind=ArtifactKind.PAYLOAD,
        domain=RecordDomain.TEMPLATE,
    )
    context = registry.set_context(
        "target.host",
        "example.com",
        kind=ContextKind.TARGET,
        domain=RecordDomain.TARGET,
    )

    assert registry.get_observation("puts") is observation
    assert registry.get_fact("libc.base") is fact
    assert registry.get_artifact("ret2libc.payload") is artifact
    assert registry.get_context("target.host") is context


def test_registry_can_query_by_domain_kind_and_tag() -> None:
    registry = EvidenceRegistry()
    registry.record_observation(
        "puts",
        0x7F0001234000,
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.LIBC,
        tags=["leak", "libc"],
    )
    registry.record_observation(
        "main",
        0x555555555199,
        kind=ObservationKind.SYMBOL_LEAK,
        domain=RecordDomain.ELF,
        tags=["leak", "elf"],
    )

    libc_records = registry.find_observations(domain=RecordDomain.LIBC)
    leak_records = registry.find_observations(tag="leak")

    assert [item.name for item in libc_records] == ["puts"]
    assert {item.name for item in leak_records} == {"puts", "main"}


def test_registry_overwrite_rules_are_explicit() -> None:
    registry = EvidenceRegistry()
    registry.record_fact("libc.base", 0x7F0001200000, kind=FactKind.BASE_ADDRESS)

    with pytest.raises(RegistryConflictError):
        registry.record_fact(
            "libc.base",
            0x7F0001300000,
            kind=FactKind.BASE_ADDRESS,
            overwrite=False,
        )

    replaced = registry.record_fact(
        "libc.base",
        0x7F0001300000,
        kind=FactKind.BASE_ADDRESS,
        overwrite=True,
    )
    assert replaced.value == 0x7F0001300000


def test_record_symbol_leak_helper_is_explicit_about_domain() -> None:
    registry = EvidenceRegistry()

    record = registry.record_symbol_leak(
        "puts",
        0x7F0001234000,
        domain=RecordDomain.LIBC,
        source="got",
        tags=["libc", "leak"],
    )

    assert record.kind == ObservationKind.SYMBOL_LEAK
    assert record.domain == RecordDomain.LIBC
    assert record.source == "got"
    assert "leak" in record.tags
