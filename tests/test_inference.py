from __future__ import annotations

from chun.core.inference import InferenceService
from chun.core.models import FactKind, RecordDomain
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
