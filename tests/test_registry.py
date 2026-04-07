from __future__ import annotations

from chun.core.registry import AddressClass, PwnRegistry, RecordKind


def test_add_log_keeps_int_and_misc_values() -> None:
    reg = PwnRegistry()

    reg.add_log("puts@libc", 0x7F0001234000)
    reg.add_log(note="warmup")

    record = reg.get_record("puts@libc")
    assert record is not None
    assert record.value == 0x7F0001234000
    assert record.kind == RecordKind.LEAK
    assert reg.get_value("note") == "warmup"


def test_classify_address_returns_reasonable_hint() -> None:
    reg = PwnRegistry()

    assert reg.classify_address(0x555555554000) == AddressClass.PIE_LIKE
    assert reg.classify_address(0x7F1234567000) == AddressClass.LIBC_LIKE
    assert reg.classify_address(0x7FFFFFFFE000) == AddressClass.STACK_LIKE


def test_infer_base_accepts_and_persists_candidate() -> None:
    reg = PwnRegistry(accept_score=0.40)

    puts_offset = 0x080000
    expected_base = 0x7F1234500000
    leak = expected_base + puts_offset
    reg.add_address("puts@libc", leak, confidence=0.90)

    candidate = reg.infer_base(
        leak_name="puts@libc",
        symbol_offset=puts_offset,
        base_name="libc",
    )

    assert candidate.aligned_base == expected_base
    assert candidate.score >= 0.40

    base_record = reg.get_base("libc")
    assert base_record is not None
    assert base_record.base == expected_base
