from __future__ import annotations

from chun.core.registry import AddressClass, PwnRegistry, RecordKind, RecordSource


def test_add_log_keeps_int_and_misc_values() -> None:
    reg = PwnRegistry()

    reg.add_log("puts@libc", 0x7F0001234000)
    reg.add_log(note="warmup")

    record = reg.get_record("puts@libc")
    assert record is not None
    assert record.value == 0x7F0001234000
    assert record.kind == RecordKind.LEAK
    assert reg.get_value("note") == "warmup"


def test_add_log_can_attach_metadata_to_single_record() -> None:
    reg = PwnRegistry()

    reg.add_log(
        "_IO_2_1_stderr_@libc",
        0x7F0001234000,
        kind=RecordKind.LIBC_SYMBOL,
        source=RecordSource.GDB_SYNC,
        confidence=0.95,
        notes="gdb 确认的 stderr 泄漏",
        meta={"stage": "leak"},
    )

    record = reg.get_record("_IO_2_1_stderr_@libc")
    assert record is not None
    assert record.kind == RecordKind.LIBC_SYMBOL
    assert record.source == RecordSource.GDB_SYNC
    assert record.confidence == 0.95
    assert record.notes == "gdb 确认的 stderr 泄漏"
    assert record.meta["stage"] == "leak"


def test_add_log_supports_single_keyword_record_with_metadata() -> None:
    reg = PwnRegistry()

    reg.add_log(
        puts_libc=0x7F0001234000,
        kind=RecordKind.LIBC_SYMBOL,
        source=RecordSource.LOCAL_ELF,
        confidence=0.80,
    )

    record = reg.get_record("puts_libc")
    assert record is not None
    assert record.kind == RecordKind.LIBC_SYMBOL
    assert record.source == RecordSource.LOCAL_ELF
    assert record.confidence == 0.80


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


def test_infer_base_uses_semantic_hint_for_libc_like_leak() -> None:
    reg = PwnRegistry()

    stderr_offset = 0x1D3680
    expected_base = 0x7F1234500000
    leak = expected_base + stderr_offset

    reg.add_log("_IO_2_1_stderr_@libc", leak)
    candidate = reg.infer_base(
        leak_name="_IO_2_1_stderr_@libc",
        symbol_offset=stderr_offset,
        base_name="libc",
    )

    assert candidate.aligned_base == expected_base
    assert candidate.score >= 0.55

    base_record = reg.get_base("libc")
    assert base_record is not None
    assert base_record.base == expected_base


def test_infer_base_prefers_stronger_source_prior() -> None:
    offset = 0x080000
    expected_base = 0x7F1234500000
    leak = expected_base + offset

    manual_reg = PwnRegistry()
    manual_reg.add_address(
        "puts@libc",
        leak,
        source=RecordSource.MANUAL,
        confidence=0.50,
    )
    manual_candidate = manual_reg.infer_base("puts@libc", offset, base_name="libc")

    local_elf_reg = PwnRegistry()
    local_elf_reg.add_address(
        "puts@libc",
        leak,
        source=RecordSource.LOCAL_ELF,
        confidence=0.50,
    )
    local_elf_candidate = local_elf_reg.infer_base("puts@libc", offset, base_name="libc")

    assert local_elf_candidate.score > manual_candidate.score


def test_infer_base_penalizes_conflicting_related_base() -> None:
    reg = PwnRegistry()
    offset = 0x080000

    reg.add_base(
        name="libc_main",
        base=0x7F1234500000,
        meta={"address_class": AddressClass.LIBC_LIKE.value},
    )
    reg.add_log("puts@libc", 0x7F1234700000 + offset)

    candidate = reg.infer_base("puts@libc", offset, base_name="libc_alt")

    assert candidate.score < reg.accept_score
    assert reg.get_base("libc_alt") is None


def test_infer_base_handles_abnormal_raw_base_without_raising() -> None:
    reg = PwnRegistry()
    reg.add_log("puts@libc", 0x1000)

    candidate = reg.infer_base("puts@libc", symbol_offset=0x5000, base_name="libc")

    assert candidate.raw_base < 0
    assert any("异常" in reason for reason in candidate.reasons)
    assert reg.get_base("libc") is None
