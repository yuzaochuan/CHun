from __future__ import annotations

from chun import CHun, MyTool, Reg, Tool
from chun.core.registry import PwnRegistry, RecordKind, RecordSource


def test_public_aliases_are_consistent() -> None:
    assert Tool is MyTool
    assert CHun is MyTool
    assert Reg.__name__ == "PwnRegistry"


def test_derive_base_can_forward_custom_accept_score() -> None:
    tool = MyTool.__new__(MyTool)
    tool.reg = PwnRegistry(accept_score=0.55)

    stderr_offset = 0x1D3680
    expected_base = 0x7F1234500000
    leak = expected_base + stderr_offset
    tool.reg.add_address("_IO_2_1_stderr_@libc", leak, confidence=0.50)

    candidate = tool.derive_base(
        "_IO_2_1_stderr_@libc",
        stderr_offset,
        base_name="libc",
        min_accept_score=0.40,
    )

    assert candidate.aligned_base == expected_base
    assert tool.reg.get_base("libc") is not None


def test_record_libc_symbol_uses_semantic_defaults() -> None:
    tool = MyTool.__new__(MyTool)
    tool.reg = PwnRegistry()

    tool.api.record_libc_symbol("puts", 0x7F1234501000)

    record = tool.reg.get_record("puts@libc")
    assert record is not None
    assert record.kind == RecordKind.LIBC_SYMBOL
    assert record.source == RecordSource.MANUAL
    assert record.confidence == 0.90


def test_show_forwards_verbose_flag() -> None:
    tool = MyTool.__new__(MyTool)
    tool.reg = PwnRegistry()
    called: list[bool] = []

    def _fake_puts_log(*, verbose: bool = False) -> None:
        called.append(verbose)

    tool.reg.puts_log = _fake_puts_log  # type: ignore[method-assign]

    tool.show()
    tool.show(verbose=True)

    assert called == [False, True]


def test_infer_libc_base_from_uses_libc_symbol_and_suffix_fallback() -> None:
    class _DummyLibc:
        sym = {"puts": 0x80000}

    tool = MyTool.__new__(MyTool)
    tool.reg = PwnRegistry(accept_score=0.40)
    tool.target = type("DummyTarget", (), {"libc": _DummyLibc(), "elf": None})()

    expected_base = 0x7F1234500000
    leak = expected_base + 0x80000
    tool.reg.add_log("puts@libc", leak)

    candidate = tool.api.infer_libc_base_from("puts")
    assert candidate.aligned_base == expected_base
    assert tool.reg.get_base("libc") is not None


def test_infer_pie_base_from_uses_elf_symbol_and_suffix_fallback() -> None:
    class _DummyElf:
        sym = {"main": 0x1200}

    tool = MyTool.__new__(MyTool)
    tool.reg = PwnRegistry(accept_score=0.40)
    tool.target = type("DummyTarget", (), {"libc": None, "elf": _DummyElf()})()

    expected_base = 0x555555554000
    leak = expected_base + 0x1200
    tool.reg.add_log("main_ret@elf", leak, kind=RecordKind.PIE_RET)

    candidate = tool.api.infer_pie_base_from("main_ret")
    assert candidate.aligned_base == expected_base
    assert tool.reg.get_base("pie") is not None
