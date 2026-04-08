from __future__ import annotations

from chun import CHun, MyTool, Reg, Tool
from chun.core.registry import PwnRegistry


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
