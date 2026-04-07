from __future__ import annotations

from chun import CHun, MyTool, Reg, Tool


def test_public_aliases_are_consistent() -> None:
    assert Tool is MyTool
    assert CHun is MyTool
    assert Reg.__name__ == "PwnRegistry"
