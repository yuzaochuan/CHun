from __future__ import annotations

from dataclasses import dataclass, field

from chun.core.registry import PwnRegistry
from chun.plugins.blind import BlindFmtTool


@dataclass
class DummyIO:
    timeout: float = 0.0
    closed: bool = False
    sent: list[bytes] = field(default_factory=list)

    def close(self) -> None:
        self.closed = True


def test_dump_stack_ptrs_finds_offset_and_syncs_registry() -> None:
    reg = PwnRegistry()

    def io_factory() -> DummyIO:
        return DummyIO()

    def interact(io_obj: DummyIO, payload: bytes) -> bytes | None:
        io_obj.sent.append(payload)
        table = {
            b"%1$p": b"0x7fffffffde00\n",
            b"%2$p": b"0x70246161\n",  # 含 0x7024 特征，视为命中 offset
            b"%3$p": b"0x555555554123\n",
        }
        return table.get(payload, b"(nil)\n")

    blind = BlindFmtTool(io_factory=io_factory, interact_func=interact, registry=reg, delay=0.0)
    results = blind.dump_stack_ptrs(start_idx=1, end_idx=3)

    assert results[2].startswith("0x7024")
    assert blind.offset == 2
    assert reg.get_value("fmt.input_offset") == 2


def test_dump_stack_ptrs_recovers_after_crash() -> None:
    reg = PwnRegistry()
    counter = {"io_factory_calls": 0}

    def io_factory() -> DummyIO:
        counter["io_factory_calls"] += 1
        return DummyIO()

    def interact(_io_obj: DummyIO, payload: bytes) -> bytes | None:
        if payload == b"%2$p":
            return None
        return b"0x7ffff7dd18b0\n"

    blind = BlindFmtTool(io_factory=io_factory, interact_func=interact, registry=reg, delay=0.0)
    blind.dump_stack_ptrs(start_idx=1, end_idx=3)

    assert counter["io_factory_calls"] >= 2


def test_offest_alias_maps_to_offset() -> None:
    blind = BlindFmtTool(io_factory=DummyIO, interact_func=lambda _io, _payload: b"(nil)\n")

    blind.offest = 7

    assert blind.offset == 7
    assert blind.offest == 7
