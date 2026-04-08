from __future__ import annotations

from chun.core.target import resolve_remote_mode


def test_resolve_remote_mode_priority() -> None:
    assert resolve_remote_mode(config_remote=False, cli_remote=False, override=True) is True
    assert resolve_remote_mode(config_remote=False, cli_remote=True, override=None) is True
    assert resolve_remote_mode(config_remote=True, cli_remote=False, override=None) is True
    assert resolve_remote_mode(config_remote=False, cli_remote=False, override=None) is False
