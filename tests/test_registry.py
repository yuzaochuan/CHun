from __future__ import annotations

import pytest

import chun.core.registry.service as registry_service
from chun.core.errors import RegistryConflictError
from chun.core.models import (
    ArtifactKind,
    ContextKind,
    FactKind,
    ObservationKind,
    RecordDomain,
)
from chun.core.replay import VerificationResult
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


def test_registry_require_helpers_return_typed_values() -> None:
    registry = EvidenceRegistry()
    registry.record_observation("puts", 0x401000, domain=RecordDomain.LIBC)
    registry.record_fact("libc.base", 0x7F0000000000, domain=RecordDomain.LIBC)
    registry.record_fact("libc.version", "glibc-test", domain=RecordDomain.LIBC)

    assert registry.require_observation("puts").name == "puts"
    assert registry.require_int_observation("puts") == 0x401000
    assert registry.require_int_fact("libc.base") == 0x7F0000000000
    assert registry.require_str_fact("libc.version") == "glibc-test"


def test_registry_require_helpers_raise_for_missing_or_wrong_type() -> None:
    registry = EvidenceRegistry()
    registry.record_observation("puts", b"not-an-int", domain=RecordDomain.LIBC)

    with pytest.raises(KeyError, match="observation 不存在"):
        registry.require_observation("missing")

    with pytest.raises(TypeError, match="不是 int"):
        registry.require_int_observation("puts")


def test_registry_snapshot_can_filter_layers_and_limit_each_layer() -> None:
    registry = EvidenceRegistry()
    registry.set_context(
        "workflow.current_checkpoint",
        "menu",
        kind=ContextKind.SESSION,
        domain=RecordDomain.WORKFLOW,
    )
    registry.record_fact(
        "libc.base",
        0x7F0001200000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
    )
    registry.record_fact(
        "resolved.system",
        0x7F0001249000,
        kind=FactKind.SYMBOL_ADDRESS,
        domain=RecordDomain.LIBC,
    )

    snapshot = registry.snapshot(layers=("context", "facts"), limit=1)

    assert list(snapshot["layers"]) == ["context", "facts"]
    assert snapshot["summary"] == {"context": 1, "facts": 1, "total": 2}
    assert [item.name for item in snapshot["layers"]["facts"]] == ["libc.base"]


def test_registry_render_can_skip_artifact_layer_output() -> None:
    registry = EvidenceRegistry()
    registry.record_fact(
        "libc.base",
        0x7F0001200000,
        kind=FactKind.BASE_ADDRESS,
        domain=RecordDomain.LIBC,
        source="infer",
        confidence=0.95,
    )
    registry.record_artifact(
        "ret2libc.payload",
        b"AAAA",
        kind=ArtifactKind.PAYLOAD,
        domain=RecordDomain.TEMPLATE,
    )

    standard_lines = registry.render(detail="standard")
    skipped_lines = registry.render(detail="standard", artifact_mode="skip")

    assert any("facts=1 arts=1 total=2" in line for line in standard_lines)
    assert any("bytes[len=4]" in line for line in standard_lines)
    assert any("conf=0.95" in line for line in standard_lines)
    assert any("facts=1 arts=0 total=1" in line for line in skipped_lines)
    assert "[Artifacts]" not in skipped_lines


def test_registry_show_uses_requested_emit_level(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = EvidenceRegistry()
    registry.record_fact("libc.base", 0x7F0001200000, kind=FactKind.BASE_ADDRESS)

    calls: list[tuple[str, str]] = []

    class _StubLog:
        def debug(self, message: str) -> None:
            calls.append(("debug", message))

        def info(self, message: str) -> None:
            calls.append(("info", message))

        def warning(self, message: str) -> None:
            calls.append(("warning", message))

    monkeypatch.setattr(registry_service, "log", _StubLog())

    lines = registry.show(layers="facts", detail="compact", emit="warning")

    assert lines
    assert calls
    assert all(level == "warning" for level, _ in calls)
    assert calls[0][1].startswith("[Registry]")


def test_registry_to_dict_supports_replay_mappingproxy_metadata() -> None:
    registry = EvidenceRegistry()
    registry.append_event("spawn", metadata={"target_kind": "process"})
    registry.append_event("sendline", payload=b"3\n")
    registry.checkpoint("io_node_1", metadata={"tag": "manual"})

    payload = registry.to_dict()
    replay = payload["replay"]
    events = replay["events"]
    checkpoints = replay["checkpoints"]

    assert len(events) == 3
    assert events[0]["kind"] == "spawn"
    assert events[0]["metadata"]["target_kind"] == "process"
    assert events[1]["kind"] == "sendline"
    assert events[1]["payload"]["size"] == 2
    assert events[2]["kind"] == "checkpoint"
    assert checkpoints["io_node_1"]["name"] == "io_node_1"
    assert checkpoints["io_node_1"]["metadata"]["tag"] == "manual"


def test_registry_can_render_and_show_replay(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = EvidenceRegistry()
    registry.append_event("spawn", metadata={"target_kind": "process"})
    registry.append_event("sendline", payload=b"3\n")
    registry.checkpoint("io_node_1")

    rendered = registry.render_replay(include_payload=True, payload_mode="repr")
    assert rendered
    assert rendered[0].startswith("[Replay]")
    assert any("payload=b'3\\n'" in line for line in rendered)

    calls: list[tuple[str, str]] = []

    class _StubLog:
        def debug(self, message: str) -> None:
            calls.append(("debug", message))

        def info(self, message: str) -> None:
            calls.append(("info", message))

        def warning(self, message: str) -> None:
            calls.append(("warning", message))

    monkeypatch.setattr(registry_service, "log", _StubLog())
    lines = registry.show_replay(emit="warning", include_payload=False, limit=2)
    assert lines
    assert calls
    assert all(level == "warning" for level, _ in calls)


def test_registry_run_replay_can_request_replay_registry_capture() -> None:
    registry = EvidenceRegistry()
    registry.append_event("sendline", payload=b"3\n")
    captured: dict[str, object] = {}

    class _StubExecutor:
        def replay(self, trace: tuple[object, ...], **kwargs: object) -> VerificationResult:
            captured["trace_len"] = len(trace)
            captured.update(kwargs)
            return VerificationResult(run_id="run", ok=True, reason="predicate_pass")

    result = registry.run_replay(
        session_factory=lambda: object(),
        executor=_StubExecutor(),  # type: ignore[arg-type]
        probe=b"7",
        predicate=lambda _out: True,
        capture_replay_registry=True,
        replay_registry_layers=("context", "facts"),
        replay_registry_detail="compact",
        replay_registry_limit=3,
    )

    assert result.ok is True
    assert captured["trace_len"] == 1
    assert captured["capture_registry"] is True
    assert captured["registry_layers"] == ("context", "facts")
    assert captured["registry_detail"] == "compact"
    assert captured["registry_limit"] == 3
