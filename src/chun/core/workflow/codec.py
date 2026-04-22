"""Workflow / Action IR 的 JSON 导出与导入。"""

from __future__ import annotations

import json
from dataclasses import fields, is_dataclass
from pathlib import Path
from typing import Mapping

from ..models.action_ir import (
    AnalysisNode,
    AssignNode,
    CallNode,
    ExpActionIR,
    ExprNode,
    FunctionActionDef,
    ImportModel,
    ImportRef,
    LiteralNode,
    NameRefNode,
    OpaqueCallNode,
    PrimitiveNode,
    RecursiveCallNode,
    SourceSpan,
    TopLevelBlockDef,
)
from ..models.workflow import (
    WorkflowCheckpoint,
    WorkflowExecutionResult,
    WorkflowPrimitive,
    WorkflowStepReceipt,
    WorkflowTranscript,
)


_TYPE_REGISTRY = {
    cls.__name__: cls
    for cls in (
        AnalysisNode,
        AssignNode,
        CallNode,
        ExpActionIR,
        ExprNode,
        FunctionActionDef,
        ImportModel,
        ImportRef,
        LiteralNode,
        NameRefNode,
        OpaqueCallNode,
        PrimitiveNode,
        RecursiveCallNode,
        SourceSpan,
        TopLevelBlockDef,
        WorkflowCheckpoint,
        WorkflowExecutionResult,
        WorkflowPrimitive,
        WorkflowStepReceipt,
        WorkflowTranscript,
    )
}


class WorkflowJsonCodec:
    """把 Action IR / WorkflowTranscript 稳定落成 JSON。"""

    @classmethod
    def dump_action_ir(cls, ir: ExpActionIR, path: str | Path) -> Path:
        return cls._dump(ir, path)

    @classmethod
    def load_action_ir(cls, path: str | Path) -> ExpActionIR:
        loaded = cls._load(path)
        if not isinstance(loaded, ExpActionIR):
            raise TypeError("JSON payload is not an ExpActionIR")
        return loaded

    @classmethod
    def dump_transcript(cls, transcript: WorkflowTranscript, path: str | Path) -> Path:
        return cls._dump(transcript, path)

    @classmethod
    def load_transcript(cls, path: str | Path) -> WorkflowTranscript:
        loaded = cls._load(path)
        if not isinstance(loaded, WorkflowTranscript):
            raise TypeError("JSON payload is not a WorkflowTranscript")
        return loaded

    @classmethod
    def to_jsonable(cls, value: object) -> object:
        if is_dataclass(value):
            payload: dict[str, object] = {"__type__": value.__class__.__name__}
            for item in fields(value):
                payload[item.name] = cls.to_jsonable(getattr(value, item.name))
            return payload
        if isinstance(value, bytes):
            return {"__kind__": "bytes", "encoding": "hex", "value": value.hex()}
        if isinstance(value, bytearray):
            return {"__kind__": "bytes", "encoding": "hex", "value": bytes(value).hex()}
        if isinstance(value, tuple):
            return {"__kind__": "tuple", "items": [cls.to_jsonable(item) for item in value]}
        if isinstance(value, list):
            return [cls.to_jsonable(item) for item in value]
        if isinstance(value, Mapping):
            return {str(key): cls.to_jsonable(item) for key, item in value.items()}
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        raise TypeError(f"unsupported workflow json value: {type(value).__name__}")

    @classmethod
    def from_jsonable(cls, value: object) -> object:
        if isinstance(value, list):
            return [cls.from_jsonable(item) for item in value]
        if not isinstance(value, dict):
            return value

        kind = value.get("__kind__")
        if kind == "bytes":
            raw = value.get("value")
            if not isinstance(raw, str):
                raise TypeError("bytes payload must use string hex value")
            return bytes.fromhex(raw)
        if kind == "tuple":
            items = value.get("items")
            if not isinstance(items, list):
                raise TypeError("tuple payload must provide list items")
            return tuple(cls.from_jsonable(item) for item in items)

        type_name = value.get("__type__")
        if isinstance(type_name, str):
            model_type = _TYPE_REGISTRY.get(type_name)
            if model_type is None:
                raise TypeError(f"unsupported workflow model type: {type_name}")
            kwargs = {
                key: cls.from_jsonable(item)
                for key, item in value.items()
                if key != "__type__"
            }
            return model_type(**kwargs)

        return {str(key): cls.from_jsonable(item) for key, item in value.items()}

    @classmethod
    def _dump(cls, value: object, path: str | Path) -> Path:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        payload = cls.to_jsonable(value)
        file_path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return file_path

    @classmethod
    def _load(cls, path: str | Path) -> object:
        file_path = Path(path)
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        return cls.from_jsonable(payload)


__all__ = ["WorkflowJsonCodec"]
