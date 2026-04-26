"""workflow/action IR translator registry。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Mapping, Sequence

from pwnlib.context import context as pwn_context
from pwnlib.util.cyclic import cyclic
from pwnlib.util.packing import flat, p8, p16, p32, p64, u8, u16, u32, u64

from ..models.action_ir import AnalysisNode, ExprNode, PrimitiveNode

TranslatorEffect = Literal[
    "pure",
    "io_primitive",
    "analysis",
    "expandable_macro",
    "opaque",
]

_DEFAULT_PWN_BITS = int(getattr(pwn_context, "bits", 32))
_DEFAULT_PWN_ENDIAN = str(getattr(pwn_context, "endian", "little"))


@dataclass(slots=True, frozen=True)
class CallTranslation:
    effect: TranslatorEffect
    node: object


@dataclass(slots=True, frozen=True)
class TranslatorContext:
    callee: str
    args: tuple[object, ...]
    keywords: Mapping[str, object]
    source_span: object | None
    metadata: Mapping[str, object]


class BaseCallTranslator:
    effect: TranslatorEffect = "opaque"
    expandable: bool = False

    def translate(self, ctx: TranslatorContext) -> CallTranslation:
        raise NotImplementedError

    def expand(self, node: object) -> tuple[object, ...]:
        return (node,)


@dataclass(slots=True, frozen=True)
class PureExprTranslator(BaseCallTranslator):
    kind: str = "call"
    effect: TranslatorEffect = "pure"

    def translate(self, ctx: TranslatorContext) -> CallTranslation:
        evaluated, resolved_value, value_type, value_summary = self._evaluate(
            ctx.callee,
            ctx.args,
            ctx.keywords,
        )
        return CallTranslation(
            effect=self.effect,
            node=ExprNode(
                kind=self.kind,
                callee=ctx.callee,
                args=ctx.args,
                keywords=ctx.keywords,
                evaluated=evaluated,
                resolved_value=resolved_value,
                value_type=value_type,
                value_summary=value_summary,
                source_span=ctx.source_span,
                metadata=ctx.metadata,
            ),
        )

    def _evaluate(
        self,
        callee: str,
        args: Sequence[object],
        keywords: Mapping[str, object],
    ) -> tuple[bool, object | None, str | None, Mapping[str, object]]:
        resolved_args = tuple(self._unwrap_value(arg) for arg in args)
        resolved_kwargs = {key: self._unwrap_value(value) for key, value in keywords.items()}
        try:
            with pwn_context.local(bits=_DEFAULT_PWN_BITS, endian=_DEFAULT_PWN_ENDIAN):
                if callee in {"str", "builtins.str"} and resolved_args:
                    value = str(resolved_args[0])
                    return True, value, "str", {"preview": value[:64], "length": len(value)}
                if callee in {"int", "builtins.int"} and resolved_args:
                    value = int(resolved_args[0])
                    return True, value, "int", {"preview": str(value)}
                if callee in {"bytes", "builtins.bytes"} and resolved_args:
                    value = bytes(resolved_args[0])
                    return True, value, "bytes", self._bytes_summary(value)
                if callee in {"flat", "pwn.flat"}:
                    value = flat(*resolved_args, **resolved_kwargs)
                    return True, value, "bytes", self._bytes_summary(value)
                if callee == "cyclic":
                    value = cyclic(*resolved_args, **resolved_kwargs)
                    return True, value, "bytes", self._bytes_summary(value)
                if callee == "p8" and resolved_args:
                    value = p8(int(resolved_args[0]))
                    return True, value, "bytes", self._bytes_summary(value)
                if callee == "p16" and resolved_args:
                    value = p16(int(resolved_args[0]))
                    return True, value, "bytes", self._bytes_summary(value)
                if callee == "p32" and resolved_args:
                    value = p32(int(resolved_args[0]))
                    return True, value, "bytes", self._bytes_summary(value)
                if callee == "p64" and resolved_args:
                    value = p64(int(resolved_args[0]))
                    return True, value, "bytes", self._bytes_summary(value)
                if callee == "u8" and resolved_args:
                    value = u8(bytes(resolved_args[0]))
                    return True, int(value), "int", {"preview": str(int(value))}
                if callee == "u16" and resolved_args:
                    value = u16(bytes(resolved_args[0]))
                    return True, int(value), "int", {"preview": str(int(value))}
                if callee == "u32" and resolved_args:
                    value = u32(bytes(resolved_args[0]))
                    return True, int(value), "int", {"preview": str(int(value))}
                if callee == "u64" and resolved_args:
                    value = u64(bytes(resolved_args[0]))
                    return True, int(value), "int", {"preview": str(int(value))}
                if callee.endswith(".encode"):
                    receiver = resolved_args[0] if resolved_args else self._receiver_value(callee, args)
                    if isinstance(receiver, str):
                        encoding = (
                            str(resolved_args[1])
                            if len(resolved_args) > 1
                            else str(resolved_kwargs.get("encoding", "utf-8"))
                        )
                        errors = (
                            str(resolved_args[2])
                            if len(resolved_args) > 2
                            else str(resolved_kwargs.get("errors", "strict"))
                        )
                        value = receiver.encode(encoding, errors)
                        return True, value, "bytes", self._bytes_summary(value)
        except Exception:
            return False, None, None, {}
        return False, None, None, {}

    @staticmethod
    def _receiver_value(callee: str, args: Sequence[object]) -> object | None:
        if args:
            return None
        prefix = callee.rsplit(".encode", 1)[0]
        if prefix.startswith(("'", '"')) and prefix.endswith(("'", '"')):
            return prefix[1:-1]
        return None

    @staticmethod
    def _unwrap_value(node: object) -> object:
        if hasattr(node, "resolved_value") and getattr(node, "evaluated", False):
            return getattr(node, "resolved_value")
        if hasattr(node, "value"):
            return getattr(node, "value")
        if hasattr(node, "name"):
            return getattr(node, "name")
        return node

    @staticmethod
    def _bytes_summary(value: bytes) -> Mapping[str, object]:
        return {"length": len(value), "preview_hex": value[:16].hex()}


@dataclass(slots=True, frozen=True)
class PrimitiveCallTranslator(BaseCallTranslator):
    primitive_kind: str
    effect: TranslatorEffect = "io_primitive"
    expandable: bool = False

    def translate(self, ctx: TranslatorContext) -> CallTranslation:
        payload = ctx.args[0] if ctx.args else None
        return CallTranslation(
            effect=self.effect,
            node=PrimitiveNode(
                kind=self.primitive_kind,
                payload=payload,
                args=ctx.args,
                keywords=ctx.keywords,
                source_span=ctx.source_span,
                metadata=ctx.metadata,
            ),
        )

    def expand(self, node: object) -> tuple[object, ...]:
        primitive = node if isinstance(node, PrimitiveNode) else None
        if primitive is None or not self.expandable:
            return (node,)
        if primitive.kind == "sendafter":
            return (
                PrimitiveNode(
                    kind="expect",
                    payload=primitive.args[0] if primitive.args else None,
                    args=(primitive.args[0],) if primitive.args else (),
                    source_span=primitive.source_span,
                    metadata={**dict(primitive.metadata), "expanded_from": "sendafter"},
                ),
                PrimitiveNode(
                    kind="send",
                    payload=primitive.args[1] if len(primitive.args) > 1 else None,
                    args=(primitive.args[1],) if len(primitive.args) > 1 else (),
                    source_span=primitive.source_span,
                    metadata={**dict(primitive.metadata), "expanded_from": "sendafter"},
                ),
            )
        if primitive.kind == "sendlineafter":
            return (
                PrimitiveNode(
                    kind="expect",
                    payload=primitive.args[0] if primitive.args else None,
                    args=(primitive.args[0],) if primitive.args else (),
                    source_span=primitive.source_span,
                    metadata={**dict(primitive.metadata), "expanded_from": "sendlineafter"},
                ),
                PrimitiveNode(
                    kind="sendline",
                    payload=primitive.args[1] if len(primitive.args) > 1 else None,
                    args=(primitive.args[1],) if len(primitive.args) > 1 else (),
                    source_span=primitive.source_span,
                    metadata={**dict(primitive.metadata), "expanded_from": "sendlineafter"},
                ),
            )
        return (primitive,)


@dataclass(slots=True, frozen=True)
class AnalysisCallTranslator(BaseCallTranslator):
    effect: TranslatorEffect = "analysis"

    def translate(self, ctx: TranslatorContext) -> CallTranslation:
        return CallTranslation(
            effect=self.effect,
            node=AnalysisNode(
                callee=ctx.callee,
                args=ctx.args,
                keywords=ctx.keywords,
                source_span=ctx.source_span,
                metadata=ctx.metadata,
            ),
        )


class WorkflowTranslatorRegistry:
    """面向 exploit 脚本的调用分类注册表。"""

    def __init__(self) -> None:
        self._exact: dict[str, BaseCallTranslator] = {}
        self._suffix: dict[str, BaseCallTranslator] = {}
        self._bootstrap_defaults()

    def register_exact(self, name: str, translator: BaseCallTranslator) -> None:
        self._exact[name] = translator

    def register_suffix(self, suffix: str, translator: BaseCallTranslator) -> None:
        self._suffix[suffix] = translator

    def resolve(self, callee: str) -> BaseCallTranslator | None:
        if callee in self._exact:
            return self._exact[callee]
        for suffix, translator in self._suffix.items():
            if callee.endswith(suffix):
                return translator
        return None

    def classify(
        self,
        callee: str,
        *,
        args: Sequence[object],
        keywords: Mapping[str, object],
        source_span: object | None,
        metadata: Mapping[str, object],
    ) -> CallTranslation | None:
        translator = self.resolve(callee)
        if translator is None:
            return None
        return translator.translate(
            TranslatorContext(
                callee=callee,
                args=tuple(args),
                keywords=keywords,
                source_span=source_span,
                metadata=metadata,
            )
        )

    def expand_macro(self, node: object) -> tuple[object, ...]:
        primitive = node if isinstance(node, PrimitiveNode) else None
        if primitive is None:
            return (node,)
        translator = self.resolve(str(primitive.metadata.get("callee", primitive.kind)))
        if translator is None:
            return (primitive,)
        return translator.expand(primitive)

    def _bootstrap_defaults(self) -> None:
        pure = PureExprTranslator()
        for name in (
            "str",
            "int",
            "bytes",
            "flat",
            "p8",
            "p16",
            "p32",
            "p64",
            "u8",
            "u16",
            "u32",
            "u64",
            "cyclic",
        ):
            self.register_exact(name, pure)
        for name in ("builtins.str", "builtins.int", "builtins.bytes", "pwn.flat"):
            self.register_exact(name, pure)
        self.register_suffix(".encode", pure)

        self.register_suffix(".send", PrimitiveCallTranslator("send"))
        self.register_suffix(".sendline", PrimitiveCallTranslator("sendline"))
        self.register_suffix(".recv", PrimitiveCallTranslator("recv"))
        self.register_suffix(".recvuntil", PrimitiveCallTranslator("expect"))
        self.register_suffix(".request", PrimitiveCallTranslator("request"))
        self.register_suffix(
            ".sa",
            PrimitiveCallTranslator("sendafter", effect="expandable_macro", expandable=True),
        )
        self.register_suffix(
            ".sla",
            PrimitiveCallTranslator("sendlineafter", effect="expandable_macro", expandable=True),
        )
        self.register_suffix(
            ".sendafter",
            PrimitiveCallTranslator("sendafter", effect="expandable_macro", expandable=True),
        )
        self.register_suffix(
            ".sendlineafter",
            PrimitiveCallTranslator("sendlineafter", effect="expandable_macro", expandable=True),
        )
        self.register_suffix(".infer.search_libc", AnalysisCallTranslator())
        self.register_suffix(".infer.libc_base_from", AnalysisCallTranslator())
        self.register_suffix(".infer.libc_base_from_symbol_leak", AnalysisCallTranslator())
        self.register_suffix(".recv_leak", AnalysisCallTranslator())
        self.register_suffix(".resolve.libc_base_from_elf_symbol", AnalysisCallTranslator())
        self.register_suffix(".resolve.symbol_via_dynelf", AnalysisCallTranslator())
        self.register_suffix(".search_libc", AnalysisCallTranslator())
        self.register_suffix(".libc_base_from", AnalysisCallTranslator())


__all__ = [
    "BaseCallTranslator",
    "CallTranslation",
    "PrimitiveCallTranslator",
    "PureExprTranslator",
    "TranslatorContext",
    "WorkflowTranslatorRegistry",
]
