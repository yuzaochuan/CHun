"""Exploit source -> action IR -> workflow transcript。"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Mapping, Sequence

from ..models.action_ir import (
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
    WorkflowPrimitive,
    WorkflowTranscript,
)
from .translators import WorkflowTranslatorRegistry


class ExploitWorkflowCompiler:
    """面向 exploit 脚本的 action IR / transcript 编译器。"""

    def __init__(
        self,
        *,
        registry: WorkflowTranslatorRegistry | None = None,
        max_expand_depth: int = 8,
    ) -> None:
        self.registry = registry if registry is not None else WorkflowTranslatorRegistry()
        self.max_expand_depth = max_expand_depth
        self._current_filename = "<memory>"

    def compile_source(
        self,
        source: str,
        *,
        module_name: str = "exp",
        filename: str = "<memory>",
    ) -> ExpActionIR:
        self._current_filename = filename
        module = ast.parse(source, filename=filename)
        imports: list[ImportRef] = []
        functions: list[FunctionActionDef] = []
        blocks: list[TopLevelBlockDef] = []
        current_block: list[ast.stmt] = []
        block_index = 0
        function_names: dict[str, str] = {}

        for stmt in module.body:
            if isinstance(stmt, (ast.Import, ast.ImportFrom)):
                imports.extend(self._lower_import(stmt))
                continue
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if current_block:
                    blocks.append(
                        self._build_top_level_block(
                            current_block,
                            source=source,
                            module_name=module_name,
                            block_index=block_index,
                            function_names=function_names,
                        )
                    )
                    current_block = []
                    block_index += 1
                function_names[stmt.name] = f"{module_name}.{stmt.name}"
                continue
            current_block.append(stmt)

        for stmt in module.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions.append(
                    self._build_function_def(
                        stmt,
                        source=source,
                        module_name=module_name,
                        function_names=function_names,
                    )
                )

        if current_block:
            blocks.append(
                self._build_top_level_block(
                    current_block,
                    source=source,
                    module_name=module_name,
                    block_index=block_index,
                    function_names=function_names,
                )
            )

        return ExpActionIR(
            module_name=module_name,
            imports=ImportModel(refs=tuple(imports), source_span=self._span_for_module(module)),
            functions=tuple(functions),
            top_level_blocks=tuple(blocks),
            entrypoints=tuple(block.block_id for block in blocks),
            source=source,
            filename=filename,
            metadata={"function_count": len(functions), "block_count": len(blocks)},
        )

    def compile_path(self, path: str | Path, *, module_name: str = "exp") -> ExpActionIR:
        file_path = Path(path)
        return self.compile_source(
            file_path.read_text(encoding="utf-8"),
            module_name=module_name,
            filename=str(file_path),
        )

    def expand_action(
        self,
        ir: ExpActionIR,
        action_id: str,
        *,
        max_expand_depth: int | None = None,
    ) -> tuple[object, ...]:
        limit = self.max_expand_depth if max_expand_depth is None else max_expand_depth
        action = ir.action_map[action_id]
        return self._expand_body(
            tuple(getattr(action, "body")),
            ir=ir,
            call_stack=(action_id,),
            depth=0,
            max_expand_depth=limit,
        )

    def build_transcript(
        self,
        ir: ExpActionIR,
        entry_action: str,
        *,
        max_expand_depth: int | None = None,
    ) -> WorkflowTranscript:
        expanded = self.expand_action(ir, entry_action, max_expand_depth=max_expand_depth)
        primitives: list[WorkflowPrimitive] = [
            WorkflowPrimitive(
                kind="checkpoint",
                checkpoint=WorkflowCheckpoint(
                    name=entry_action,
                    source_action=entry_action,
                    source_node="entry",
                    metadata={"entry_action": entry_action},
                ),
                source_action=entry_action,
                source_node="entry",
                metadata={"entry_action": entry_action},
            )
        ]
        for node in expanded:
            primitives.extend(self._node_to_transcript(node, source_action=entry_action))
        return WorkflowTranscript(
            entry_action=entry_action,
            primitives=tuple(primitives),
            source_map={"entry_action": entry_action},
            metadata={"expanded_nodes": len(expanded)},
        )

    def build_module_transcript(
        self,
        ir: ExpActionIR,
        *,
        entry_actions: Sequence[str] | None = None,
        max_expand_depth: int | None = None,
    ) -> WorkflowTranscript:
        """按顶层块顺序构建整份 exp 的 transcript。"""
        selected = tuple(entry_actions) if entry_actions is not None else tuple(ir.entrypoints)
        primitives: list[WorkflowPrimitive] = []
        for action_id in selected:
            transcript = self.build_transcript(
                ir,
                action_id,
                max_expand_depth=max_expand_depth,
            )
            primitives.extend(transcript.primitives)
        return WorkflowTranscript(
            entry_action=f"{ir.module_name}.__module__",
            primitives=tuple(primitives),
            source_map={"entry_actions": selected},
            metadata={
                "entry_actions": selected,
                "expanded_blocks": len(selected),
            },
        )

    def _build_function_def(
        self,
        stmt: ast.FunctionDef | ast.AsyncFunctionDef,
        *,
        source: str,
        module_name: str,
        function_names: Mapping[str, str],
    ) -> FunctionActionDef:
        return FunctionActionDef(
            action_id=f"{module_name}.{stmt.name}",
            qualname=f"{module_name}.{stmt.name}",
            params=tuple(arg.arg for arg in stmt.args.args),
            body=tuple(
                node
                for child in stmt.body
                if (node := self._lower_stmt(child, source=source, function_names=function_names))
                is not None
            ),
            source_span=self._span(stmt),
            metadata={"source_text": self._segment(source, stmt)},
        )

    def _build_top_level_block(
        self,
        statements: Sequence[ast.stmt],
        *,
        source: str,
        module_name: str,
        block_index: int,
        function_names: Mapping[str, str],
    ) -> TopLevelBlockDef:
        block_id = f"{module_name}.__block__.{block_index}"
        return TopLevelBlockDef(
            block_id=block_id,
            body=tuple(
                node
                for stmt in statements
                if (node := self._lower_stmt(stmt, source=source, function_names=function_names))
                is not None
            ),
            source_span=self._span_for_statements(statements),
            metadata={"source_text": "\n".join(self._segment(source, stmt) for stmt in statements)},
        )

    def _lower_stmt(
        self,
        stmt: ast.stmt,
        *,
        source: str,
        function_names: Mapping[str, str],
    ) -> object | None:
        if isinstance(stmt, ast.Assign):
            if len(stmt.targets) != 1:
                return OpaqueCallNode(
                    callee="assign",
                    reason="multi_target_assign",
                    source_span=self._span(stmt),
                    metadata={"source_text": self._segment(source, stmt)},
                )
            return AssignNode(
                target=self._assign_target_name(stmt.targets[0], source=source),
                value=self._lower_expr(stmt.value, source=source, function_names=function_names),
                source_span=self._span(stmt),
                metadata={"source_text": self._segment(source, stmt)},
            )
        if isinstance(stmt, ast.Expr):
            return self._lower_expr(stmt.value, source=source, function_names=function_names)
        if isinstance(stmt, ast.Return):
            value = (
                self._lower_expr(stmt.value, source=source, function_names=function_names)
                if stmt.value is not None
                else LiteralNode(value=None, value_type="none", source_span=self._span(stmt))
            )
            return ExprNode(
                kind="return",
                callee="return",
                args=(value,),
                source_span=self._span(stmt),
                metadata={"source_text": self._segment(source, stmt)},
            )
        return OpaqueCallNode(
            callee=type(stmt).__name__,
            reason="unsupported_stmt",
            source_span=self._span(stmt),
            metadata={"source_text": self._segment(source, stmt)},
        )

    def _lower_expr(
        self,
        expr: ast.expr,
        *,
        source: str,
        function_names: Mapping[str, str],
    ) -> object:
        if isinstance(expr, ast.Call):
            return self._lower_call(expr, source=source, function_names=function_names)
        if isinstance(expr, ast.Constant):
            return LiteralNode(value=expr.value, value_type=type(expr.value).__name__, source_span=self._span(expr))
        if isinstance(expr, ast.Name):
            return NameRefNode(name=expr.id, source_span=self._span(expr))
        if isinstance(expr, ast.Attribute):
            return NameRefNode(
                name=self._resolve_attr_name(expr) or self._segment(source, expr),
                source_span=self._span(expr),
            )
        return LiteralNode(value=self._segment(source, expr), value_type="expr_source", source_span=self._span(expr))

    def _lower_call(
        self,
        call: ast.Call,
        *,
        source: str,
        function_names: Mapping[str, str],
    ) -> object:
        source_span = self._span(call)
        args = tuple(self._lower_expr(arg, source=source, function_names=function_names) for arg in call.args)
        keywords = {
            kw.arg or "**": self._lower_expr(kw.value, source=source, function_names=function_names)
            for kw in call.keywords
        }
        metadata = {"source_text": self._segment(source, call)}
        if self._is_session_init_call(call):
            return self._lower_session_init_call(
                call,
                source=source,
                source_span=source_span,
                function_names=function_names,
                metadata=metadata,
            )
        callee = self._resolve_call_name(call.func) or self._segment(source, call.func)
        if callee in function_names:
            return CallNode(
                callee=function_names[callee],
                args=args,
                keywords=keywords,
                source_span=source_span,
                metadata={**metadata, "callee": function_names[callee]},
            )
        translation = self.registry.classify(
            callee,
            args=args,
            keywords=keywords,
            source_span=source_span,
            metadata={**metadata, "callee": callee},
        )
        if translation is not None:
            return translation.node
        return OpaqueCallNode(
            callee=callee,
            args=args,
            keywords=keywords,
            reason="unregistered_call",
            source_span=source_span,
            metadata=metadata,
        )

    def _lower_session_init_call(
        self,
        call: ast.Call,
        *,
        source: str,
        source_span: SourceSpan | None,
        function_names: Mapping[str, str],
        metadata: Mapping[str, object],
    ) -> PrimitiveNode:
        """把 `CHun.script(...).start()` 降成可执行的 session_init。"""
        base_call = call.func.value
        assert isinstance(base_call, ast.Call)
        payload = (
            self._lower_expr(base_call.args[0], source=source, function_names=function_names)
            if base_call.args
            else None
        )
        launcher_keywords = {
            kw.arg or "**": self._lower_expr(kw.value, source=source, function_names=function_names)
            for kw in base_call.keywords
        }
        source_file = Path(self._current_filename).resolve() if self._current_filename != "<memory>" else None
        if source_file is not None and "cwd" not in launcher_keywords:
            # 导出的 transcript 允许跨 cwd 复用，因此默认把 exp 所在目录固定下来。
            launcher_keywords["cwd"] = LiteralNode(
                value=str(source_file.parent),
                value_type="str",
                source_span=source_span,
            )
        return PrimitiveNode(
            kind="session_init",
            payload=payload,
            keywords=launcher_keywords,
            source_span=source_span,
            metadata=metadata,
        )

    def _lower_import(self, stmt: ast.Import | ast.ImportFrom) -> list[ImportRef]:
        refs: list[ImportRef] = []
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                refs.append(
                    ImportRef(module=None, name=alias.name, alias=alias.asname, kind="import", source_span=self._span(stmt))
                )
            return refs
        for alias in stmt.names:
            refs.append(
                ImportRef(
                    module=stmt.module,
                    name=alias.name,
                    alias=alias.asname,
                    kind="from",
                    level=stmt.level,
                    source_span=self._span(stmt),
                )
            )
        return refs

    def _expand_body(
        self,
        body: Sequence[object],
        *,
        ir: ExpActionIR,
        call_stack: tuple[str, ...],
        depth: int,
        max_expand_depth: int,
    ) -> tuple[object, ...]:
        expanded: list[object] = []
        for node in body:
            if isinstance(node, CallNode):
                expanded.extend(self._expand_call_node(node, ir=ir, call_stack=call_stack, depth=depth, max_expand_depth=max_expand_depth))
                continue
            if isinstance(node, AssignNode) and isinstance(node.value, CallNode):
                expanded.extend(self._expand_call_node(node.value, ir=ir, call_stack=call_stack, depth=depth, max_expand_depth=max_expand_depth))
                expanded.append(
                    AssignNode(
                        target=node.target,
                        value=OpaqueCallNode(
                            callee=node.value.callee,
                            args=node.value.args,
                            keywords=node.value.keywords,
                            reason="expanded_call_result",
                            source_span=node.value.source_span,
                            metadata={"expanded": True},
                        ),
                        source_span=node.source_span,
                        metadata=node.metadata,
                    )
                )
                continue
            if isinstance(node, AssignNode) and isinstance(node.value, PrimitiveNode):
                expanded.extend(self.registry.expand_macro(node.value))
                expanded.append(node)
                continue
            if isinstance(node, PrimitiveNode):
                expanded.extend(self.registry.expand_macro(node))
                continue
            expanded.append(node)
        return tuple(expanded)

    def _expand_call_node(
        self,
        node: CallNode,
        *,
        ir: ExpActionIR,
        call_stack: tuple[str, ...],
        depth: int,
        max_expand_depth: int,
    ) -> tuple[object, ...]:
        if node.callee in call_stack:
            return (RecursiveCallNode(callee=node.callee, cycle=call_stack + (node.callee,), source_span=node.source_span, metadata=node.metadata),)
        if depth >= max_expand_depth:
            return (
                OpaqueCallNode(
                    callee=node.callee,
                    args=node.args,
                    keywords=node.keywords,
                    reason="max_expand_depth",
                    truncated=True,
                    source_span=node.source_span,
                    metadata=node.metadata,
                ),
            )
        action = ir.action_map.get(node.callee)
        if action is None:
            return (node,)
        return (
            PrimitiveNode(
                kind="checkpoint",
                payload=node.callee,
                args=(LiteralNode(value=node.callee, value_type="str"),),
                source_span=node.source_span,
                metadata={"expanded_action": node.callee},
            ),
        ) + self._expand_body(
            tuple(getattr(action, "body")),
            ir=ir,
            call_stack=call_stack + (node.callee,),
            depth=depth + 1,
            max_expand_depth=max_expand_depth,
        )

    def _node_to_transcript(self, node: object, *, source_action: str) -> tuple[WorkflowPrimitive, ...]:
        if isinstance(node, PrimitiveNode):
            return self._primitive_to_transcript(node, source_action=source_action)
        return ()

    def _primitive_to_transcript(self, node: PrimitiveNode, *, source_action: str) -> tuple[WorkflowPrimitive, ...]:
        if node.kind == "checkpoint":
            return (
                WorkflowPrimitive(
                    kind="checkpoint",
                    checkpoint=WorkflowCheckpoint(
                        name=str(node.payload),
                        source_action=source_action,
                        source_node=node.kind,
                        metadata=node.metadata,
                    ),
                    source_action=source_action,
                    source_node=node.kind,
                    metadata=node.metadata,
                ),
            )
        if node.kind in {"send", "sendline", "expect", "recv", "session_init"}:
            resolved_metadata = dict(node.metadata)
            if node.kind == "session_init":
                resolved_metadata["launcher_kwargs"] = self._resolve_runtime_mapping(node.keywords)
            return (
                WorkflowPrimitive(
                    kind=node.kind,
                    payload=self._resolve_runtime_value(node.payload),
                    args=tuple(self._resolve_runtime_value(arg) for arg in node.args),
                    source_action=source_action,
                    source_node=node.kind,
                    metadata={**resolved_metadata, "payload_expr": node.payload},
                ),
            )
        return ()

    @staticmethod
    def _resolve_runtime_value(value: object | None) -> object | None:
        if isinstance(value, ExprNode) and value.evaluated:
            return value.resolved_value
        if isinstance(value, LiteralNode):
            return value.value
        if isinstance(value, NameRefNode):
            return value.name
        return value

    def _resolve_runtime_mapping(self, mapping: Mapping[str, object]) -> Mapping[str, object]:
        return {key: self._resolve_runtime_value(value) for key, value in mapping.items()}

    @staticmethod
    def _resolve_attr_name(node: ast.Attribute) -> str | None:
        parts = [node.attr]
        current = node.value
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
            return ".".join(reversed(parts))
        return None

    def _resolve_call_name(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return self._resolve_attr_name(node)
        return None

    def _is_session_init_call(self, call: ast.Call) -> bool:
        if not isinstance(call.func, ast.Attribute) or call.func.attr != "start":
            return False
        if not isinstance(call.func.value, ast.Call):
            return False
        base_name = self._resolve_call_name(call.func.value.func)
        return base_name == "CHun.script" or (base_name is not None and base_name.endswith(".script"))

    @staticmethod
    def _assign_target_name(target: ast.expr, *, source: str) -> str:
        if isinstance(target, ast.Name):
            return target.id
        if isinstance(target, ast.Attribute):
            return ExploitWorkflowCompiler._resolve_attr_name(target) or ast.get_source_segment(source, target) or "<attr>"
        return ast.get_source_segment(source, target) or "<target>"

    @staticmethod
    def _segment(source: str, node: ast.AST) -> str:
        return ast.get_source_segment(source, node) or ""

    @staticmethod
    def _span(node: ast.AST) -> SourceSpan | None:
        lineno = getattr(node, "lineno", None)
        end_lineno = getattr(node, "end_lineno", None)
        if lineno is None or end_lineno is None:
            return None
        return SourceSpan(
            lineno=int(lineno),
            end_lineno=int(end_lineno),
            col_offset=int(getattr(node, "col_offset", 0)),
            end_col_offset=int(getattr(node, "end_col_offset", 0)),
        )

    @staticmethod
    def _span_for_statements(statements: Sequence[ast.stmt]) -> SourceSpan | None:
        if not statements:
            return None
        start = ExploitWorkflowCompiler._span(statements[0])
        end = ExploitWorkflowCompiler._span(statements[-1])
        if start is None or end is None:
            return None
        return SourceSpan(
            lineno=start.lineno,
            end_lineno=end.end_lineno,
            col_offset=start.col_offset,
            end_col_offset=end.end_col_offset,
        )

    def _span_for_module(self, module: ast.Module) -> SourceSpan | None:
        return self._span_for_statements(module.body)


__all__ = ["ExploitWorkflowCompiler"]
