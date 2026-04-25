"""CHun 命令行入口。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .core.cache import CACHE_SCHEMA_VERSION, default_cache_dir, file_cache_key, file_sha256
from .core.models import AnalysisNode, CallNode, ExprNode, LiteralNode, NameRefNode, OpaqueCallNode, WorkflowTranscript
from .core.workflow import ExploitWorkflowCompiler, WorkflowExecutor, WorkflowJsonCodec


DESCRIPTION = "CHun 命令行工具。"


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器。"""
    parser = argparse.ArgumentParser(prog="chun", description=DESCRIPTION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    info_parser = subparsers.add_parser("info", help="查看包和工作区信息")
    info_parser.add_argument("--cwd", default=".", help="要检查的工作目录")

    cache_parser = subparsers.add_parser("cache", help="查看脚本缓存状态")
    cache_subparsers = cache_parser.add_subparsers(dest="cache_command", required=True)

    cache_state_parser = cache_subparsers.add_parser(
        "state",
        help="查看指定 binary/libc 的 cache 命中状态",
    )
    cache_state_parser.add_argument("path", help="目标 binary 或 libc 文件路径")
    cache_state_parser.add_argument(
        "--cache-dir",
        help="指定缓存目录；默认按 CHUN_CACHE_DIR / XDG_CACHE_HOME / ~/.cache/chun 解析",
    )

    workflow_parser = subparsers.add_parser("workflow", help="导出、查看和执行 workflow")
    workflow_subparsers = workflow_parser.add_subparsers(dest="workflow_command", required=True)

    export_parser = workflow_subparsers.add_parser("export", help="把 exp 脚本导出成 action IR 与 workflow transcript")
    export_parser.add_argument("exp_path", help="要编译的 exploit 脚本路径")
    export_parser.add_argument("--entry", help="指定单个入口 action；默认导出整份模块 transcript")
    export_parser.add_argument("--out-dir", help="导出目录；默认落到 exp 同目录")

    show_parser = workflow_subparsers.add_parser("show", help="查看 exp 脚本的 workflow 摘要")
    show_parser.add_argument("exp_path", help="要分析的 exploit 脚本路径")
    show_parser.add_argument("--entry", help="指定单个入口 action；默认按整份模块摘要展示")

    run_parser = workflow_subparsers.add_parser("run", help="执行已导出的 workflow transcript")
    run_parser.add_argument("workflow_path", help="workflow transcript JSON 文件路径")

    return parser


def cmd_info(cwd: str) -> int:
    """输出工作区信息，便于脚本化检查。"""
    path = Path(cwd).resolve()
    print(f"chun 工作区: {path}")
    print("状态: 可用")
    return 0


def cmd_cache_state(path: str, *, cache_dir: str | None = None) -> int:
    target = Path(path).expanduser()
    if not target.exists() or not target.is_file():
        print(f"error: target file not found: {target.resolve()}")
        return 2
    target = target.resolve()

    cache_root = (
        Path(cache_dir).expanduser().resolve()
        if cache_dir is not None
        else default_cache_dir().resolve()
    )
    target_sha = file_sha256(target)

    elf_key = file_cache_key(target, namespace="elf", schema=CACHE_SCHEMA_VERSION)
    libc_key = file_cache_key(target, namespace="libc", schema=CACHE_SCHEMA_VERSION)
    elf_cache_path = cache_root / "elf" / f"{elf_key}.json"
    libc_cache_path = cache_root / "libc" / f"{libc_key}.json"

    elf_record = _load_cache_json(elf_cache_path)
    libc_record = _load_cache_json(libc_cache_path)
    if libc_record is None and isinstance(elf_record, dict):
        linked = _resolve_linked_libc_cache(cache_root=cache_root, elf_record=elf_record)
        if linked is not None:
            libc_cache_path, libc_record = linked
    gadget_records = _load_gadget_records(cache_root=cache_root, target_sha=target_sha)

    print(f"cache_root: {cache_root}")
    print(f"schema: {CACHE_SCHEMA_VERSION}")
    print(f"target: {target}")
    print(f"sha256: {target_sha}")
    print(
        f"elf: {'hit' if elf_record is not None else 'miss'}"
        + (
            f" path={elf_cache_path}"
            if elf_record is not None
            else ""
        )
    )
    if isinstance(elf_record, dict):
        print(
            "elf.meta: "
            f"arch={elf_record.get('arch')} "
            f"bits={elf_record.get('bits')} "
            f"pie={elf_record.get('pie')} "
            f"mode={elf_record.get('address_mode')} "
            f"symbols={_mapping_len(elf_record.get('symbols'))} "
            f"got={_mapping_len(elf_record.get('got'))} "
            f"plt={_mapping_len(elf_record.get('plt'))}"
        )
        _print_elf_detail_entries(elf_record)

    print(
        f"libc: {'hit' if libc_record is not None else 'miss'}"
        + (
            f" path={libc_cache_path}"
            if libc_record is not None
            else ""
        )
    )
    if isinstance(libc_record, dict):
        print(
            "libc.meta: "
            f"source={libc_record.get('source')} "
            f"trusted={libc_record.get('trusted')} "
            f"usable_for_remote={libc_record.get('usable_for_remote')} "
            f"core_symbols={_mapping_len(libc_record.get('core_symbols'))} "
            f"extra_symbols={_mapping_len(libc_record.get('extra_symbols'))} "
            f"strings={_mapping_len(libc_record.get('strings'))}"
        )

    if not gadget_records:
        print("gadget: miss records=0 total_queries=0 found=0 not_found=0")
        return 0
    total_queries = 0
    total_found = 0
    total_missing = 0
    for record in gadget_records:
        queries = record.get("queries")
        if not isinstance(queries, dict):
            continue
        total_queries += len(queries)
        for query in queries.values():
            if not isinstance(query, dict):
                continue
            if bool(query.get("found")):
                total_found += 1
            else:
                total_missing += 1
    print(
        "gadget: "
        f"hit records={len(gadget_records)} "
        f"total_queries={total_queries} "
        f"found={total_found} "
        f"not_found={total_missing}"
    )
    for index, record in enumerate(gadget_records, start=1):
        queries = record.get("queries")
        query_count = len(queries) if isinstance(queries, dict) else 0
        print(
            f"gadget.record[{index}]: "
            f"source={record.get('source')} "
            f"arch={record.get('arch')} "
            f"bits={record.get('bits')} "
            f"pwntools={record.get('pwntools_version')} "
            f"queries={query_count}"
        )
        _print_gadget_detail_entries(index=index, record=record)
    return 0


def cmd_workflow_export(exp_path: str, *, entry: str | None = None, out_dir: str | None = None) -> int:
    compiler = ExploitWorkflowCompiler()
    source_path = Path(exp_path).resolve()
    module_name = source_path.stem
    ir = compiler.compile_path(source_path, module_name=module_name)
    entry_action = _normalize_entry(entry, module_name=module_name)
    transcript = (
        compiler.build_transcript(ir, entry_action)
        if entry_action is not None
        else compiler.build_module_transcript(ir)
    )
    action_ir_path, workflow_path = _resolve_export_paths(source_path, out_dir=out_dir)
    WorkflowJsonCodec.dump_action_ir(ir, action_ir_path)
    WorkflowJsonCodec.dump_transcript(transcript, workflow_path)
    print(f"action_ir: {action_ir_path}")
    print(f"workflow: {workflow_path}")
    print(f"entry_action: {transcript.entry_action}")
    print(f"primitive_count: {len(transcript.primitives)}")
    _print_workflow_payload_warnings(transcript)
    return 0


def cmd_workflow_show(exp_path: str, *, entry: str | None = None) -> int:
    compiler = ExploitWorkflowCompiler()
    source_path = Path(exp_path).resolve()
    module_name = source_path.stem
    ir = compiler.compile_path(source_path, module_name=module_name)
    entry_action = _normalize_entry(entry, module_name=module_name)
    transcript = (
        compiler.build_transcript(ir, entry_action)
        if entry_action is not None
        else compiler.build_module_transcript(ir)
    )
    print(f"source: {source_path}")
    print(f"module: {ir.module_name}")
    print(f"functions: {len(ir.functions)}")
    print(f"top_level_blocks: {len(ir.top_level_blocks)}")
    print(f"entrypoints: {', '.join(ir.entrypoints)}")
    print(f"transcript_entry: {transcript.entry_action}")
    print(f"primitive_count: {len(transcript.primitives)}")
    _print_workflow_payload_warnings(transcript)
    return 0


def cmd_workflow_run(workflow_path: str) -> int:
    transcript = WorkflowJsonCodec.load_transcript(workflow_path)
    executor = WorkflowExecutor()
    captured_session: dict[str, object] = {}

    def _capture_session(session: object, _result: object) -> None:
        captured_session["session"] = session

    result = executor.execute(transcript, on_complete=_capture_session)
    print(f"entry_action: {result.transcript.entry_action}")
    print(f"total_steps: {result.total_steps}")
    if result.final_checkpoint is not None:
        print(f"final_checkpoint: {result.final_checkpoint.name}")
    else:
        print("final_checkpoint: <none>")
    session = captured_session.get("session")
    if session is not None:
        session.rec.show(layers=("context", "facts"), detail="standard", emit="info")
    return 0


def _resolve_export_paths(exp_path: Path, *, out_dir: str | None = None) -> tuple[Path, Path]:
    base_dir = Path(out_dir).resolve() if out_dir is not None else exp_path.parent
    stem = exp_path.stem
    return (
        base_dir / f"{stem}.action_ir.json",
        base_dir / f"{stem}.workflow.json",
    )


def _normalize_entry(entry: str | None, *, module_name: str) -> str | None:
    if entry is None:
        return None
    if "." in entry:
        return entry
    return f"{module_name}.{entry}"


def _unresolved_payload_preview(payload: object) -> str | None:
    source_text = getattr(payload, "metadata", {}).get("source_text")
    if isinstance(source_text, str) and source_text:
        return source_text
    if isinstance(payload, LiteralNode) and payload.value_type == "expr_source":
        return str(payload.value)
    callee = getattr(payload, "callee", None)
    if isinstance(callee, str) and callee:
        return callee
    return None


def _find_unresolved_payloads(transcript: WorkflowTranscript) -> list[tuple[int, str, str]]:
    unresolved: list[tuple[int, str, str]] = []
    for index, primitive in enumerate(transcript.primitives):
        if primitive.kind not in {"session_init", "send", "sendline", "expect", "assign", "call"}:
            continue
        payload = primitive.payload
        if _workflow_payload_supported(payload):
            continue
        preview = _unresolved_payload_preview(payload) or type(payload).__name__
        unresolved.append((index, primitive.kind, preview))
    return unresolved


def _workflow_payload_supported(payload: object) -> bool:
    if isinstance(payload, (bytes, bytearray, str, int, float, bool, type(None))):
        return True
    if isinstance(payload, LiteralNode):
        return True
    if isinstance(payload, NameRefNode):
        return True
    if isinstance(payload, ExprNode):
        return payload.evaluated or bool(payload.metadata.get("source_text"))
    if isinstance(payload, (AnalysisNode, OpaqueCallNode, CallNode)):
        return bool(payload.metadata.get("source_text"))
    return False


def _print_workflow_payload_warnings(transcript: WorkflowTranscript) -> None:
    unresolved = _find_unresolved_payloads(transcript)
    if not unresolved:
        return
    print(f"warning: found {len(unresolved)} unresolved workflow payload(s); replay may fail")
    for index, kind, preview in unresolved[:5]:
        print(f"  - step {index} [{kind}]: {preview}")


def _mapping_len(value: object) -> int:
    if isinstance(value, dict):
        return len(value)
    return 0


def _load_cache_json(path: Path) -> dict[str, Any] | None:
    if not path.exists() or not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None
    if not isinstance(payload, dict):
        return None
    return payload


def _load_gadget_records(*, cache_root: Path, target_sha: str) -> list[dict[str, Any]]:
    namespace_dir = cache_root / "gadget"
    if not namespace_dir.exists() or not namespace_dir.is_dir():
        return []

    records: list[dict[str, Any]] = []
    for cache_file in sorted(namespace_dir.glob(f"{target_sha}-gadget-schema*.json")):
        payload = _load_cache_json(cache_file)
        if payload is None:
            continue
        if payload.get("schema") != CACHE_SCHEMA_VERSION:
            continue
        if payload.get("sha256") != target_sha:
            continue
        records.append(payload)
    return records


def _resolve_linked_libc_cache(
    *,
    cache_root: Path,
    elf_record: dict[str, Any],
) -> tuple[Path, dict[str, Any]] | None:
    linked_sha = elf_record.get("linked_libc_sha256")
    if isinstance(linked_sha, str) and linked_sha:
        key = f"{linked_sha}-libc-schema{CACHE_SCHEMA_VERSION}"
        linked_cache_path = cache_root / "libc" / f"{key}.json"
        payload = _load_cache_json(linked_cache_path)
        if payload is not None:
            return linked_cache_path, payload

    linked_path = elf_record.get("linked_libc_path")
    if not isinstance(linked_path, str) or not linked_path:
        return None

    key = file_cache_key(linked_path, namespace="libc", schema=CACHE_SCHEMA_VERSION)
    linked_cache_path = cache_root / "libc" / f"{key}.json"
    payload = _load_cache_json(linked_cache_path)
    if payload is None:
        return None
    if isinstance(linked_sha, str) and linked_sha:
        payload_sha = payload.get("sha256")
        if isinstance(payload_sha, str) and payload_sha != linked_sha:
            return None
    return linked_cache_path, payload


def _print_elf_detail_entries(record: dict[str, Any]) -> None:
    for table in ("symbols", "got", "plt", "sections"):
        mapping = record.get(table)
        if not isinstance(mapping, dict) or not mapping:
            print(f"elf.{table}: <empty>")
            continue
        for key in sorted(mapping.keys()):
            value = mapping.get(key)
            print(f"elf.{table}[{key}]={_format_address(value)}")


def _print_gadget_detail_entries(*, index: int, record: dict[str, Any]) -> None:
    queries = record.get("queries")
    if not isinstance(queries, dict) or not queries:
        print(f"gadget.record[{index}].queries: <empty>")
        return
    for token in sorted(queries.keys()):
        query = queries.get(token)
        if not isinstance(query, dict):
            continue
        found = bool(query.get("found"))
        value = query.get("value")
        mode = str(query.get("address_mode", "offset"))
        print(
            f"gadget.query[{index}][{token}]: "
            f"found={str(found).lower()} "
            f"value={_format_address(value)} "
            f"mode={mode}"
        )


def _format_address(value: object) -> str:
    if isinstance(value, int):
        return hex(value)
    if value is None:
        return "null"
    return str(value)


def main(argv: list[str] | None = None) -> int:
    """运行 CLI 并返回退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "info":
        return cmd_info(args.cwd)
    if args.command == "cache":
        if args.cache_command == "state":
            return cmd_cache_state(args.path, cache_dir=args.cache_dir)
    if args.command == "workflow":
        if args.workflow_command == "export":
            return cmd_workflow_export(args.exp_path, entry=args.entry, out_dir=args.out_dir)
        if args.workflow_command == "show":
            return cmd_workflow_show(args.exp_path, entry=args.entry)
        if args.workflow_command == "run":
            return cmd_workflow_run(args.workflow_path)

    parser.error(f"未知命令: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
