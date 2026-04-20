"""CHun 命令行入口。"""

from __future__ import annotations

import argparse
from pathlib import Path

from .core.workflow import ExploitWorkflowCompiler, WorkflowExecutor, WorkflowJsonCodec


DESCRIPTION = "CHun 命令行工具。"


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器。"""
    parser = argparse.ArgumentParser(prog="chun", description=DESCRIPTION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    info_parser = subparsers.add_parser("info", help="查看包和工作区信息")
    info_parser.add_argument("--cwd", default=".", help="要检查的工作目录")

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
    return 0


def cmd_workflow_run(workflow_path: str) -> int:
    transcript = WorkflowJsonCodec.load_transcript(workflow_path)
    executor = WorkflowExecutor()
    result = executor.execute(transcript)
    print(f"entry_action: {result.transcript.entry_action}")
    print(f"total_steps: {result.total_steps}")
    if result.final_checkpoint is not None:
        print(f"final_checkpoint: {result.final_checkpoint.name}")
    else:
        print("final_checkpoint: <none>")
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


def main(argv: list[str] | None = None) -> int:
    """运行 CLI 并返回退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "info":
        return cmd_info(args.cwd)
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
