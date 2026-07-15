from __future__ import annotations

from chun import (
    AnalysisNode,
    AssignNode,
    CallNode,
    ExploitWorkflowCompiler,
    ExprNode,
    OpaqueCallNode,
    PrimitiveNode,
    RecursiveCallNode,
)


def build_compiler() -> ExploitWorkflowCompiler:
    return ExploitWorkflowCompiler()


def test_compile_source_splits_module_by_def_boundaries() -> None:
    source = """
from chun import CHun
from pwn import flat

s = CHun.script("./fm").start()
s.sendline(b"hi")

def itob(num):
    return str(num).encode()

def menu(num):
    s.sendline(str(num))

menu(1)
payload = flat(1, 2, 3)

def test():
    s.recv()
"""

    ir = build_compiler().compile_source(source, module_name="exp")

    assert len(ir.imports.refs) == 2
    assert [block.block_id for block in ir.top_level_blocks] == [
        "exp.__block__.0",
        "exp.__block__.1",
    ]
    assert [func.action_id for func in ir.functions] == [
        "exp.itob",
        "exp.menu",
        "exp.test",
    ]
    assert ir.entrypoints == ("exp.__block__.0", "exp.__block__.1")


def test_lowering_basic_primitives_and_current_module_call() -> None:
    source = """
from chun import CHun

s = CHun.script("./fm").start()

def menu(num):
    s.sendline(str(num))
    s.recvuntil(b"> ")
    s.sa(b"name:", b"guest")
    s.sla(b"choice:", b"1")

menu(1)
"""

    ir = build_compiler().compile_source(source, module_name="exp")
    menu = ir.action_map["exp.menu"]
    block = ir.action_map["exp.__block__.1"]

    assert isinstance(menu.body[0], PrimitiveNode)
    assert menu.body[0].kind == "sendline"
    assert isinstance(menu.body[1], PrimitiveNode)
    assert menu.body[1].kind == "expect"
    assert isinstance(menu.body[2], PrimitiveNode)
    assert menu.body[2].kind == "sendafter"
    assert isinstance(menu.body[3], PrimitiveNode)
    assert menu.body[3].kind == "sendlineafter"
    assert isinstance(block.body[0], CallNode)
    assert block.body[0].callee == "exp.menu"


def test_lowering_chun_script_start_as_session_init() -> None:
    source = """
from chun import CHun

s = CHun.script("./fm").start()
"""

    ir = build_compiler().compile_source(source, module_name="exp")
    block = ir.action_map["exp.__block__.0"]

    assert isinstance(block.body[0], AssignNode)
    assert isinstance(block.body[0].value, PrimitiveNode)
    assert block.body[0].value.kind == "session_init"


def test_session_init_transcript_keeps_binary_and_launcher_metadata(tmp_path) -> None:
    source_path = tmp_path / "exp.py"
    source_path.write_text(
        "\n".join(
            [
                "from chun import CHun",
                's = CHun.script("./fm", libc="./libc.so.6").start()',
            ]
        ),
        encoding="utf-8",
    )

    compiler = build_compiler()
    ir = compiler.compile_path(source_path, module_name="exp")
    transcript = compiler.build_module_transcript(ir)

    session_init = transcript.primitives[1]
    assert session_init.kind == "session_init"
    assert session_init.payload == "./fm"
    assert session_init.metadata["launcher_kwargs"]["libc"] == "./libc.so.6"
    assert session_init.metadata["launcher_kwargs"]["cwd"] == str(tmp_path.resolve())


def test_session_init_transcript_keeps_script_cache_kwargs(tmp_path) -> None:
    source_path = tmp_path / "exp.py"
    source_path.write_text(
        "\n".join(
            [
                "from chun import CHun",
                's = CHun.script("./fm", cache=True, cache_dir="./.chun_cache", auto_local_libc=False).start()',
            ]
        ),
        encoding="utf-8",
    )

    compiler = build_compiler()
    ir = compiler.compile_path(source_path, module_name="exp")
    transcript = compiler.build_module_transcript(ir)
    session_init = transcript.primitives[1]

    assert session_init.kind == "session_init"
    assert session_init.metadata["launcher_kwargs"]["cache"] is True
    assert session_init.metadata["launcher_kwargs"]["cache_dir"] == "./.chun_cache"
    assert session_init.metadata["launcher_kwargs"]["auto_local_libc"] is False


def test_call_classification_keeps_pure_analysis_and_opaque_separate() -> None:
    source = """
from pwn import flat

def leak():
    payload = flat(1, 2, 3)
    text = str(123)
    base = s.infer.search_libc("puts")
    data = weird(payload)
"""

    ir = build_compiler().compile_source(source, module_name="exp")
    leak = ir.action_map["exp.leak"]

    assert isinstance(leak.body[0], AssignNode)
    assert isinstance(leak.body[0].value, ExprNode)
    assert leak.body[0].value.effect == "pure"
    assert isinstance(leak.body[1].value, ExprNode)
    assert isinstance(leak.body[2].value, AnalysisNode)
    assert isinstance(leak.body[3].value, OpaqueCallNode)


def test_pure_flat_expr_keeps_structure_and_evaluated_bytes() -> None:
    source = """
from pwn import flat

def build():
    payload = flat(0x41414141, b"BC")
"""

    ir = build_compiler().compile_source(source, module_name="exp")
    build = ir.action_map["exp.build"]
    expr = build.body[0].value

    assert isinstance(expr, ExprNode)
    assert expr.callee == "flat"
    assert expr.evaluated is True
    assert expr.value_type == "bytes"
    assert expr.resolved_value is not None
    assert expr.value_summary["length"] == len(expr.resolved_value)
    assert expr.value_summary["preview_hex"]


def test_expand_action_recurses_into_current_module_functions() -> None:
    source = """
def menu(num):
    s.sendline(str(num))

def add():
    menu(1)
    s.recv()
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    expanded = compiler.expand_action(ir, "exp.add")

    assert isinstance(expanded[0], PrimitiveNode)
    assert expanded[0].kind == "checkpoint"
    assert isinstance(expanded[1], PrimitiveNode)
    assert expanded[1].kind == "sendline"
    assert isinstance(expanded[2], PrimitiveNode)
    assert expanded[2].kind == "recv"


def test_expand_action_stops_on_recursive_cycle() -> None:
    source = """
def a():
    b()

def b():
    a()
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    expanded = compiler.expand_action(ir, "exp.a", max_expand_depth=6)

    assert any(isinstance(node, RecursiveCallNode) for node in expanded)


def test_expand_action_stops_on_max_expand_depth() -> None:
    source = """
def a():
    b()

def b():
    c()

def c():
    d()

def d():
    s.sendline(b"x")
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    expanded = compiler.expand_action(ir, "exp.a", max_expand_depth=1)

    truncated = [node for node in expanded if isinstance(node, OpaqueCallNode)]
    assert truncated
    assert truncated[0].truncated is True


def test_build_transcript_normalizes_primitives_for_replay() -> None:
    source = """
def menu():
    s.sla(b"> ", b"1")
    s.recv()
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    transcript = compiler.build_transcript(ir, "exp.menu")

    assert transcript.entry_action == "exp.menu"
    assert [item.kind for item in transcript.primitives] == [
        "checkpoint",
        "expect",
        "sendline",
        "recv",
    ]
    assert transcript.primitives[2].payload == b"1"


def test_transcript_send_uses_evaluated_pure_expr_value() -> None:
    source = """
from pwn import flat

def fire():
    s.sendline(flat(0x41414141, b"BC"))
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    transcript = compiler.build_transcript(ir, "exp.fire")

    send = transcript.primitives[1]
    assert send.kind == "sendline"
    assert isinstance(send.payload, (bytes, bytearray))
    assert send.payload == b"AAAABC"
    assert isinstance(send.metadata["payload_expr"], ExprNode)


def test_transcript_send_uses_stable_pwntools_defaults_under_mutated_context() -> None:
    from pwn import context

    source = """
from pwn import flat

def fire():
    s.sendline(flat(0x41414141, b"BC"))
"""

    with context.local(bits=64):
        compiler = build_compiler()
        ir = compiler.compile_source(source, module_name="exp")
        transcript = compiler.build_transcript(ir, "exp.fire")

    send = transcript.primitives[1]
    assert send.kind == "sendline"
    assert send.payload == b"AAAABC"


def test_transcript_inlines_local_helper_return_for_sendlineafter_payload() -> None:
    source = """
def itob(num):
    return str(num).encode()

def menu(num):
    s.sla(b">> ", itob(num))

menu(1)
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    transcript = compiler.build_module_transcript(ir)

    assert [item.kind for item in transcript.primitives] == [
        "checkpoint",
        "checkpoint",
        "expect",
        "sendline",
    ]
    assert transcript.primitives[3].payload == b"1"


def test_transcript_keeps_unresolved_dynamic_payload_as_node() -> None:
    source = """
from pwn import p64

def fire():
    s.sendline(p64(s.resolve.symbol("system")))
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    transcript = compiler.build_transcript(ir, "exp.fire")

    payload = transcript.primitives[1].payload
    assert not isinstance(payload, str)
    assert isinstance(payload, ExprNode)


def test_build_module_transcript_preserves_ret2libc_runtime_flow() -> None:
    source = """
from chun import CHun
from pwn import p64

s = CHun.script("./chall").start()
leak = s.recv_leak("puts", "puts: ", offset=0)
s.infer.libc_base_from_symbol_leak("puts", s.libc.sym["puts"])
s.sendline(p64(s.resolve.symbol("system")))
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    transcript = compiler.build_module_transcript(ir)

    assert [item.kind for item in transcript.primitives] == [
        "checkpoint",
        "session_init",
        "assign",
        "call",
        "sendline",
    ]
    assert transcript.primitives[1].metadata["bind_target"] == "s"
    assert transcript.primitives[2].metadata["target"] == "leak"
    assert isinstance(transcript.primitives[2].payload, AnalysisNode)
    assert isinstance(transcript.primitives[3].payload, AnalysisNode)


def test_build_transcript_from_top_level_block_keeps_order_stable() -> None:
    source = """
s.sendline(b"A")
s.recvuntil(b"> ")
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    transcript = compiler.build_transcript(ir, "exp.__block__.0")

    assert [item.kind for item in transcript.primitives] == [
        "checkpoint",
        "sendline",
        "expect",
    ]


def test_build_module_transcript_keeps_top_level_block_order() -> None:
    source = """
s.sendline(b"A")

def menu():
    s.recvuntil(b"> ")

menu()
"""

    compiler = build_compiler()
    ir = compiler.compile_source(source, module_name="exp")
    transcript = compiler.build_module_transcript(ir)

    assert transcript.entry_action == "exp.__module__"
    assert [item.kind for item in transcript.primitives] == [
        "checkpoint",
        "sendline",
        "checkpoint",
        "checkpoint",
        "expect",
    ]
