# CHun

CHun 是面向长期维护的 Pwn 框架骨架，采用 `src/` layout、`pyproject.toml` 主配置、统一状态中心（`PwnRegistry`）和门面工具类（`MyTool`/`Tool`）。

## 命名与导入口径

- 仓库名：`CHun`
- Python 包名：`chun`
- 推荐导入：

```python
from chun import Tool, Blind, Reg
```

## 目录结构

```text
CHun/
├── pyproject.toml
├── setup.py
├── my_tools.py
├── src/
│   └── chun/
│       ├── __init__.py
│       ├── _compat.py
│       ├── cli.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── tool.py
│       │   ├── registry.py
│       │   └── target.py
│       ├── plugins/
│       │   ├── __init__.py
│       │   ├── blind.py
│       │   ├── fmt.py
│       │   └── heap.py
│       ├── utils/
│       │   ├── __init__.py
│       │   ├── display.py
│       │   └── misc.py
│       └── templates/
│           ├── exp.py.tpl
│           └── blind_fmt.py.tpl
├── tests/
│   ├── test_blind.py
│   ├── test_registry.py
│   ├── test_target.py
│   └── test_tool.py
└── docs/
    ├── design.md
    └── migration.md
```

## 安装

```bash
pip install -e .
```

## 快速使用

```python
from chun import Tool

p = Tool("./challenge", remote_mode=False)
io = p.start()

p.api.record_libc_symbol("puts", 0x7ffff7a5f5e0)
p.api.infer_libc_base_from("puts")
p.show()  # 默认简洁视图
# p.show(verbose=True)  # 详细视图：kind/source/confidence
```

## 推荐接口（普通打题）

- `Tool(...)`
- `start()` / `connect()`
- `api.record_libc_symbol()` / `api.record_stack_ptr()` / `api.record_heap_ptr()`
- `api.record_base()` / `api.record_derived()` / `api.record_note()`
- `api.infer_libc_base_from()` / `api.infer_pie_base_from()`
- `show()`（简洁）/ `show(verbose=True)`（详细）

## 高级接口（框架扩展/调试）

- `Reg` / `PwnRegistry`
- `add_log()` / `infer_base()` / `derive_base()`
- `RecordKind` / `RecordSource`
- `BaseCandidate`

## Blind 模式

```python
from chun import Tool


def io_factory():
    return ...


def interact(io, payload: bytes) -> bytes | None:
    io.sendline(payload)
    return io.recvline(timeout=1)


p = Tool("./challenge")
blind = p.new_blind_tool(io_factory=io_factory, interact_func=interact)
blind.dump_stack_ptrs(1, 40)
p.show()
```

## 兼容说明

历史脚本可继续使用：

```python
from my_tools import MyTool, BlindFmtTool
```

其中 `UnifiedPwn` 在兼容层里映射到 `Tool`。
