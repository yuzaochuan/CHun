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

p.add_log("puts@libc", 0x7ffff7a5f5e0)
p.derive_base("puts@libc", p.libc.sym["puts"], base_name="libc")
p.show()
```

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
