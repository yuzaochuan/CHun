# 快速开始

## 安装前提

- Python 3.10+
- 本地 Pwn 题建议有 `pwntools` 运行环境
- Web / WebSocket 场景建议已安装项目依赖中的 `httpx` / `websockets`

## Editable install

```bash
python -m pip install -e .
```

## 最小示例

```python
from chun import CHun, RecordDomain

p = CHun.process("./challenge")
p.rec.record_symbol_leak("puts", 0x7F1234580000, domain=RecordDomain.LIBC, source="got")
result = p.infer.libc_base_from_symbol_leak("puts", symbol_offset=0x80000)
print(hex(result.aligned_base))
```

## 稳定公开入口

- `CHun.process()` / `CHun.remote()` / `CHun.ssh_process()`
- `CHun.http()` / `CHun.websocket()` / `CHun.blind()`
- `CHun.script()`：面向人工写 exp 的薄 facade
- `session.io` / `session.registry` / `session.rec` / `session.infer`
- `session.dbg` / `session.gdb_mi` / `session.resolve` / `session.crash`

## 本地 / 远程 / SSH

```python
from chun import CHun

local = CHun.process("./challenge")
remote = CHun.remote("example.com", 31337, binary="./challenge")
ssh_remote = CHun.ssh_process(
    "example.com",
    user="ctf",
    binary="/home/ctf/challenge",
)

io = remote.io
io.sendlineafter(b"menu> ", b"1")
print(io.recvuntil(b"\n"))
```

## 脚本模式快速切换

显式工厂适合模板、自动化和明确调用路径；`CHun.script()` 适合手写 exp 时保留 `start()` / `gdb()` 的旧手感。

初始化时还会默认准备：

- `context.log_level` / `context.terminal`
- `t.elf = context.binary`
- `t.libc`，若未显式传入则尝试从 `t.elf.libc` 自动获取
- `t.start()` 返回 `t` 自身，因此既支持分步写法，也支持 `t = CHun.script(...).start()`
- `t.start()` 后会通过 `session.bind_binaries()` 把 `t.elf` / `t.libc` 绑定到当前 session，并把 `binary.path`、`arch.bits`、`arch.endian`、`arch.pointer_size`、`libc.path` 等规范化信息写进 registry context
- `t.rec` / `t.resolve` / `t.dbg` 等 session 核心能力的显式入口
- `t.sla()` / `t.rl()` / `t.ia()` 等高频交互方法与 alias
- 低频 tube 方法可继续通过 fallback 使用，例如 `t.clean()`

```python
from chun import CHun
from pwn import *

t = CHun.script("./challenge", host="example.com", port=31337, libc="./libc.so.6")
t.start()

# 或者：
# t = CHun.script("./challenge", host="example.com", port=31337, libc="./libc.so.6").start()

t.gdb("b *main\nc")
t.sla(b"menu> ", b"1")
base = t.resolve.libc_base_from_elf_symbol("puts", symbol="puts")
print(hex(base.value))
```

支持的命令行模式：

```bash
python exp.py
python exp.py GDB
python exp.py REMOTE
python exp.py REMOTE GDB
```

## HTTP / WebSocket

```python
from chun import CHun

http = CHun.http("http://127.0.0.1:8000")
print(http.io.request("GET", "/health"))

ws = CHun.websocket("ws://127.0.0.1:9001")
ws.io.send_message("ping")
print(ws.io.recv_message())
```

## Blind reconnect

```python
from chun import CHun


def connection_factory():
    return CHun.remote("example.com", 31337).raw


blind = CHun.blind(connection_factory)
result = blind.io.exchange(
    b"%7$p",
    receive=lambda io: io.recvuntil(b"\n"),
    newline=True,
)
print(result)
```

## 调试与解析入口

```python
from chun import CHun

session = CHun.process("./challenge")

# 交互式 GDB
# session.dbg.attach(script="b *main\nc")

# GDB/MI
# mi_result = session.gdb_mi.execute("-gdb-version")

# DynELF
resolved = session.resolve.symbol_via_dynelf(
    "system",
    leak_primitive=lambda addr, size=8: b"\x00" * size,
    pointer=0x601018,
    lib="libc",
)
print(hex(resolved.address))
```

## 三条最小 workflow

```python
from chun import CHun

session = CHun.process("./challenge")

# ret2libc
session.rec.record_symbol_leak("puts", 0x7F1234580000, source="got")
# base = session.resolve.libc_base_from_elf_symbol("puts", libc_elf=libc, symbol="puts")
# print(hex(base.value))

# blind leak -> DynELF
blind = CHun.blind(lambda: object())
# blind.resolve.symbol_via_dynelf("system", leak_primitive=leak_func, pointer=0x601018)

# fmt planning
# session.resolve.bind_defaults(elf=elf, libc_elf=libc)
# session.rec.record_fact("libc.base", 0x7F1234500000)
# plan = session.fmt.plan_writes({"printf@got": "system"})
# print(plan.total_atoms, plan.total_tasks)
# offset = session.fmt.find_offset(loginfo=True)
# rendered = session.fmt.render_plan(plan, offset=6)
# receipts = session.fmt.execute_plan(plan, offset=6)
# print(receipts[0].response)

# script facade sugar
# s = CHun.script("./challenge").start()
# result = s.fmt.find_offset(max_slots=16)  # script mode defaults loginfo=True
# print(result.index)

# corefile -> crash facts
# session.crash.analyze("/tmp/core")
```

## 当前阶段边界

- 已落地：session 入口、transport、registry、最小 inference、debug/resolve/crash bridge、fmt 探测/规划/渲染/执行链
- 暂未实现：heap/template 主体与 pwngdb/pwndbg 深集成
