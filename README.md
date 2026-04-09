# CHun

CHun: a lightweight and evolving Pwn toolkit by Chenhun.

CHun 当前已进入第三轮收口阶段：在前两轮的 transport + registry/session 地基之上，已经固定了 pwntools / GDB bridge、DynELF 解析链路和 core dump 分析入口的公开用法。

## 核心特性

- 会话入口：`CHun.process()` / `CHun.remote()` / `CHun.ssh_process()`
- 脚本模式入口：`CHun.script()`，保留人工写 exp 时的快速切换手感
- Web 方向 transport：`CHun.http()` / `CHun.websocket()`
- Blind transport：`CHun.blind()` + `BlindReconnectTransport`
- 会话内统一事实层：`session.registry` / `session.rec`
- 最小 inference 入口：`session.infer`
- 调试与解析入口：`session.dbg` / `session.gdb_mi` / `session.resolve` / `session.crash`

## 当前稳定公开接口

- 顶层工厂：`CHun.process()` / `CHun.remote()` / `CHun.ssh_process()` / `CHun.http()` / `CHun.websocket()` / `CHun.blind()`
- 脚本 facade：`CHun.script()`
- 会话入口：`session.io` / `session.registry` / `session.rec` / `session.infer`
- 调试与解析：`session.dbg` / `session.gdb_mi` / `session.resolve` / `session.crash`

## 安装

```bash
python -m pip install -e .
```

## 最小使用示例

```python
from chun import CHun

p = CHun.process("./challenge")
p.rec.record_symbol_leak("puts", 0x7F1234580000, source="got")
result = p.infer.libc_base_from_symbol_leak("puts", symbol_offset=0x80000)
print(hex(result.aligned_base))
```

## 多种连接方式

```python
from chun import CHun

local = CHun.process("./challenge")
remote = CHun.remote("127.0.0.1", 31337, binary="./challenge")
http = CHun.http("http://127.0.0.1:8000")
ws = CHun.websocket("ws://127.0.0.1:9001")

resp = http.io.request("GET", "/health")
print(resp)

ws.io.send_message("ping")
print(ws.io.recv_message())
```

## 脚本模式 facade

显式工厂适合自动化、模板和 agent；`CHun.script()` 只给人工写 exp 时保留快速切换手感。

初始化时会顺手完成：

- `context.log_level` / `context.terminal`
- `t.elf = context.binary = ELF(binary, checksec=False)`
- `t.libc = ELF(libc, checksec=False)`，未显式传入时会尝试从 `t.elf.libc` 自动拿

```python
from chun import CHun
from pwn import *

t = CHun.script("./challenge", host="example.com", port=31337, libc="./libc.so.6")
s = t.start()
io = t.io

t.gdb("""
b *main
c
""")

io.sendlineafter(b"menu> ", b"1")
```

命令行切换方式：

```bash
python exp.py
python exp.py GDB
python exp.py REMOTE
python exp.py REMOTE GDB
```

## Blind reconnect 示例

```python
from chun import CHun

blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
response = blind.io.exchange(
    b"%7$p",
    receive=lambda io: io.recvuntil(b"\n"),
    newline=True,
)
print(response)
```

## Session + Registry 示例

```python
from chun import CHun, RecordDomain

session = CHun.process("./challenge")
session.rec.set_context("libc.path", "/glibc/libc.so.6", domain=RecordDomain.LIBC)
session.rec.record_artifact("payload.stage1", b"AAAA", tags=["payload"])
```

## 最小 workflow 示例

```python
from chun import CHun

session = CHun.process("./challenge")

# ret2libc
session.rec.record_symbol_leak("puts", 0x7F1234580000, source="got")
# session.resolve.libc_base_from_elf_symbol("puts", libc_elf=libc, symbol="puts")

# 交互式 GDB attach
# session.dbg.attach(script="b *main\nc")

# blind leak -> DynELF
result = session.resolve.symbol_via_dynelf(
    "system",
    leak_primitive=lambda addr, size=8: b"\x00" * size,
    pointer=0x601018,
    lib="libc",
)
print(hex(result.address))
```

## 文档入口

- 文档首页：[`docs/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/index.md)
- MkDocs 配置：[`mkdocs.yml`](/Users/zaochuan/Documents/code/python/CHun_pwn/mkdocs.yml)
- API 总览：[`docs/api/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/index.md)

文档主维护位置在 `docs/`，README 只保留项目入口、安装与最小示例。

## 当前模块概览

- `src/chun/facade.py`：`CHun` 顶层工厂入口
- `src/chun/core`：`session.py`、`models/`、`errors.py`、`registry/`、`inference/`、`resolve/`、`analysis/`
- `src/chun/bridges`：GDB / pwntools 相关 bridge
- `src/chun/transports`：transport 实现与组装工厂
- `src/chun/plugins`：后续 blind/fmt/heap 插件骨架
- `src/chun/utils`：`display.py`、`misc.py`

当前阶段刻意未做 fmt / heap / template 主体，以及 pwngdb / pwndbg 深集成。
