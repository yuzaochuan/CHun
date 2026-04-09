# Session API

## 顶层入口

当前主入口是 `CHun` 工厂，而不是旧 `Tool`。

```python
from chun import CHun

local = CHun.process("./challenge")
remote = CHun.remote("example.com", 31337, binary="./challenge")
http = CHun.http("http://127.0.0.1:8000")
ws = CHun.websocket("ws://127.0.0.1:9001")
blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
```

当前稳定保留的工厂方法只有：

- `CHun.process()`
- `CHun.remote()`
- `CHun.ssh_process()`
- `CHun.http()`
- `CHun.websocket()`
- `CHun.blind()`

另有一个面向人工写 exp 的薄 facade：

- `CHun.script()`

它不替代显式工厂，也不改变 `CHun.process()` / `CHun.remote()` 的语义，只负责：

- `start()`：根据 `args.REMOTE` 选择本地 `process` 或远程 `remote`
- `gdb(script="")`：根据 `args.GDB` 决定是否调用现有 `session.dbg.attach()`
- `session` / `io`：暴露当前已启动 session 与 io

显式工厂与 `CHun.script()` 在内部都会先收敛到同一套 `TargetSpec` / `TransportSpec` builder，再交给 `from_specs()` 组装 session。

并在初始化时为脚本态准备：

- `context.log_level` / `context.terminal`
- `elf`：`context.binary = ELF(binary, checksec=False)`
- `libc`：显式 `ELF(libc, checksec=False)`，或回退到 `elf.libc`

## `CHunSession`

每个工厂方法都会返回一个 `CHunSession`。第三轮它已经承载 transport、registry、最小 inference，以及调试 / 解析 / crash 分析入口：

- `target`：`TargetSpec`
- `transport_spec`：`TransportSpec`
- `transport`：实际 transport 实例
- `registry`：统一事实层
- `rec`：`registry` 的短别名
- `infer`：最小 inference 服务
- `dbg`：交互式 `PwntoolsGdbBridge`
- `gdb_mi`：结构化 `GdbMiBridge`
- `resolve`：`MemLeak` / `DynELF` / pwntools symbol 解析入口
- `crash`：`CorefileAnalyzer`
- `io`：延迟打开后的 transport 访问入口
- `raw`：底层原始连接对象

其中推荐把下面这些看作下一阶段插件开发的稳定挂接点：

- `session.registry` / `session.rec`
- `session.infer`
- `session.resolve`
- `session.crash`
- `session.dbg` / `session.gdb_mi`

## 工厂方法

- `CHun.process(binary, *, argv=None, env=None, cwd=None, log_level="info")`
- `CHun.remote(host, port, *, binary=None, timeout=None)`
- `CHun.ssh_process(host, *, user, binary, argv=None, port=22, ...)`
- `CHun.http(base_url, *, headers=None, timeout=None, follow_redirects=True, verify=True)`
- `CHun.websocket(ws_url, *, headers=None, timeout=None, connect_timeout=None)`
- `CHun.blind(connection_factory, *, timeout=None)`
- `CHun.script(binary, *, host=None, port=None, libc=None, ld=None, argv=None, env=None, cwd=None, timeout=None, log_level="info")`

## `CHun.script()`

```python
from chun import CHun
from pwn import *

t = CHun.script("./challenge", host="example.com", port=31337, libc="./libc.so.6")
s = t.start()
io = t.io

t.gdb("b *main\nc")
```

行为边界：

- 默认运行 `python exp.py` 时，`t.start()` 走本地 `CHun.process()`
- 传 `REMOTE` 时，`t.start()` 走 `CHun.remote()`
- 传 `GDB` 且当前 session 是本地 process 时，`t.gdb()` 调用现有 `session.dbg.attach()`
- `REMOTE GDB` 时只 warning，不会 attach
- `t.target` 是当前脚本入口使用的 `TargetSpec` 配置对象
- `resolve` / `crash` / `gdb_mi` 仍然通过 `t.session.resolve`、`t.session.crash`、`t.session.gdb_mi` 使用

---

维护者说明：

- `CHun.process()` / `CHun.remote()` / `CHun.ssh_process()` / `CHun.http()` / `CHun.websocket()` / `CHun.blind()` 在内部都先落到同一套私有 `TargetSpec` / `TransportSpec` builder
- `CHun.script()` 也不再单独拼装 transport，而是复用相同 builder，再统一走 `from_specs()`
- `ScriptEntry.target` 是脚本入口缓存的基础 `TargetSpec`
- `ScriptEntry.start()` 在 `REMOTE` 模式下会基于该 target 派生 remote target，再配合 `pwntools-tube` transport 进入统一 session 装配路径
- `ScriptEntry` 保留的脚本态额外状态只有 `elf`、`libc` 和当前 `session`

## 会话生命周期

- `session.open()`：显式打开 transport
- `session.close()`：关闭 transport
- `session.reconnect()`：重建 transport
- `session.io`：首次访问时自动打开 transport
- pwntools 场景下可直接使用 `session.io.sendlineafter()` / `session.io.interactive()`
- `session.rec`：记录 observation / fact / artifact / context
- `session.infer`：执行最小 inference 闭环
- `session.dbg`：attach / gdbscript / 基本命令
- `session.gdb_mi`：结构化 GDB/MI 命令
- `session.resolve`：MemLeak / DynELF / symbol 解析
- `session.crash`：core dump 分析

## 示例

```python
from chun import CHun, RecordDomain

p = CHun.process("./challenge")
p.rec.record_symbol_leak("puts", 0x7F1234580000, domain=RecordDomain.LIBC, source="got")
result = p.infer.libc_base_from_symbol_leak("puts", symbol_offset=0x80000)
print(hex(result.aligned_base))

api = CHun.http("http://127.0.0.1:8000")
print(api.io.request("GET", "/health"))
```

## 本阶段边界

- 已完成：session/runtime 入口、registry 挂接、最小 inference、debug/resolve/crash bridge
- 未完成：完整 `fmt / heap / tpl` 子系统，以及 pwngdb/pwndbg 深集成
