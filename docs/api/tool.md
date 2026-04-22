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
- 显式挂出 `rec` / `infer` / `resolve` / `dbg` / `crash` 等 session 核心能力
- 显式挂出 `sendlineafter()` / `recvline()` / `interactive()` 以及 `sla()` / `rl()` / `ia()` 等高频方法
- 显式挂出 `recv_leak()`，用于脚本态直接接收并记录 leak
- `session` / `io`：保留为底层出口

显式工厂与 `CHun.script()` 在内部都会先收敛到同一套 `TargetSpec` / `TransportSpec` builder，再交给 `from_specs()` 组装 session。

并在初始化时为脚本态准备：

- `context.log_level` / `context.terminal`
- `elf`：先构造 `ELF(binary, checksec=False)`，再挂到 `context.binary`
- `libc`：显式 `ELF(libc, checksec=False)`，或回退到 `elf.libc`

注意事项（与当前 pwntools 行为对齐）：

- `context.log_level` 在 pwntools 内部是标准化后的等级值（例如 `"debug" -> 10`），不是原始字符串
- `context.binary` 在脚本态会直接指向当前 `ELF` 对象，后续应按“对象已就绪”使用，不要假设每次访问都重新按路径解析

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
- `elf` / `libc_elf`：当前会话绑定的运行时 ELF / libc ELF 对象

运行时富对象的标准绑定入口是：

- `session.bind_binaries(elf=..., libc_elf=...)`

它会：

- 把富对象挂到 `session.elf` / `session.libc_elf`
- 同步写入规范化标量 context，例如 `binary.path` / `binary.arch` / `arch.bits` / `libc.path`

不会把 ELF / libc ELF 对象本身写入 registry context。

其中推荐把下面这些看作下一阶段插件开发的稳定挂接点：

- `session.registry` / `session.rec`
- `session.infer`
- `session.resolve`
- `session.crash`
- `session.dbg` / `session.gdb_mi`

## 工厂方法

- `CHun.process(binary, *, argv=None, libc=None, ld=None, env=None, cwd=None, log_level="info", terminal=("tmux", "splitw", "-h"))`
- `CHun.remote(host, port, *, binary=None, libc=None, timeout=None, log_level="info", terminal=("tmux", "splitw", "-h"))`
- `CHun.ssh_process(host, *, user, binary, argv=None, port=22, password=None, keyfile=None, key_password=None, env=None, cwd=None, log_level="info", terminal=("tmux", "splitw", "-h"))`
- `CHun.http(base_url, *, headers=None, timeout=None, follow_redirects=True, verify=True, client_factory=None)`
- `CHun.websocket(ws_url, *, headers=None, timeout=None, connect_timeout=None, connection_factory=None)`
- `CHun.blind(connection_factory, *, timeout=None)`
- `CHun.script(binary, *, host=None, port=None, libc=None, ld=None, argv=None, env=None, cwd=None, timeout=None, log_level="debug", terminal=("tmux", "splitw", "-h", "-d"))`

## `CHun.script()`

```python
from chun import CHun
from pwn import *

t = CHun.script("./challenge", host="example.com", port=31337, libc="./libc.so.6")
t.start()

# 或者直接链式写：
# t = CHun.script("./challenge", host="example.com", port=31337, libc="./libc.so.6").start()

t.sla(b"menu> ", b"1")
t.rec.record_symbol_leak("puts", 0x7F1234580000, source="got")
leak = t.recv_leak("puts", delim=b"puts: ")
print(hex(leak))
t.resolve.libc_base_from_elf_symbol("puts", symbol="puts")
print(hex(t.libc_base))

session = t.session
print(hex(session.libc_base))
t.gdb("b *main\nc")
```

行为边界：

- 默认运行 `python exp.py` 时，`t.start()` 走本地 `CHun.process()`
- 传 `REMOTE` 时，`t.start()` 走 `CHun.remote()`
- `REMOTE` 且非 `GDB` 时，remote target 的 `log_level` 固定为 `"info"`
- `REMOTE GDB` 时，remote target 继承 process 侧 `log_level`（不强制降级到 `"info"`）
- 传 `GDB` 且当前 session 是本地 process 时，`t.gdb()` 调用现有 `session.dbg.attach()`
- `REMOTE GDB` 时只 warning，不会 attach
- `t.target` 是当前脚本入口使用的 `TargetSpec` 配置对象
- `t.start()` 返回 `t` 自身，因此 `t = CHun.script(...).start()` 与 `t = CHun.script(...); t.start()` 都可用
- `t.start()` 会通过 `session.bind_binaries()` 绑定脚本态已加载的 `t.elf` / `t.libc`
- `t.rec` / `t.infer` / `t.resolve` / `t.dbg` / `t.crash` 会显式转发到当前 session
- `t.session` 是属性，不是方法；用于直接访问当前已启动的完整 `CHunSession`
- `t.resolve.libc_base_from_elf_symbol(..., symbol="puts")` 在脚本态可直接复用默认 `t.libc`，无需重复传 `libc_elf=t.libc`
- `t.resolve.pie_base_from_elf_symbol(..., symbol="main")` 在脚本态可直接复用默认 `t.elf`
- `t.infer.search_libc()` 会从事实层自动扫描 `RecordDomain.LIBC` 的 symbol leak，并优先使用 `session.elf` / 已同步的标量 context 推断架构
- `t.infer.search_libc(index=...)` 可在多候选场景下按候选排名静默确认目标版本，并自动回写 `libc.version + libc.base`
- `t.recv_leak(name, ...)` 会在脚本 façade 层完成“接收 -> 解析 -> offset 修正 -> `record_symbol_leak()` 回写”
- `t.recv_leak(...)` 的返回值就是解析后的整数泄漏；脚本态优先直接使用返回值，而不是再手动 `get_observation(...).value`
- `t.recv_leak(name)` 支持没有明显前缀的场景：若不传 `delim` / `regex`，会直接按当前 `mode` 从流中读取泄漏值
- `t.recv_leak(..., mode="raw")` 默认按常见 CTF 泄漏习惯读取 32 位 `4` 字节、64 位 `6` 字节，再按 `t.elf.bytes` 补零解析
- `t.recv_leak(..., mode="hex")` 会从读到的文本里提取全部 `0x...` 地址 token；默认取第一个，可用 `index=` 指定第几个命中
- `t.recv_leak(..., mode="hex", delim=..., delim_end=...)` 可限定提取窗口到两个分隔符之间；若命中多个地址会 `warning` 输出完整列表和默认选中的地址
- `t.libc_base` / `t.libc_version` 以及 `t.session.libc_base` / `t.session.libc_version` 提供快捷读取；若尚未确认则抛 `RuntimeError`
- `t.resolve.symbol("str_bin_sh")` / `t.resolve.symbol("puts@got")` 会自动做后缀剥离和 alias 归一化；已绑定 `t.libc` 时优先走本地 `libc_elf + libc.base`，否则回退到 `libc.version + catalog`
- 访问 `t.session` / `t.rec` / `t.infer` / `t.resolve` / `t.dbg` / `t.crash` 前必须先 `t.start()`；否则抛 `RuntimeError`
- 高频交互方法可直接使用 `t.sendlineafter()` / `t.recvline()` / `t.interactive()` 及其 alias
- 低频 tube 方法通过 `__getattr__` fallback 到 `t.io`
- `with CHun.script(...) as t:` 会自动 `start()` 并打开/关闭底层 transport

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
- `session.bind_binaries(elf=..., libc_elf=...)`：绑定运行时二进制对象，并同步 `session` 字段与规范化 `registry context`
- `session.io`：首次访问时自动打开 transport
- pwntools 场景下可直接使用 `session.io.sendlineafter()` / `session.io.interactive()`
- pwntools 场景下，未显式列出的常用 `tube` 方法也会透传，例如 `session.io.recvline()`
- `session.rec`：记录 observation / fact / artifact / context
- `session.infer`：执行最小 inference 闭环
- `session.dbg`：attach / gdbscript / 基本命令
- `session.gdb_mi`：结构化 GDB/MI 命令
- `session.resolve`：MemLeak / DynELF / symbol 解析
- `session.crash`：core dump 分析
- `session.fmt`：无状态 fmt 服务，负责从 session/registry 读取架构上下文、做符号归一化、按 `sequential` / `positional_window` 两种模式探测并持久化 `fmt.offset`、提供重构后的 read 子系统、生成并持久化 `FmtWritePlan`、执行 task 级渲染与默认 executor 分发；写路径内部采用“CHun 语义层 + pwntools backend”两层架构，默认把 atom 生成、排序与 `fmt/data` 拆分委托给 `pwnlib.fmtstr`，同时继续保留 CHun 的 typed models、registry 回写与 transport orchestration；`read()` 默认走“内存字符串泄漏” primitive，但也支持通过 `fmt=`、`append_target=`、`recv_until=` 覆盖 payload 与捕获边界；高层 `write()` / `writes()` / `execute_plan()` 会返回聚合后的 `FmtExecutionResult`，内部收纳 `receipts`、`responses` 与 `task_indexes`；执行时会按 transport 类型选择 `sendline` 或 blind `exchange`，同时把原始响应写 observation、把 `FmtExecutionReceipt` 写 artifact；write path 现在显式区分 `offset` 与 `data_offset`；缺 offset、符号解析失败、读写分发失败现在都会抛出明确的 fmt 异常，而不是裸 `RuntimeError`；`find_offset(loginfo=False)` 默认静默，显式打开后会打印命中的 index / token / signature / confidence
- `ScriptEntry.fmt`：脚本态 `session.fmt` 语法糖；除常规转发外，`s.fmt.find_offset(...)` 会默认以 `loginfo=True` 打印探测结果，等价于 `s.session.fmt.find_offset(..., loginfo=True)`

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

```python
plan = p.fmt.plan_writes(
    {"printf@got": "system"},
    artifact_name="fmt.plan.printf2system",
)
print(plan.total_atoms, plan.total_tasks)

rendered = p.fmt.render_plan(plan, offset=6)
print(rendered[0].payload)

result = p.fmt.execute_plan(plan, offset=6)
print(result.responses[0])
```

```python
s = CHun.script("./challenge").start()
result = s.fmt.find_offset(max_slots=16)
print(result.index)
```

```python
leak = p.fmt.read(0x404040, size=8, mode="raw", offset=6)
print(leak.raw)

ptr = p.fmt.read(
    0x0,
    size=8,
    mode="pointer",
    offset=6,
    fmt="%6$p",
    append_target=False,
    recv_until=None,
    strict_terminator=False,
)
print(hex(ptr.decoded))

result = p.fmt.write("printf@got", "system", strategy="short", offset=6)
print(result.total_tasks, result.responses[0])
```

## 本阶段边界

- 已完成：session/runtime 入口、registry 挂接、最小 inference、debug/resolve/crash bridge、fmt 探测/规划/渲染/执行链
- 未完成：heap / tpl 子系统，以及 pwngdb/pwndbg 深集成
