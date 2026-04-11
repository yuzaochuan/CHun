# Debug & Resolve API

## `session.dbg`

`session.dbg` 是 `PwntoolsGdbBridge`，偏交互式调试：

- `attach(io=None, script=None, api=True)`
- `execute(command)`
- `breakpoint(location)`
- `snapshot_regs()`
- `snapshot_maps()`

设计目标：

- 适合当前 pwntools process / tube attach
- 允许发基本 gdbscript
- 关键调试上下文回写 registry

## `session.gdb_mi`

`session.gdb_mi` 是 `GdbMiBridge`，偏机器可解析与自动化：

- `start()`
- `execute(command)`
- `snapshot_regs()`
- `snapshot_maps()`
- `backtrace()`

设计目标：

- 与交互式 GDB 分离
- 返回结构化结果
- 为后续自动分析保留稳定接口

## `session.resolve`

`session.resolve` 是围绕 pwntools 能力封装的解析入口：

- `memleak(leak_primitive, ...)`
- `symbol_via_dynelf(symbol, ..., pointer=...)`
- `libc_base_from_elf_symbol(observation_name, libc_elf=..., symbol=...)`
- `pie_base_from_elf_symbol(observation_name, elf=..., symbol=...)`

它负责把：

- leak primitive
- `MemLeak`
- `DynELF`
- session.registry

收敛到同一条工作流里。

## `session.crash`

`session.crash` 是 `CorefileAnalyzer`：

- `analyze(core, offset_subseq=None)`

分析后会把结果写回 registry，包括：

- crash registers
- fault address
- PC / SP
- maps
- cyclic offset
- core path / signal 等 context

## 三条最小 workflow

### ret2libc

```python
session.rec.record_symbol_leak("puts", leak, source="got")
result = session.resolve.libc_base_from_elf_symbol(
    "puts",
    libc_elf=libc,
    symbol="puts",
)
```

### blind leak -> DynELF

```python
resolved = session.resolve.symbol_via_dynelf(
    "system",
    leak_primitive=leak_func,
    pointer=0x601018,
    lib="libc",
)
```

### core dump analysis

```python
report = session.crash.analyze("/tmp/core")
print(report.pc, report.cyclic_offset)
```

这些 workflow 在当前仓库里都有独立 smoke test，并且都只走 `CHun` + `CHunSession` 的公开入口。
