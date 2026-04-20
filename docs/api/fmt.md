# FMT API

## 定位

`session.fmt` 是 CHun 当前已经独立成型的利用子系统之一。

它负责：

- 探测并持久化 `fmt.offset`
- 规范化目标地址与写入值
- 生成 `FmtWritePlan`
- 渲染 `RenderedFmtTask`
- 执行 fmt 写入任务
- 提供默认的读 primitive 与高层 `read()` / `write()` / `writes()` façade

它不负责：

- workflow / replay
- 自动回到同一 IO 输入点
- exploit 级流程编排

也就是说，`session.fmt` 负责“单次 session 内的 fmt 子系统能力”，而不是更高层的利用流程控制。

## 能力概览

当前 `fmt` 的稳定链路已经是：

1. `find_offset()`
2. `plan_writes()`
3. `render_plan()`
4. `execute_plan()`

以及两个高层 façade：

- `read()`
- `write()` / `writes()`

## Offset

### `find_offset()`

用于探测输入点的 fmt offset。

当前支持两种模式：

- `sequential`
- `positional_window`

常见脚本态调用：

```python
from chun import CHun

s = CHun.script("./challenge").start()
result = s.fmt.find_offset(max_slots=16)

print(result.index)
print(result.method.value)
print(result.matched_token)
```

返回值是 `FmtOffsetProbeResult`，不是裸整数。

探测成功后会分层写入 registry：

- observation: `fmt.offset.response`
- artifact: `fmt.offset.probe`
- fact: `fmt.offset`

### `get_offset()`

从 `registry` 读取已经确认的 `fmt.offset`，并组装为 `FmtOffset` 返回。

```python
offset = s.fmt.get_offset(required=True)
print(offset.index)
```

### `set_offset()`

手工写入 offset，或把 `FmtOffsetProbeResult` 固化为最终 fact。

```python
s.fmt.set_offset(6)
```

## Read

### `read()`

`read()` 是当前 `fmt` 的默认 leak 入口。

最常见的普通用法：

```python
from chun import CHun, FmtReadMode

s = CHun.script("./challenge").start()
s.fmt.set_offset(6)

leak = s.fmt.read(
    0x404040,
    size=8,
    mode=FmtReadMode.RAW,
)

print(leak.raw)
```

### 默认行为

默认 `read()` 走“内存字符串泄漏” primitive，大致会构造：

```text
%<offset>$s + terminator + packed_address
```

这样做的原因是：

- 它适合读取任意地址内容
- 便于通过 `terminator` 稳定截断回显
- 在长连接与 blind reconnect 场景下都容易复用相同 dispatch 逻辑

### 高级参数

`read()` 现在支持几组高级参数，用于覆盖默认行为：

- `fmt=`
  - 显式指定格式串，例如 `%6$p`
- `append_target=`
  - 是否自动在 payload 尾部拼接目标地址
- `recv_until=`
  - 覆盖默认捕获边界
- `terminator=`
  - 指定默认字符串泄漏场景的结束标记
- `strict_terminator=`
  - 当使用 terminator 时，要求回包中必须出现该标记

例如读取 `%p` 文本：

```python
ptr = s.fmt.read(
    0x0,
    size=8,
    mode=FmtReadMode.POINTER,
    offset=6,
    fmt="%6$p",
    append_target=False,
    recv_until=None,
    strict_terminator=False,
)

print(hex(ptr.decoded))
```

### 返回值

`read()` 返回 `FmtLeak`。

主要字段：

- `target`
- `address`
- `mode`
- `raw`
- `decoded`
- `offset`

调试时更建议同时看 `metadata`：

- `payload`
- `primitive`
- `append_target`
- `terminator`
- `recv_until`
- `dispatch`
- `transport_kind`
- `raw_response`
- `body`

## Write

### `plan_write()` / `plan_writes()`

这两组接口只负责规划，不发送。

```python
plan = s.fmt.plan_writes(
    {"printf@got": "system"},
    strategy="short",
)

print(plan.total_atoms, plan.total_tasks)
```

返回值是 `FmtWritePlan`。

### `render_task()` / `render_plan()`

这两组接口只负责渲染，不发送。

```python
rendered = s.fmt.render_plan(plan, offset=6)
print(rendered[0].payload)
```

返回值分别是：

- `RenderedFmtTask`
- `tuple[RenderedFmtTask, ...]`

### `execute_plan()`

执行已经存在的 `FmtWritePlan`。

```python
result = s.fmt.execute_plan(plan, offset=6)
print(result.total_tasks)
print(result.responses[0])
```

它会：

1. 先 `render_plan()`
2. 再按 transport 能力选择：
   - 普通场景：`sendline()` / `recv*()`
   - blind reconnect：`exchange()`
3. 产出聚合结果 `FmtExecutionResult`

### `write()` / `writes()`

这是当前推荐的高层写接口。

```python
result = s.fmt.write(
    "printf@got",
    "system",
    strategy="short",
    offset=6,
)

print(result.total_tasks)
print(result.task_indexes)
print(result.responses[0])
```

`write()` 相当于单目标版，`writes()` 相当于批量版。

它们内部会自动完成：

1. `plan_writes()`
2. `execute_plan()`

因此更适合脚本态直接使用。

## 结果模型

当前 `fmt` 最常用的返回对象有这些：

- `FmtOffsetProbeResult`
  - 一次 offset 探测结果
- `FmtOffset`
  - 最终确认后的 offset fact
- `FmtLeak`
  - 一次读操作结果
- `FmtWritePlan`
  - 一次写规划结果
- `RenderedFmtTask`
  - 一次渲染结果
- `FmtExecutionReceipt`
  - 单 task 执行回执
- `FmtExecutionResult`
  - 一次完整写执行的聚合结果

如果你只关心“脚本里怎么继续用”，建议记住下面这个层级：

- probe 看 `FmtOffsetProbeResult`
- read 看 `FmtLeak`
- write 看 `FmtExecutionResult`

## 错误模型

当前 `fmt` 已经有自己的明确异常，不再继续依赖裸 `RuntimeError`。

常见异常：

- `FmtOffsetProbeError`
- `FmtOffsetNotFoundError`
- `FmtOffsetMissingError`
- `FmtSymbolResolveError`
- `FmtReadError`
- `FmtExecutionError`
- `FmtWriteError`
- `FmtConfigurationError`

这意味着：

- 缺 offset 时，不再是模糊的 runtime 错误
- 符号解析失败时，会明确落在 fmt 子系统自己的异常语义里
- dispatch / decode 失败时，也能更快定位到读链还是写链

## Registry 约定

当前 `fmt` 会把关键中间产物写回 registry。

常见键包括：

- fact:
  - `fmt.offset`
- artifact:
  - `fmt.offset.probe`
  - `fmt.plan`
  - `fmt.render.task.<n>`
  - `fmt.exec.task.<n>`
  - `fmt.write.task.<n>`
- observation:
  - `fmt.offset.response`
  - `fmt.exec.response.<n>`
  - `fmt.write.response.<n>`
  - `fmt.leak.<name>`

## 设计边界

当前这页文档描述的是 `fmt v1.x` 的稳定能力。

已经完成：

- offset probe
- write plan / render / execute 闭环
- read 默认 backend
- 高层 `read()` / `write()` / `writes()` façade
- 聚合结果模型
- 明确错误模型

Future work：

- replay / workflow
- 自动回到同一输入点
- 更强的 blind exploit orchestration
- 更细的 leak primitive 分层
