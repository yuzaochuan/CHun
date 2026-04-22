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
- `compare_write()`
- `compare_writes()`

写路径内部现在采用“两层架构”：

- CHun 语义层
  - 保留 typed models、service、registry 回写和 execution orchestration
- payload backend 层
  - 默认使用 pwntools `pwnlib.fmtstr`
  - 负责 atom 生成、排序和 `fmt/data` 拆分

因此，`planner` / `renderer` 当前更像 backend 的 CHun 适配层，而不是继续手写 fmt payload 核心算法。

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

### 自动验证（可选）

`find_offset()` 现在支持可选验证：

```python
result = s.fmt.find_offset(
    max_slots=16,
    verify=True,
    verify_marker=b"aabb",
)
```

行为是：

1. 先探测 offset（写 observation / artifact）
2. 使用 `rec` 当前 replay trace 新开独立 session 回放到当前 IO 点
  - 默认回放到“本次探测发送之前”的节点，再注入验证 probe
  - 避免把 `find_offset` 探测 payload 本身二次发送进验证链
3. 注入 `marker + b"%<offset>$p"` 探针
4. `predicate` 命中后再晋升 `fmt.offset` fact

如果验证失败：

- 保留 observation（含 `verification_status=failed`）
- 不晋升 `fmt.offset` fact

默认 `verify=False`，保留原有快速路径。

调试期如果希望看到验证进度，可以保留 `loginfo=True`（脚本态语法糖默认开启），会输出 verify start / passed / failed 的简短反馈。验证 replay 会话默认使用静默日志级别，不刷第二个进程的 debug IO。

`replay_silent=True` 只应抑制 replay 子会话日志，不应影响主会话后续 `loginfo` 输出。内部会在 replay 结束后恢复调用前的全局日志级别。

当 `loginfo=True` 且 `verify=True` 时，原有两行 offset 输出仍会保留，并额外追加一行验证摘要：

- `fmt offset found: ...`
- `fmt offset detail: ...`
- `fmt offset verify result: status=...`

验证阶段对 `%p` 的命中判定使用“marker 是否出现在 pointer bytes 中”，因此像 `aabb%6$p` 回显成 `0x7024362562626161` 这类携带后缀格式串字节的结果也能被识别为通过。

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

默认 backend 是 `pwntools`。当前写路径需要明确区分两个偏移概念：

- `offset`
  - 即 `fmt_offset`
  - 表示输入缓冲区首个机器字槽位对应的 positional index
- `data_offset`
  - 表示尾部追加地址/数据区首槽位对应的 positional index

在经典 `fmt + packed_addresses` 场景里，这两个值通常并不相同。CHun 不再把 `data_offset = fmt_offset` 作为默认退化逻辑，而是在 task 渲染阶段按机器字宽自动计算真正的尾部地址区槽位。

### Append-Address 语义

默认 `ADDRESSES_LAST` 布局采用下面的模型：

- `fmt_offset`
  - 输入缓冲区起始槽位
- `data_offset`
  - 尾部地址区起始槽位
- 64 位按 8-byte 槽位计算
- 32 位按 4-byte 槽位计算

也就是说，最终 payload 更接近：

```text
fmt_bytes + alignment_padding + packed_addresses
```

`alignment_padding` 会把 `fmt_bytes` 补齐到下一个机器字边界，然后尾部地址区才开始占槽位。

### `data_offset` 的收敛

对 pwntools backend，CHun 在每个 rendered task 上独立做 fixed-point 收敛：

1. 用当前猜测的 `data_offset` 先渲染一次 `fmt_bytes`
2. 计算补齐后的前缀长度
3. 推导新的 `data_offset`
4. 重复直到稳定，或在安全上限内抛出明确异常

因此：

- `FmtWritePlan.offset`
  - 表示 `fmt_offset`
- `FmtWritePlan.data_offset`
  - 仅在用户显式覆盖时保存该值；否则可为 `None`
- `RenderedFmtTask.data_offset`
  - 表示该 task 最终收敛后的尾部地址区首槽位
- `FmtRenderStep.arg_index`
  - 始终基于该 task 的最终 `data_offset`

`plan_writes()` 支持的 backend 侧关键参数包括：

- `backend="pwntools"`：默认 backend
- `backend="native"`：实验性 fallback
- `write_size`
- `write_size_max`
- `overflows`
- `badbytes`
- `no_dollars`
- `numbwritten`

### `render_task()` / `render_plan()`

这两组接口只负责渲染，不发送。

```python
rendered = s.fmt.render_plan(plan, offset=6)
print(rendered[0].payload)
```

返回值分别是：

- `RenderedFmtTask`
- `tuple[RenderedFmtTask, ...]`

对于 `pwntools` backend，渲染结果会显式区分：

- `fmt_bytes`
- `data_bytes`
- `payload`

其中 `payload` 现在允许包含：

- `fmt_bytes`
- 对齐补齐用的 padding
- `data_bytes`

所以 `payload` 不再总是简单等于 `fmt_bytes + data_bytes`。

如果你只是想拿最终 payload，而不是直接发送：

```python
plan = s.fmt.plan_write(0x60120, 102, strategy="byte")
rendered = s.fmt.render_task(plan.tasks[0], plan=plan)

print(rendered.payload)
print(rendered.data_offset)
```

例如在 64 位、`fmt_offset = 6`、单字节写 `0x60120 <- 102` 的 append-address 场景里，最终 positional index 会落在更后的槽位，而不会再错误地继续使用 `%6$...`。

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

### `compare_write()`

用于在同一组写参数下，对比多种 write strategy 的计划与 payload，而不实际发送。

默认比较这些策略：

- `AUTO`
- `BYTE`
- `SHORT`
- `INT`

其中 `BYTE` 现在默认是严格 byte-only 语义：

- `write_size = "byte"`
- `write_size_max = "byte"`
- backend 不会再把相邻 byte atom 合并成 `%hn` / `%n`

另外，整数值的总写入宽度现在按 strategy 分两类：

- `AUTO` / `PTR`
  - 默认按当前机器字宽展开
  - 64 位按 8-byte，32 位按 4-byte
  - 适合 GOT / 函数指针这类希望把高位 `0x00` 也纳入计划的场景
- `BYTE` / `SHORT` / `INT`
  - 默认只按最小有效字节数规划
  - 更紧凑，也更接近手工 exploit 时“只改低位”的直觉

如果你要显式覆盖总写入范围，仍然可以用 `value_bits` 或 `chunk_width`。

示例：

```python
report = s.fmt.compare_write(
    0x6010A0,
    0x601018,
)

print(report)
```

`compare_write()` 返回 `FmtWriteComparison`，其中每个 strategy 会产出一个 `FmtWriteCandidate`：

- 成功时包含 `plan` 与 `rendered_tasks`
- 失败时保留结构化错误文本

脚本态 `s.fmt.compare_write(...)` 默认会打开 `loginfo=True`，直接把对照结果打印出来；service 层 `session.fmt.compare_write(...)` 默认只返回结果，不主动打印。

`compare_write()` 也支持两个 script 场景里很常用的门面参数：

- `buflen`
  - 期望的最大输入长度
  - 用于对照输出里的 `✅ / ❌ / ❔` 提示
- `end`
  - 实际发送到目标时自动附加在 payload 末尾的结束符
  - 默认是 `b"\n"`
  - 例如 `scanf("%s")` 类输入场景可以手工改成 `b" "` 或 `b""`

状态图标语义：

- `✅`
  - 指定了 `buflen`，且本次实际发送长度不超过它
- `❌`
  - 指定了 `buflen`，且本次实际发送长度超过它
  - 或者当前方案的 `pad_time` 已经是 `EXTREME`
- `❔`
  - 没有提供 `buflen`，且 `pad_time` 还没有到 `EXTREME`

### Script 门面

脚本态 `s.fmt.write(...)` 现在是一个更适合手写 exp 的门面，不再直接暴露底层 service 的大量 `**kwargs`。

推荐用法：

```python
s.fmt.write(
    0x6010A0,
    0x601018,
    b"name: ",
    6,
    strategy="AUTO",
    end=b"\n",
).info(0x40, show_hex=True)

s.fmt.write(
    0x6010A0,
    0x601018,
    b"name: ",
    6,
    strategy="BYTE",
    end=b" ",
).send()
```

如果你需要在 fmt 写入前面手工塞一段格式串头部，也可以只在 script 门面里用半自动模式：

```python
s.fmt.write(
    0x6010A0,
    0x601018,
    b"name: ",
    6,
    strategy="AUTO",
    head=b"%32$p",
    head_numbwritten=14,
).info(0x40)
```

这里的语义是：

- `head`
  - 直接拼到最终 fmt payload 前面
- `head_numbwritten`
  - 你手工告诉 CHun：这段 `head` 在运行时实际会打印多少字符
  - CHun 再据此重算后续 `%hhn/%hn/%n` 的 padding 和 `data_offset`

注意：

- 这是 script-only 的半自动语法糖，不影响底层 `session.fmt.write()`
- 当前只支持单 task 的 `write(...)` 发送链
- 如果 `head` 里是 `%p/%s/%d` 这类动态输出，必须由你自己提供正确的 `head_numbwritten`

当前 script 门面显式暴露这些高频参数：

- `target`
- `value`
- `delim`
- `offset`
- `strategy`
- `task_policy`
- `data_offset`
- `end`

其中：

- `.info()`
  - 第一个位置参数可以直接传 `buflen`
  - 内部复用同一组参数，调用 `compare_write(...)`
- `.send()`
  - 使用当前单一 `strategy` 真正执行发送
  - script 门面这里是 send-only 语义，不会额外 `recv`
  - 如果提供了 `delim`，会先 `recvuntil(delim)` 再发送
  - 如果传了 `buflen`，会在发送前做一次软检查：超长时 `log.error(...)`，但不阻塞发送
  - 如果当前方案的 `pad_time >= HIGH`，也会打印中文 `log.warning(...)`
  - 如果后面还要手动 `s.recv()` / `s.recvuntil()`，就应该用这个入口

多地址写也有对应的 script 门面：

```python
s.fmt.writes(
    {
        0x404018: 0x11223344,
        0x404020: 0x55667788,
    },
    b"choice> ",
    6,
    strategy="SHORT",
    task_policy="BY_TARGET",
    end=b"\n",
).info(0x80, show_hex=True)
```

`s.fmt.writes(...).send()` 与单目标版相同，也是 send-only 语义：

- 只发送 payload
- 如果提供了 `delim`，会先 `recvuntil(delim)` 再发送
- 如果传了 `buflen`，会在发送前做一次软检查：超长时 `log.error(...)`，但不阻塞发送
- 如果当前方案的 `pad_time >= HIGH`，也会打印中文 `log.warning(...)`
- 不会提前消费后续响应
- 适合你自己继续控制 `recv()` / `recvuntil()` 的脚本流程

以及直接的多策略对照入口：

```python
s.fmt.compare_writes(
    {
        0x404018: 0x11223344,
        0x404020: 0x55667788,
    },
    offset=6,
    show_hex=True,
)
```

当 `show_hex=True` 时，对照输出会额外打印 `send.hex`，使用类似 pwntools debug dump 的格式展示真正发送给目标的字节串（即 `payload + end`）。

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
- `FmtWriteComparison`
  - 多策略对照结果
- `FmtWriteCandidate`
  - 单个 strategy 的候选结果

### `compare_writes()`

用于同一批写请求在多种 strategy 下做对照，不实际发送。

```python
report = session.fmt.compare_writes(
    {
        0x404018: 0x11223344,
        0x404020: 0x55667788,
    },
    offset=6,
)

print(report)
```

`compare_writes()` 返回 `FmtWritesComparison`：

- 头部是单行摘要，直接显示 request 数和前几个写入目标
- 每个 strategy 仍然显示 `atoms / tasks / send / data@ / max_pad / pad_time`
- 多 task 场景下，`fmt` 和 `payload` 会采用更紧凑的单行展示，给头部指标留更多空间
- `show_hex=True` 时同样会打印 `send.hex`
- `RenderedFmtTask`
  - 一次渲染结果
- `FmtExecutionReceipt`
  - 单 task 执行回执
- `FmtExecutionResult`
  - 一次完整写执行的聚合结果

和写路径 backend 重构直接相关的字段有：

- `FmtWritePlan.backend`
- `FmtWritePlan.offset`
- `FmtWritePlan.data_offset`
- `RenderedFmtTask.fmt_bytes`
- `RenderedFmtTask.data_bytes`
- `RenderedFmtTask.data_offset`
- `RenderedFmtTask.backend`

## Future work

- `read()` 的默认 `%<offset>$s + terminator + packed_address` 路径仍沿用 legacy append-address 拼接。
- 它还没有像写路径那样把 `fmt_offset` / `data_offset` 完全拆开并做槽位收敛。
- 因此，本次修复优先覆盖 write path；read path 后续仍应补同类对齐模型。

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

需要特别注意的边界：

- `read()` 的 offset 语义仍然是“当前读 primitive 使用的参数槽位”
- `write()` 的 `data_offset` 语义是“追加地址块的首个参数槽位”

两者相关，但不应混为一个概念。
