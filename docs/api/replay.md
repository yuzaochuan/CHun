# Replay API

## 定位

`core/replay` 是 CHun 在运行期使用的 compact replay 子系统，目标是：

- 低开销记录可重放的最小 IO 前缀
- 在独立会话中回放到同一同步点
- 注入 probe 并用 predicate 自动判定

它不是 full workflow 编译器，也不恢复 Python 运行时变量。

## 核心边界

- replay 热路径只关心外部 effect：
  - `spawn`
  - `send`
  - `sendline`
  - `expect`（`recvuntil` 同步锚点）
  - `checkpoint`
- 不记录完整 `recv` 字节流
- 不记录 AST / ExprNode / 局部变量状态

这保证 replay trace 足够小，可在 exploit 运行中持续记录。

## 数据模型

### `ReplayEventKind`

- `SPAWN`
- `SEND`
- `SENDLINE`
- `EXPECT`
- `CHECKPOINT`

### `PayloadRef`

大 payload 不内联到事件中，而是通过 `PayloadRef` 引用：

- `blob_id`
- `sha256`
- `size`

默认存储由 `InMemoryBlobStore` 提供，按 `sha256` 去重。

### `ReplayEvent`

- `seq`: 事件序号（单调递增）
- `ts_ns`: 纳秒时间戳
- `kind`: 事件类型
- `payload`: `PayloadRef | None`
- `drop`: `EXPECT` 是否 `drop=True`
- `metadata`: 轻量附加信息

### `ReplayCheckpoint`

- `name`
- `event_seq`
- `trace_digest`
- `metadata`

### `VerificationResult`

- `run_id`
- `ok`
- `reason`（`predicate_pass` / `predicate_fail`）
- `output_preview`
- `completed_ns`
- `metadata`

## 记录链路

### 自动记录来源

`CHunSession` 在初始化时绑定 transport replay hook，事件来源如下：

- `BaseTransport.open()` -> `spawn`
- `PwntoolsTubeTransport.send()` -> `send`
- `PwntoolsTubeTransport.sendline()` -> `sendline`
- `PwntoolsTubeTransport.sendafter()` -> `expect + send`
- `PwntoolsTubeTransport.sendlineafter()` -> `expect + sendline`
- `PwntoolsTubeTransport.recvuntil()` -> `expect`

用户也可以手工打点：

```python
session.checkpoint("before_fmt_probe")
```

## Recorder API（`ReplayRecorder`）

### `append_event(...)`

追加一条 replay 事件。若携带 `payload`，会先写入 blob store，事件仅保存 `PayloadRef`。

### `checkpoint(name, metadata=None)`

写入命名检查点，并追加一条 `CHECKPOINT` 事件。

### `slice_to_here(from_checkpoint=None)`

- 不传 checkpoint：返回 `[0:cursor]` 全量切片
- 传 checkpoint：从该 checkpoint 的 `event_seq` 开始切片

### `replay_from_checkpoint(checkpoint_name)`

`slice_to_here(from_checkpoint=...)` 的语义化别名。

## 重放执行逻辑（`ReplayExecutor.replay`）

`ReplayExecutor` 只执行 compact trace，不做 workflow 编译。

执行顺序固定为：

1. 记录当前全局日志级别（用于 replay 后恢复）
2. `session = session_factory()` 构造独立会话
3. 依序回放 trace
   - `SEND` -> `io.send(...)`
   - `SENDLINE` -> `io.sendline(...)`
   - `EXPECT` -> `io.recvuntil(delim, drop=...)`
   - `SPAWN` / `CHECKPOINT` 目前不执行动作（由会话打开和切片边界承担语义）
4. 在 injection point 注入 probe
   - 默认 `sendline`
   - 可切换为 `send`
5. `io.recv(recv_bytes)` 获取验证输出
6. 调用 `predicate(output)` 判定通过/失败
7. 返回 `VerificationResult`
8. `finally` 中关闭 replay 会话并恢复之前日志级别

> `replay_silent=True` 的目标是只压低 replay 子会话日志，不影响主会话后续日志输出。

## Registry 集成（`EvidenceRegistry`）

`EvidenceRegistry` 暴露 replay 相关最小 API：

- `append_event(...)`
- `checkpoint(...)`
- `slice_to_here(...)`
- `replay(...)`
- `validate_observation(...)`
- `promote_observation_to_fact(...)`

### `validate_observation(...)` 的执行链

1. 读取 observation（例如 `fmt.offset.candidate`）
2. 取 replay 切片：`slice_to_here(from_checkpoint=...)`
3. 可选截断：`end_seq_exclusive`
   - 常用于“回放到探测前节点”，避免把探测 payload 二次发送
4. `executor.replay(...)` 执行验证
5. 回写 observation metadata：
   - `verification_status`
   - `verified_by`
   - `verification_reason`
   - `verification_output_preview`
6. 验证通过且 `promote_to_fact=True` 时，晋升为 fact

## FMT 自动验证接入

`FmtService.find_offset(verify=True)` 当前链路：

1. 探测 offset，得到 `FmtOffsetProbeResult`
2. 写 observation：`fmt.offset.candidate`
3. 构造 probe：`marker + b"%<index>$p"`
4. 通过 replay slice 在独立会话验证
5. `predicate` 命中则把 `fmt.offset` 晋升为 fact
6. 保留 `fmt.offset.probe` artifact 与验证状态

调试输出在 `loginfo=True` 时会保留原有 offset 信息，并追加验证结果摘要。

## 静态快照与动态地址

replay 记录的是“发送了什么 / 等待了什么”，不是“地址值快照”。

这意味着：

- 静态脚本场景可用
- `ret2libc` 这类动态地址场景也可用
  - 动态 payload 会作为 bytes 事件被重放
  - 验证判定依赖实时输出，不依赖旧地址快照

## 已知边界（当前版本）

- 默认 executor 只针对 tube 风格 IO（`send/sendline/recvuntil/recv`）
- 不恢复 Python 局部变量和闭包
- 不负责 blind/remote 重试策略编排
- checkpoint 恢复是“切片级恢复”，不是进程状态快照恢复

这些边界是有意为之，用于保持 replay 热路径可控。

## 示例：手动验证一个候选 observation

```python
from chun.core.replay import ReplayExecutor

obs = session.rec.record_observation(
    "fmt.offset.candidate",
    6,
    source="manual",
)

executor = ReplayExecutor(session.rec.replay.blob_store)
result = session.rec.validate_observation(
    "fmt.offset.candidate",
    session_factory=session.make_replay_session,
    executor=executor,
    probe=b"aabb%6$p",
    predicate=lambda out: b"62626161" in out,
    promote_to_fact=True,
    fact_name="fmt.offset",
)

print(result.ok, result.reason)
```
