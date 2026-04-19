# Models 与 Enum

## 覆盖范围

- `TargetSpec`
- `TransportSpec`
- `RecordDomain`
- `ObservationKind`
- `FactKind`
- `ArtifactKind`
- `ContextKind`
- `Observation`
- `Fact`
- `Artifact`
- `ContextEntry`
- `BaseInferenceResult`
- `ResolvedSymbolResult`
- `CrashAnalysisResult`
- `GdbMiResult`
- `LibcLeakConstraint`
- `LibcCandidate`
- `LibcSearchResult`
- `FmtTargetRef`
- `FmtValueRef`
- `FmtOffset`
- `FmtLeak`
- `FmtWriteRequest`
- `FmtWriteAtom`
- `FmtWriteTask`
- `FmtWritePlan`
- `FmtRenderStep`
- `RenderedFmtTask`
- `FmtWriteStrategy`
- `FmtReadMode`
- `FmtTaskPolicy`
- `FmtLayoutPolicy`

## `TargetSpec`

`TargetSpec` 统一描述“目标是什么”，核心字段包括：

- `kind`
- `binary`
- `host` / `port`
- `base_url`
- `ws_url`
- `argv` / `env` / `cwd`
- `ssh_*`

它的意义是让连接模式不再依赖 `remote_mode: bool`，而是显式落在数据模型里。

## `TransportSpec`

`TransportSpec` 统一描述“这次怎么连”，核心字段包括：

- `kind`
- `timeout`
- `connect_timeout`
- `headers`
- `follow_redirects`
- `verify`
- `delimiter`
- `metadata`

它负责承载 transport 生命周期和协议相关配置。

## 为什么使用 `Enum`

枚举提供稳定可比对的语义集合，避免字符串拼写漂移造成“看起来差不多、实际不一致”的问题。

## Registry 相关枚举

新的 registry 不再围绕“地址记录 / base 记录”工作，而是围绕语义更稳定的几类枚举：

- `RecordDomain`
- `ObservationKind`
- `FactKind`
- `ArtifactKind`
- `ContextKind`

这些枚举继续使用 `str + Enum`，原因是相同的：

- 枚举约束（类型安全）
- 字符串兼容（便于日志、序列化、展示）

其中 `ArtifactKind` 现在包含 `CATALOG_RESULT`，用于保存 `LibcSearchResult` 这类 catalog 检索产物。

## 数据模型如何支撑 Registry 与 Transport

- `TargetSpec`：描述目标
- `TransportSpec`：描述 transport 配置
- `Observation`：记录原始观测
- `Fact`：记录稳定结论
- `Artifact`：记录可复用产物
- `ContextEntry`：记录会话上下文
- `BaseInferenceResult`：承载最小 base inference 闭环结果
- `ResolvedSymbolResult`：承载 DynELF / symbol resolve 结果
- `CrashAnalysisResult`：承载 core dump 分析结果
- `GdbMiResult`：承载结构化 GDB/MI 命令结果

模型层让 Registry 不只是“存值”，而是“存值 + 存上下文 + 存可信度”。

## FMT 共享模型

FMT 的结构化 DTO 现在统一收口在 `src/chun/core/models/fmt.py`，而不是继续挂在插件目录内部。这样做有两个目的：

- `session.fmt`、blind executor、后续 planner / writer 可以共享同一组类型，而不是各自维护私有 dataclass
- 模型层职责更清晰：`plugins/fmt` 负责 service / orchestration，`core/models` 负责稳定数据形状

当前这组模型包括：

- `FmtTargetRef`：描述规范化后的目标地址引用，保留原始输入、解析地址、符号来源与元数据
- `FmtValueRef`：描述规范化后的写入值引用，支持字面值或符号值
- `FmtOffset`：描述最终确认后的 offset fact；确认后的值应写回 `fmt.offset`
- `FmtOffsetProbeMode`：描述 offset 探测模式，当前支持 `sequential` 与 `positional_window`
- `FmtOffsetProbeResult`：描述一次 offset 探测 artifact，包含 `method`、`matched_token`、`raw_output`、`tokens`、`window_start/window_end`、`sep`、`confidence`
- `FmtLeak`：描述一次 fmt 读取结果；默认更接近 observation，而不是 fact
- `FmtWriteRequest`：描述用户层原始写入请求
- `FmtWriteAtom`：描述最小独立写单元，新增了 `end_address` 便于 payload/executor 做区间判断
- `FmtWriteTask`：描述一个可独立执行的任务，新增了 `total_atoms`
- `FmtWritePlan`：描述 service 输出的完整计划，额外暴露 `total_atoms`、`total_tasks` 与 `is_blind_safe`
- `FmtRenderStep`：描述单个 atom 在 renderer 阶段的具体决策，包括 padding、arg index、specifier 与计数器推进
- `RenderedFmtTask`：描述 renderer 产出的纯字节任务，包含最终 payload、layout、初始/最终计数器
- `FmtExecutionMethod`：描述 executor 最终采用的分发方式，例如 `sendline` 或 `exchange`
- `FmtExecutionReceipt`：描述一次 task 执行回执，包含 `rendered`、`payload`、`response`、`transport_kind` 与 `dispatch`

这组 FMT DTO 现在统一采用 `slots=True, frozen=True`。语义上它们是“可缓存、可对比、可入库”的 IR，而不是 service 内部可随手改写的状态对象。为避免出现“dataclass 冻结了但 metadata 还能被偷偷改”的假不可变状态，`metadata` 也会在构造时被冻结。

配套枚举：

- `FmtWriteStrategy`
- `FmtReadMode`
- `FmtTaskPolicy`
- `FmtLayoutPolicy`

以及基础别名：

- `AddressLike`
- `ValueLike`
- `FmtEndian`

## Libc Catalog 模型

新增的 libc catalog DTO 只服务于“版本候选检索”这条链路，不参与现有 `EvidenceRegistry` 的会话内事实存储：

- `LibcLeakConstraint`：描述单条符号泄漏约束，内置 `offset_12bit` 便于直接映射 SQLite 检索键。
- `LibcCandidate`：描述单个 libc 候选，保留 `libc_id` / `name` / `arch` / `build_id` 与匹配结果。
- `LibcSearchResult`：描述一次查询的完整返回，包含约束集合、候选列表、是否存在精确匹配以及查询模式。

这组模型的目标是让未来的 `InferenceService` 只消费结构化对象，而不是直接拼接 SQL。

`BaseInferenceResult` 当前暴露：

- `raw_base`
- `aligned_base`
- `stored_fact`
- `value`

其中 `value` 是 `aligned_base` 的语义化别名，方便脚本里直接继续做地址计算。

## 为什么要显式带 `domain`

`domain` 用来给未来插件预留能力域，不让所有记录都挤在一个平面命名空间里。

例如：

- `RecordDomain.LIBC`
- `RecordDomain.FMT`
- `RecordDomain.HEAP`
- `RecordDomain.TRANSPORT`
- `RecordDomain.DEBUGGER`
