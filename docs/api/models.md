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
