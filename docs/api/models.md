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

## 数据模型如何支撑 Registry 与 Transport

- `TargetSpec`：描述目标
- `TransportSpec`：描述 transport 配置
- `Observation`：记录原始观测
- `Fact`：记录稳定结论
- `Artifact`：记录可复用产物
- `ContextEntry`：记录会话上下文
- `BaseInferenceResult`：承载最小 base inference 闭环结果

模型层让 Registry 不只是“存值”，而是“存值 + 存上下文 + 存可信度”。

## 为什么要显式带 `domain`

`domain` 用来给未来插件预留能力域，不让所有记录都挤在一个平面命名空间里。

例如：

- `RecordDomain.LIBC`
- `RecordDomain.FMT`
- `RecordDomain.HEAP`
- `RecordDomain.TRANSPORT`
- `RecordDomain.DEBUGGER`
