# Models 与 Enum

## 覆盖范围

- `TargetSpec`
- `TransportSpec`
- `RecordKind`
- `RecordSource`
- `AddressClass`
- `AddressRecord`
- `BaseCandidate`
- `BaseRecord`

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

## 为什么使用 `RecordKind(str, Enum)`

`str + Enum` 组合能同时获得：

- 枚举约束（类型安全）
- 字符串兼容（便于日志、序列化、展示）

所以代码里既可以比较枚举成员，也能稳定输出 `value`。

## 数据模型如何支撑 Registry 与 Transport

- `TargetSpec`：描述目标
- `TransportSpec`：描述 transport 配置
- `AddressRecord`：记录单条地址及其语义元信息
- `BaseCandidate`：承载 `infer_base()` 的候选评分结果
- `BaseRecord`：承载“达阈值后正式确认”的 base

模型层让 Registry 不只是“存值”，而是“存值 + 存上下文 + 存可信度”。

## `set[AddressClass]` 这种类型注解是什么意思

在 Python 3.9+ 中，`set[AddressClass]` 表示“元素类型是 `AddressClass` 的集合”。它是静态类型信息，帮助阅读、IDE 补全和类型检查，不改变运行时集合行为。

## `@staticmethod` 在辅助函数中的作用

像 `_coerce_kind()`、`_coerce_source()` 这类函数不依赖实例状态，用 `@staticmethod` 可以明确表达“它是类内工具函数”，调用时无需 `self`。
