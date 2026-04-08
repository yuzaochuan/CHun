# API 总览

## `CHun`

职责：统一工厂入口，按 target/transport 组合构建 `CHunSession`。

详见：[Session API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/tool.md)

## `Transport`

职责：统一承接连接生命周期与协议 IO。第一阶段已实现 tube / HTTP / WebSocket / blind reconnect 四类 transport。

详见：[Transport API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/transport.md)

## `Reg` / `PwnRegistry`

职责：统一情报中心，管理地址记录、base 记录、misc 数据，并提供推导与分类能力。当前阶段它仍可独立使用，但尚未完整接回新的 `CHunSession`。

详见：[Registry API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/registry.md)

## Blind Reconnect

职责：为 blind 场景提供“一次交互一条连接”的 transport 级骨架。

详见：[Blind API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/blind.md)

## 数据模型与枚举

职责：提供 `TargetSpec` / `TransportSpec` 以及 Registry 相关数据模型。

详见：[Models API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/models.md)
