# API 总览

## `CHun`

职责：统一工厂入口，按 target/transport 组合构建 `CHunSession`。当前稳定入口固定为 `process`、`remote`、`ssh_process`、`http`、`websocket`、`blind`。

详见：[Session API](tool.md)

## `Transport`

职责：统一承接连接生命周期与协议 IO。第一阶段已实现 tube / HTTP / WebSocket / blind reconnect 四类 transport。

详见：[Transport API](transport.md)

## `EvidenceRegistry`

职责：统一事实层，管理 observation / fact / artifact / context，并已正式挂接到 `CHunSession`。

详见：[Registry API](registry.md)

## Debug / Resolve

职责：提供 `session.dbg`、`session.gdb_mi`、`session.resolve`、`session.crash`，打通 GDB、DynELF、core dump 三条关键 workflow。

详见：[Debug & Resolve API](debug.md)

## Blind Reconnect

职责：为 blind 场景提供“一次交互一条连接”的 transport 级骨架。

详见：[Blind API](blind.md)

## 数据模型与枚举

职责：提供 `TargetSpec` / `TransportSpec`、Registry 相关数据模型、FMT 计划模型，以及 libc catalog 的结构化查询结果对象。

详见：[Models API](models.md)

## Libc Catalog

职责：提供独立于 `EvidenceRegistry` 的 SQLite libc 版本库边界；builder 现已支持核心符号筛选、`--all` 全量构建模式和基于 `score` 的候选排序。

详见：[架构设计](../architecture.md)
