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

## `Replay`

职责：提供 compact replay trace 的记录、切片、独立会话回放与 probe 验证执行能力，是 `fmt` 自动验证等运行期能力的基础设施。

详见：[Replay API](replay.md)

## Debug / Resolve

职责：提供 `session.dbg`、`session.gdb_mi`、`session.resolve`、`session.crash`，打通 GDB、DynELF、core dump 三条关键 workflow。

详见：[Debug & Resolve API](debug.md)

## Blind Reconnect

职责：为 blind 场景提供“一次交互一条连接”的 transport 级骨架。

详见：[Blind API](blind.md)

## FMT

职责：提供 offset 探测、read primitive、write plan/render/execute 闭环，以及脚本态可直接使用的 `read()` / `write()` / `writes()` 高层 façade。

详见：[FMT API](fmt.md)

## Workflow / Action IR

职责：把 exploit 脚本稳定转成 `top-level block + function def + call edge + primitive` 的 action IR，并按需展开成 replay 可消费的 transcript；同时提供第一版本地 process runtime / launcher / executor，以及 `chun workflow export/run` 的 JSON 导出执行闭环。

详见：[Workflow API](workflow.md)

## 数据模型与枚举

职责：提供 `TargetSpec` / `TransportSpec`、Registry 相关数据模型、FMT 计划模型、Workflow / Action IR 结构，以及 libc catalog 的结构化查询结果对象。

详见：[Models API](models.md)

## Libc Catalog

职责：提供独立于 `EvidenceRegistry` 的 SQLite libc 版本库边界；builder 现已支持核心符号筛选、`--all` 全量构建模式和基于 `score` 的候选排序。

详见：[架构设计](../architecture.md)
