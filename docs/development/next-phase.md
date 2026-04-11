# 下一阶段起点

## 当前稳定公开接口

- 顶层工厂：`CHun.process()` / `CHun.remote()` / `CHun.ssh_process()` / `CHun.http()` / `CHun.websocket()` / `CHun.blind()`
- 会话入口：`session.io` / `session.registry` / `session.rec` / `session.infer`
- 调试与解析：`session.dbg` / `session.gdb_mi` / `session.resolve` / `session.crash`
- 事实层类型：`EvidenceRegistry`、`Observation`、`Fact`、`Artifact`、`ContextEntry`

## 已知待解决问题

- ret2libc、DynELF、corefile workflow 已能闭环，但仍以最小实现为主，尚未形成更高层 exploit orchestration
- `session.resolve` 目前覆盖的是最常见解析链路，尚未扩成更完整的 resolver 规则集
- `session.crash` 已能提取关键 crash facts，但还没有更深入的利用建议或自动修复流程
- `session.dbg` / `session.gdb_mi` 只提供最小 bridge，不包含 pwngdb / pwndbg 深整合

## fmt / heap 下一阶段建议接入点

- 从 `session.registry` / `session.rec` 读取和写回事实，不要再引入插件私有状态桶
- 基础推导优先复用 `session.infer`，需要新增规则时沿现有 inference/service 继续扩展
- 需要 leak、symbol 解析、blind 读原语时，优先复用 `session.resolve`
- 需要 crash、寄存器、maps、offset 时，优先复用 `session.crash`
- 需要人工调试或结构化调试时，分别复用 `session.dbg` 与 `session.gdb_mi`

下一阶段的目标应是把 fmt / heap 插件建立在这些入口之上，而不是再次扩出新的平行 facade。
