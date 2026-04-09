# 架构设计

## 第一阶段回顾

第一阶段不再围绕 `Tool(remote_mode=...)` 修修补补，而是先把连接层彻底独立出来。当前实现优先建立四个稳定边界：

- `TargetSpec`：目标是什么
- `TransportSpec`：这次要怎么连
- `Transport`：真正负责生命周期与 IO
- `CHunSession`：最小可用 runtime 入口

## 为什么先重建 Transport 层

旧架构里，本地进程、远程连接、blind 自动重连都混在门面类里，直接导致：

- 连接方式只能靠 `remote_mode: bool` 切换
- `Tool` 越长越像 God object
- Web / HTTP / WebSocket 很难自然放进去
- blind 场景和长连接场景没有清晰边界

第一阶段的重构目标就是把这些分支从门面类里拆出来，改成显式的 transport 层。

## 当前目录边界

- `src/chun/core/models`
  - `TargetSpec`
  - `TransportSpec`
- `src/chun/core/session.py`
  - `CHunSession`
- `src/chun/transports`
  - `PwntoolsTubeTransport`
  - `HttpxTransport`
  - `WebSocketTransport`
  - `BlindReconnectTransport`
  - `build_transport()`
- `src/chun/facade.py`
  - `CHun.process()/remote()/ssh_process()/http()/websocket()/blind()`

## 第二阶段目标

第二阶段把新的事实层正式挂回 `CHunSession`，让后续 fmt / heap / debugger / template 都围绕统一 registry 工作，而不是继续依赖分散记录。

这次落地的核心边界是：

- `observations`：原始观测
- `facts`：稳定结论
- `artifacts`：可复用产物
- `context`：会话环境与背景信息

## 当前阶段的 session 定位

`CHunSession` 现在已经承载 transport、registry 与最小 inference，但仍然不会把后续系统一次性铺满。

当前稳定字段：

- `session.target`
- `session.transport_spec`
- `session.transport`
- `session.registry`
- `session.rec`
- `session.infer`
- `session.io`
- `session.dbg`
- `session.gdb_mi`
- `session.resolve`
- `session.crash`

本轮收口后，面向后续插件开发的公开入口已经固定在这组字段上；下一阶段应优先复用这些入口，而不是继续新增临时 facade。

## Transport 统一原则

上层统一拿到的都是 `session.io`，但不会强行要求所有协议完全同形：

- tube transport：`send` / `recv` / `interactive`
- HTTP transport：`request`
- WebSocket transport：`send_message` / `recv_message`
- blind reconnect transport：`exchange` / `run`

统一的是边界，不是伪造一套对所有协议都别扭的假接口。

## Registry 的位置

新的 `EvidenceRegistry` 位于 `core/registry/`，并已经正式挂接到 `CHunSession`。

它的职责不是“临时日志箱”，而是未来公共地基：

- transport 可以写入 context
- session 可以统一访问 observation / fact / artifact / context
- inference 可以从 observation 读取并写回 fact
- 后续插件可以稳定依赖这层事实模型

## 第三轮目标

第三轮开始把 pwntools / GDB / Corefile / DynELF 这些 exploit 工作流必需能力正式接入 session。

这次新增的重点边界是：

- `session.dbg`
  - 交互式 `PwntoolsGdbBridge`
- `session.gdb_mi`
  - 机器可解析的 `GdbMiBridge`
- `session.resolve`
  - `MemLeak` / `DynELF` / pwntools symbol 解析入口
- `session.crash`
  - `CorefileAnalyzer`

## 第三轮的设计原则

- 人类调试入口和机器分析入口分离
- bridge 产物必须回写 registry
- ret2libc / blind leak / core dump 三条 workflow 优先打通
- 不提前展开 fmt / heap / template 主体

## 当前公开 API 收口

当前对外只保留以下稳定主路径：

- 顶层工厂：`CHun.process()` / `CHun.remote()` / `CHun.ssh_process()` / `CHun.http()` / `CHun.websocket()` / `CHun.blind()`
- 会话入口：`session.io` / `session.registry` / `session.rec` / `session.infer`
- bridge / workflow：`session.dbg` / `session.gdb_mi` / `session.resolve` / `session.crash`

不再把重复别名当作长期公开接口，例如旧的 `CHun.binary`、`Registry`、`Session` 不再作为推荐入口保留。

---

维护者说明：

- facade 层当前采用“双层接口”策略：公开层保留人类友好的显式工厂，内部层统一收敛到 `TargetSpec` / `TransportSpec` builder
- `CHun.from_specs()` 是显式工厂与 `CHun.script()` 的共同装配入口
- `CHun.script()` 属于脚本态 convenience facade，不引入第二套 transport / debug / resolve 架构
- 后续如果 target 或 transport 默认字段发生变化，应优先修改 facade 内部 builder，避免在显式工厂和 script facade 中分别维护
