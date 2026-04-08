# 架构设计

## 第一阶段目标

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

## 当前阶段的 session 定位

`CHunSession` 现在只承载 transport 运行时，不提前把后续系统一次性铺满。

当前稳定字段：

- `session.target`
- `session.transport_spec`
- `session.transport`
- `session.io`

未来会继续往 `session.rec / infer / dbg / fmt / heap / tpl` 扩展，但这不在本阶段范围内。

## Transport 统一原则

上层统一拿到的都是 `session.io`，但不会强行要求所有协议完全同形：

- tube transport：`send` / `recv` / `interactive`
- HTTP transport：`request`
- WebSocket transport：`send_message` / `recv_message`
- blind reconnect transport：`exchange` / `run`

统一的是边界，不是伪造一套对所有协议都别扭的假接口。

## `PwnRegistry` 的位置

`PwnRegistry` 仍然保留在 `core/registry.py`，因为它代表的是独立的状态中心，不属于旧 `remote_mode` 架构本身。

但在这一阶段，它还没有被重新挂回新的 `CHunSession`。这是刻意控制范围，不是遗漏。
