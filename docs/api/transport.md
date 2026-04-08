# Transport API

## 统一边界

CHun 第一阶段把连接层独立为 transport。上层统一通过 `session.io` 进入，但不同协议保留自己的自然接口。

## `PwntoolsTubeTransport`

覆盖：

- `process`
- `remote`
- `ssh.process`

主要方法：

- `open()` / `close()` / `reconnect()`
- `send()` / `sendline()`
- `recv()` / `recvuntil()`
- `interactive()`

## `HttpxTransport`

用途：

- Web / API / SSRF / 服务题

主要方法：

- `open()` / `close()`
- `request(method, path="", **kwargs)`

说明：

- 默认使用 `httpx.Client`
- 可通过 `client_factory` 注入自定义 client，便于测试或内嵌靶场

## `WebSocketTransport`

用途：

- WebSocket 服务
- 双向消息交互题

主要方法：

- `open()` / `close()`
- `send_message(message)`
- `recv_message()`

## `BlindReconnectTransport`

用途：

- blind 探测
- 每次请求都要重开连接
- 不适合长连接复用的目标

主要方法：

- `open()` / `close()`
- `exchange(payload, *, receive=None, newline=False)`
- `run(operation)`

设计重点：

- 每次交互单独创建连接
- 连接工厂可注入
- 不依赖跨请求长连接状态
