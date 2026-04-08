# Session API

## 顶层入口

当前主入口是 `CHun` 工厂，而不是旧 `Tool`。

```python
from chun import CHun

local = CHun.process("./challenge")
remote = CHun.remote("example.com", 31337, binary="./challenge")
http = CHun.http("http://127.0.0.1:8000")
ws = CHun.websocket("ws://127.0.0.1:9001")
blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
```

## `CHunSession`

每个工厂方法都会返回一个 `CHunSession`。第一阶段它只承载 transport 相关运行时：

- `target`：`TargetSpec`
- `transport_spec`：`TransportSpec`
- `transport`：实际 transport 实例
- `io`：延迟打开后的 transport 访问入口
- `raw`：底层原始连接对象

## 工厂方法

- `CHun.process(binary, *, argv=None, env=None, cwd=None, log_level="info")`
- `CHun.remote(host, port, *, binary=None, timeout=None)`
- `CHun.ssh_process(host, *, user, binary, argv=None, port=22, ...)`
- `CHun.http(base_url, *, headers=None, timeout=None, follow_redirects=True, verify=True)`
- `CHun.websocket(ws_url, *, headers=None, timeout=None, connect_timeout=None)`
- `CHun.blind(connection_factory, *, timeout=None)`

## 会话生命周期

- `session.open()`：显式打开 transport
- `session.close()`：关闭 transport
- `session.reconnect()`：重建 transport
- `session.io`：首次访问时自动打开 transport

## 示例

```python
from chun import CHun

p = CHun.process("./challenge")
p.io.sendline(b"1")
print(p.io.recvuntil(b"\n"))

api = CHun.http("http://127.0.0.1:8000")
print(api.io.request("GET", "/health"))
```

## 本阶段边界

- 已完成：session/runtime 入口与 transport 组装
- 未完成：完整 `session.rec / infer / dbg / fmt / heap / tpl` 子系统
