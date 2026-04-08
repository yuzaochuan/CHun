# Blind API

## blind 入口的当前定位

当前 blind 场景的公开入口仍然是 transport 级骨架：

- `CHun.blind(connection_factory)`
- `BlindReconnectTransport`

## 适用场景

- 每次 payload 都可能导致连接中断
- 目标不适合长连接复用
- 需要把“如何重建连接”与“这次做什么交互”解耦

## `connection_factory`

`connection_factory: () -> object`

职责只有一个：每次 blind 交互时，返回一个新的可用连接对象。它可以返回：

- pwntools tube
- 其他带 `send` / `recv` / `close` 的对象
- 另一个 transport 实例

## 关键方法

- `exchange(payload, *, receive=None, newline=False)`
  - 建连
  - 发送 payload
  - 可选收取响应
  - 自动关闭本次连接
- `run(operation)`
  - 在一次性连接上下文里执行任意自定义逻辑

## 示例

```python
from chun import CHun


blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
result = blind.io.exchange(
    b"%7$p",
    receive=lambda io: io.recvuntil(b"\n"),
    newline=True,
)
print(result)
```

## 当前边界

- 已完成：blind reconnect transport，以及把 leak primitive 接到 `session.resolve` 的 MemLeak / DynELF 解析链路
- 未完成：完整 blind 探针编排、批量 `%p/%s` workflow
