# Blind FMT 推荐工作流

## 目标

在没有本地 ELF、而且目标随时可能断线的条件下，先用 blind reconnect transport 建立可重复交互骨架。

## 工作流

```python
from chun import CHun

blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)

payloads = [b"%1$p", b"%2$p", b"%3$p"]
for payload in payloads:
    result = blind.io.exchange(
        payload,
        receive=lambda io: io.recvuntil(b"\n"),
        newline=True,
    )
    print(payload, result)
```

## 实践要点

- 当前阶段先解决“每次交互都能稳定重建连接”
- Blind 探针编排、offset 自动发现、Registry 回写属于后续阶段
- 把每次交互封装成 `exchange()` 或 `run()`，比依赖长连接状态更稳
