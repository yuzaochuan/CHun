# 远程目标流程

## 场景

目标只能远程访问，且可能存在断线或限流。

## 上下文组织建议

```python
from chun import CHun

p = CHun.remote("example.com", 31337, binary="./challenge")
io = p.io

io.sendline(b"hello")
print(io.recvuntil(b"\n"))
```

## 建议

- 远程连接不再通过 `remote_mode=True` 选择，而是直接使用 `CHun.remote()`
- 如果目标经常断线，优先考虑把交互切到 `CHun.blind()` 的一次性连接模型
