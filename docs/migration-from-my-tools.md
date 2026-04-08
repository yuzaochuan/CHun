# 从 `my_tools.py` 迁移

## 这次迁移的方向

第一阶段重构不再保留 `my_tools.py` 兼容层，也不再把 `Tool` 作为主入口。迁移目标不是“旧接口原样挪过去”，而是把脚本切到新的 session + transport 入口。

## 对应关系

- `MyTool("./chall")` -> `CHun.process("./chall")`
- `MyTool(..., host=..., port=..., remote_mode=True)` -> `CHun.remote(host, port, binary=...)`
- `remote_mode: bool` -> `TargetSpec.kind` / `TransportSpec.kind`
- `BlindFmtTool` 的“自动重连”职责 -> `CHun.blind()` / `BlindReconnectTransport`

## 常见迁移示例

### 本地进程

```python
# old
from my_tools import MyTool
p = MyTool("./challenge")
io = p.start()

# new
from chun import CHun
p = CHun.process("./challenge")
io = p.io.raw
```

### 远程连接

```python
# old
p = MyTool("./challenge", host="example.com", port=31337, remote_mode=True)
io = p.start()

# new
p = CHun.remote("example.com", 31337, binary="./challenge")
io = p.io.raw
```

### blind reconnect

```python
from chun import CHun


blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
response = blind.io.exchange(
    b"%9$p",
    receive=lambda io: io.recvuntil(b"\n"),
    newline=True,
)
```

## 当前阶段不再承诺的行为

- `my_tools.py` 导入
- `Tool` / `MyTool` 旧表面 API
- `remote_mode` 布尔切换
- 把 blind / local / remote / web 逻辑继续揉在一个类里

## 仍然保留但尚未重新挂回 session 的部分

- `PwnRegistry`
- `infer_base()` 相关推导能力

这些能力仍可独立使用，但完整的新 session 集成属于后续阶段。
