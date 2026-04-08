# 本地 ELF 调试流程

## 场景

你有本地 ELF，可以直接起进程并结合 GDB 调试。

## 基本流程

```python
from chun import CHun

p = CHun.process("./challenge")
io = p.io.raw

io.sendline(b"1")
print(io.recvuntil(b"\n"))
```

## 建议

- 这一阶段先把本地进程运行时迁移到 `CHun.process()`
- 调试器桥接尚未进入第一阶段实现，后续再单独落地
