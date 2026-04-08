# 本地 ELF 调试流程

## 场景

你有本地 ELF，可以直接起进程并结合 GDB 调试。

## 基本流程

```python
from chun import Tool

p = Tool("./challenge", remote_mode=False)
io = p.start()

# 可选：命令行带 GDB 时 attach
p.gdb(io, gdbscript="b *main\nc")

# 记录泄漏
p.add_log("puts@libc", 0x7F1234580000)
p.show()
```

## 建议

- 调试阶段把关键地址写入 `add_log()`，避免信息只存在终端滚屏
- 先让 Registry 数据完整，再进入自动推导和 payload 收敛
