# Base 推导流程

## 目标

通过“泄漏地址 + 已知 symbol offset”得到 base candidate，并理解评分与 reasons。

## 示例

```python
from chun import CHun, RecordDomain

session = CHun.process("./challenge")

puts_leak = 0x7F1234580000
puts_offset = 0x080000

session.rec.record_symbol_leak(
    "puts",
    puts_leak,
    domain=RecordDomain.LIBC,
    source="got",
)
result = session.infer.libc_base_from_symbol_leak("puts", symbol_offset=puts_offset)

print(hex(result.raw_base))
print(hex(result.aligned_base))
print(session.registry.get_fact("libc.base"))
```

如果只想直接读取事实层，可以改用：

```python
fact = session.registry.get_fact("libc.base")
print(fact.value if fact else None)
```

如果想看这次推导和哪条 observation 关联：

```python
result = session.infer.libc_base_from_symbol_leak("puts", symbol_offset=puts_offset)
print(result.observation_name, hex(result.aligned_base))
```

## 如何解读结果

- `aligned_base`：页对齐后的候选值，通常作为后续基址
- `raw_base`：按 observation 减去 offset 后得到的原始结果
- `stored_fact`：已经写回 registry 的 `Fact`

当前阶段的 inference 目标是打通最小闭环，不是提前实现完整评分系统。
