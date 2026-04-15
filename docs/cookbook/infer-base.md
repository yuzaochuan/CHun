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
print(hex(result.value))
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
- `value`：`aligned_base` 的别名，适合直接参与后续地址计算

当前阶段的 inference 目标是打通最小闭环，不是提前实现完整评分系统。

## Libc Catalog 候选检索

当 `InferenceService` 注入 `libc_catalog` 后，可以直接把多条泄漏送入 catalog：

```python
from chun import CHun, LibcCatalogService

session = CHun.process("./challenge")
session.infer.libc_catalog = LibcCatalogService()

result = session.infer.libc_candidates_from_leaks(
    {
        "puts": 0x7F1234580AA0,
        "__isoc99_scanf": 0x7F1234521AB0,
    }
)

print(result.candidates)
print(session.registry.get_artifact("libc.candidates"))
print(session.registry.get_fact("libc.version"))
```

若候选唯一，`libc.version` 会自动写回 registry；若候选不唯一，只保留 artifact，不强行确认事实。
