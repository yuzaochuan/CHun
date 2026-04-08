# Base 推导流程

## 目标

通过“泄漏地址 + 已知 symbol offset”得到 base candidate，并理解评分与 reasons。

## 示例

```python
from chun import Tool

p = Tool("./challenge")

puts_leak = 0x7F1234580000
puts_offset = 0x080000

p.add_log("puts@libc", puts_leak)
candidate = p.infer_base("puts@libc", puts_offset, base_name="libc")

print(hex(candidate.raw_base))
print(hex(candidate.aligned_base))
print(candidate.score)
print(candidate.reasons)
```

## 如何解读评分结果

- `aligned_base`：页对齐后的候选值，通常作为后续基址
- `score`：0~1 置信评分，受地址区间、对齐质量、泄漏置信度等影响
- `reasons`：每个加减分的解释文本，可用于快速审计当前结论
