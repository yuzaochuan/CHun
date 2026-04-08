# Base 推导流程

## 目标

通过“泄漏地址 + 已知 symbol offset”得到 base candidate，并理解评分与 reasons。

## 示例

```python
from chun import Tool

p = Tool("./challenge")

puts_leak = 0x7F1234580000
puts_offset = 0x080000

# 推荐写法：高频流程走 api
p.api.record_libc_symbol("puts", puts_leak)
candidate = p.api.infer_libc_base_from("puts")

print(hex(candidate.raw_base))
print(hex(candidate.aligned_base))
print(candidate.score)
print(candidate.reasons)
```

默认会在 infer 完成后输出 `Infer Card`（主结论 + 证据 + 派生结果 + 下一步）。
如果只想看全量状态快照，改用：

```python
p.show_snapshot()  # 保留的全量 snapshot 视图
```

如果要看调试展开（含 raw/aligned/分项评分）：

```python
p.api.infer_libc_base_from("puts", verbose=True)
# 或
p.show_last_infer(verbose=True)
```

Infer 输出分层：

- 事件流：简短时间线（`[*] / [+] / [!] / [-]`）
- Infer Card：默认主输出，聚焦结果与依据
- Debug 展开：仅 `verbose=True` 打开，方便调阈值与审计评分

## 如何解读评分结果

- `aligned_base`：页对齐后的候选值，通常作为后续基址
- `score`：0~1 置信评分，受地址区间、对齐质量、泄漏置信度等影响
- `reasons`：每个加减分的解释文本，可用于快速审计当前结论

注意：本次 UI 升级只改变展示层，不改变 `infer_base()` 的评分逻辑与数据模型。
