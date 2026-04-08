# Registry API

## `PwnRegistry` / `Reg` 的职责

`PwnRegistry` 是 CHun 的统一情报中心，负责：

- 记录地址泄漏（`AddressRecord`）
- 记录已确认 base（`BaseRecord`）
- 保存非地址上下文（`_misc`）
- 提供 base 推导（`infer_base`）与地址分类（`classify_address`）

`Reg` 是 `PwnRegistry` 的别名，方便脚本短写。

## 三类记录分别是什么

- 地址记录（`_records`）：`name -> AddressRecord`，包括 `kind/source/confidence/notes/meta`
- base 记录（`_bases`）：`name -> BaseRecord`，保存已接受的 base
- misc 记录（`_misc`）：任意非整数上下文，如阶段标记、注释、状态字符串

## `add_log()` 兼容层语义

`add_log(name, value, **kwargs)` 用于兼容旧脚本。

- `(name, int)` 或 `kwargs` 中的 `int`：按地址记录写入
- 非 `int`：写入 `_misc`

它让旧代码保持低改造成本，同时把数据集中到统一状态中心。

## `_add_any_value()` 与 `add_log()` 的关系

当前实现中，`add_log()` 的实际分流由 `_add_any_value()` 完成：

- `int` -> `add_address(..., kind=RecordKind.LEAK)`
- other -> `_misc[key] = item`

## 关于 `_extract_add_log_meta()`

当前代码（`src/chun/core/registry.py`）没有 `_extract_add_log_meta()`。如果后续需要从 `add_log()` 自动拆解 `kind/source/confidence/meta`，建议新增该辅助函数；目前这是 Future work。

## `infer_base()` 作用、参数、返回值

作用：根据“泄漏地址 + 符号偏移”生成 base 候选并评分，可按阈值自动入库。

关键参数：

- `leak_name`：泄漏记录名（必须已存在）
- `symbol_offset`：已知符号偏移（非负）
- `base_name`：候选命名；缺省时自动推导
- `min_accept_score`：覆盖默认阈值
- `store`：是否在达标后写入 `_bases`

返回值：`BaseCandidate`（`raw_base/aligned_base/score/reasons`）。

## 评分思想（当前实现）

- 页对齐质量：已对齐加分更高
- 地址区间先验：PIE/LIBC/TEXT 更可信
- 泄漏继承：按原记录 `confidence` 加权
- 已有 base 一致性：一致加分，冲突减分

最终分数被限制在 `[0.0, 1.0]`，且只有超过阈值时才自动入库。

## `classify_address()` 启发式能力

`classify_address(value)` 返回 `AddressClass`，用于快速判断地址更像 `PIE/LIBC/STACK/HEAP`。这是提示能力，不是严格证明。

## `kind / source / confidence / notes / meta` 含义

- `kind`：记录语义（泄漏、base、栈指针等）
- `source`：来源（手工、blind、推导等）
- `confidence`：置信度（0~1）
- `notes`：人类可读备注
- `meta`：结构化上下文（payload、index、symbol_offset 等）
