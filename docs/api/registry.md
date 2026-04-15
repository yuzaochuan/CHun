# Registry API

## `EvidenceRegistry` 的职责

`EvidenceRegistry` 是 CHun 第二阶段正式落地的统一事实层，负责：

- 记录原始观测（`observations`）
- 记录稳定事实（`facts`）
- 记录可复用产物（`artifacts`）
- 记录会话上下文（`context`）

## 四类记录分别是什么

- `observations`
  - 原始观测，不保证已经被证明
  - 例如 symbol leak、HTTP 响应、blind 探测结果
- `facts`
  - 已确认或经过归纳的稳定结论
  - 例如 `libc.base`、`fmt.input_offset`
- `artifacts`
  - 可复用产物
  - 例如 payload、脚本、模板渲染结果、libc catalog 检索结果
- `context`
  - 会话背景信息
  - 例如 target kind、transport kind、libc path

## 记录 API

主入口是显式 typed API，而不是万能 `add_log()`：

- `record_observation()`
- `record_symbol_leak()`
- `record_fact()`
- `record_artifact()`
- `set_context()`

所有记录都显式携带语义字段：

- `kind`
- `domain`
- `source`
- `confidence`
- `tags`
- `metadata`

## 查询与读取

- `get_observation(name)`
- `get_fact(name)`
- `get_artifact(name)`
- `get_context(name)`
- `find_observations(...)`
- `find_facts(...)`
- `find_artifacts(...)`
- `find_context(...)`

查询维度目前支持：

- `domain`
- `kind`
- `tag`
- `source`

## 覆盖与更新规则

所有写接口都支持 `overwrite=`。

- `overwrite=True`
  - 用新记录覆盖旧记录
- `overwrite=False`
  - 若记录已存在则抛出 `RegistryConflictError`

这让“更新”和“防止误覆盖”变成显式行为。

## 与 `CHunSession` 的关系

每个 session 都会稳定持有一个 registry：

- `session.registry`
- `session.rec`

并在创建时自动写入最小上下文：

- `session.target`
- `session.target.kind`
- `session.transport`
- `session.transport.kind`
- `session.transport.is_open`

运行期补充：

- 首次访问 `session.io`（触发 lazy open）后，会刷新 `session.transport.is_open`
- 若 transport 暴露 `raw`，还会写入 `session.transport.raw_type`

## 最小 inference 闭环

`session.infer.libc_base_from_symbol_leak()` 会：

1. 从 observation 读取 symbol leak
2. 按给定 `symbol_offset` 推导 base
3. 把结果写回 fact，例如 `libc.base`

这证明新的 registry 不是纯存储壳，而是能承接 session + inference 的最小工作流闭环。

`session.infer.libc_candidates_from_leaks()` 在注入 `libc_catalog` 后还会：

1. 调用 SQLite catalog 检索候选
2. 把完整 `LibcSearchResult` 写入 artifact，默认名为 `libc.candidates`
3. 若候选唯一，则自动写入 `libc.version` fact

## 当前推荐入口

- 类型名使用 `EvidenceRegistry`
- 会话内访问优先使用 `session.registry`
- 需要短写时使用 `session.rec`

不再把额外别名当作长期公开接口。
