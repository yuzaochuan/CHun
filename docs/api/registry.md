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
  - 例如 `libc.base`、`fmt.offset`
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

如果你希望在业务侧拿到“不可空且值类型明确”的结果，而不是自己手写 `None` 判断和 `isinstance(...)`，可以使用严格读取 helper：

- `require_observation(name)`
- `require_fact(name)`
- `require_artifact(name)`
- `require_context(name)`
- `require_int_observation(name)`
- `require_int_fact(name)`
- `require_str_fact(name)`

这些 helper 在记录缺失时抛 `KeyError`，在值类型不匹配时抛 `TypeError`，适合脚本层和类型检查较严格的调用点。

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
3. 若候选唯一，或显式传入 `index` 命中候选，则自动写入 `libc.version` fact
4. 一旦版本被确认，会立刻基于任一 leak 自动写入 `libc.base` fact

`session.infer.search_libc()` 进一步把“扫描 registry -> 组装 leaks -> 调 catalog”这一层也封装起来：

1. 只扫描 `domain=LIBC` 且 `kind=SYMBOL_LEAK` 的 observation
2. 跳过非整数地址
3. 同名 symbol 出现多次时，优先采用更高 `confidence` 的记录
4. 支持 `single_arch=True`：若调用方未显式传 `arch`，则优先从 `session.elf`，否则从 registry context 中的规范化标量（例如 `binary.arch`，不足时回退到 `binary.bits` / `arch.bits`）推断单一架构收窄候选
5. 支持 `index=...`，用于多候选场景下按排名静默确认目标版本
6. 若没有可用 leak，则抛 `InferenceInputError`

若命中多个候选且没有传 `index`，系统会保留 `libc.candidates` artifact，并按 `index + matched + score + arch + symbols` 的格式输出候选列表供外部爆破逻辑使用，但不会写入 `libc.version` / `libc.base`。

当 `single_arch=False` 且当前上下文仍然能推断出主架构时，候选展示会分为两段：

- `Current arch (...)`
- `Other arch`

这里的分组只影响显示，不影响底层候选顺序；`index` 始终是全局统一编号，因此 `index=0/1/2...` 仍然稳定命中对应候选。

若命中唯一候选，系统会自动确认并通过 `log.success(...)` 输出一条简短成功消息，例如 `libc resolved: libc6_2.39-0ubuntu8.6_amd64`。

`session.resolve.symbol(name)` 则会继续消费事实层：

1. 读取 `libc.base`
2. 读取 `libc.version.metadata["libc_id"]`
3. 通过本地 SQLite catalog 查询 offset
4. 返回 `libc.base + offset`

这里的 `name` 支持服务层归一化，因此 `puts@got`、`write_plt`、`str_bin_sh` 这类常见写法都可以直接传入，不需要污染底层 catalog 表结构。

脚本态还提供两个只读快捷属性：

- `t.libc_base`
- `t.libc_version`

会话态也提供同名快捷属性：

- `session.libc_base`
- `session.libc_version`

另外，registry context 只用于保存环境标量，不保存运行时 ELF / libc ELF 富对象；后者应始终挂在 `session.elf` / `session.libc_elf`。

## 当前推荐入口

- 类型名使用 `EvidenceRegistry`
- 会话内访问优先使用 `session.registry`
- 需要短写时使用 `session.rec`

不再把额外别名当作长期公开接口。
