# 架构设计

## 为什么从 `my_tools.py` 走向模块化

历史单文件模式在题目增长后会出现两个问题：状态分散（泄漏、推导、注释混在一起）和功能耦合（本地/远程/blind 逻辑交织）。CHun 采用 `src/chun` 模块化，是为了把职责拆开并保留门面调用体验。

## `core / plugins / utils / docs` 职责边界

- `core`：稳定核心能力（目标会话、Registry、Tool 门面）
- `plugins`：可插拔专项能力（当前 blind 已实现，fmt/heap 为 Future work）
- `utils`：低层工具函数与显示逻辑
- `docs`：长期维护文档主源，不与 README 混写

## Registry 的定位

`PwnRegistry`（别名 `Reg`）是统一情报中心：

- 地址类记录：`_records`
- base 记录：`_bases`
- 非地址杂项：`_misc`

这样 `Tool`、`Blind`、未来插件都能读写同一状态，而不是各自维护临时 dict。

## `Tool` 与 `Blind` 的关系

`Tool.new_blind_tool()` 创建 `BlindFmtTool` 时会共享同一个 `registry`。blind 探测出的 `fmt.input_offset`、`fmt.stack.*` 会直接进入主 Registry，可立即参与后续推导和展示。

## `misc` 与地址记录的分流逻辑

`add_log()` 最终走到 `PwnRegistry._add_any_value()`：

- `int` 值进入地址记录（`add_address()`）
- 非 `int` 值进入 `_misc`

这个分流保持了旧接口“随手记”的体验，同时避免把字符串阶段信息误当地址。

## 为什么使用结构化记录而不是普通 dict

结构化模型（如 `AddressRecord`、`BaseRecord`）额外携带 `kind/source/confidence/notes/meta`，让记录具备可追踪语义与后续扩展能力。纯 `dict[str, int]` 虽简单，但无法稳定表达来源可信度、推导上下文和跨模块协作信息。

## 为什么保留 `add_log()` 兼容层

兼容层的目标是降低迁移成本。旧脚本可以继续用 `add_log()`，但底层写入已经统一进 Registry；后续逐步替换为更显式的 `add_address()` / `add_base()` 时，不需要一次性重写所有脚本。
