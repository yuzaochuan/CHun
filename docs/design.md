# 设计说明（历史入口）

此页面已并入新文档体系，请改读当前第一阶段架构文档。旧 `Tool / my_tools.py` 入口已经不再是主设计方向。

1. 单一职责：`core / transports / plugins / utils` 分层，避免功能互相污染
2. 连接收口：通过 `TargetSpec + TransportSpec + Transport` 统一表达连接方式
3. 入口收口：通过 `CHun` / `CHunSession` 统一进入 runtime
4. 状态中心：`PwnRegistry` 继续独立保留，后续再重新接回 session
5. 复杂度分层：当前阶段先稳住 transport，后续系统按层推进

## 2.5 使用分层

- 推荐接口（普通写题）
  - `api.record_*` / `api.infer_*` / `show()`
  - 目标是“一眼可懂、拿来就打”
- 高级接口（扩展与调试）
  - `PwnRegistry` / `RecordKind` / `RecordSource` / `infer_base()`
  - 目标是“可观测、可推理、可扩展”

## 2. 模块职责

- `core/target.py`
  - ELF/libc 加载
  - 本地进程启动与远程连接
  - GDB attach

- `core/registry.py`
  - typed record 存储
  - 地址分类（启发式）
  - base 推导（候选 + 评分 + 入库）

- `core/tool.py`
  - 门面类，协调 target/registry/plugin
  - 保留旧脚本常用 API（`add_log`、`puts_log`、`auto_search_libc`）

- `plugins/blind.py`
  - Blind FMT 探测与自动重连
  - 探测结果直写 `PwnRegistry`

- `utils/display.py`
  - Snapshot 展示/输出格式

- `utils/misc.py`
  - 小工具（如 `itob`）

## 3. 当前 base 推导评分

`infer_base()` 当前评分由以下因子组成：

- 页面对齐合理性
- 候选基址地址段分类（PIE/LIBC/UNKNOWN）
- 记录语义与候选地址类型是否匹配（如 `@libc` -> `LIBC_LIKE`）
- 泄漏源置信度继承
- 与已有 base 记录一致性/冲突惩罚

后续可扩展为多泄漏交叉校验和映射约束验证。
