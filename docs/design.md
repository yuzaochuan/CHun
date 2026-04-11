# 设计说明（历史入口）

此页面已并入新文档体系，请改读当前架构文档。旧 `Tool / my_tools.py` 入口已经不再是主设计方向。

1. 单一职责：`core / transports / plugins / utils` 分层，避免功能互相污染
2. 连接收口：通过 `TargetSpec + TransportSpec + Transport` 统一表达连接方式
3. 入口收口：通过 `CHun` / `CHunSession` 统一进入 runtime
4. 状态中心：新的 `EvidenceRegistry` 作为统一事实层挂接到 session
5. 复杂度分层：先稳住 transport 与 registry，再继续扩展后续系统

## 2.5 使用分层

- 推荐接口（普通写题）
  - `session.rec.*` / `session.infer.*`
  - 目标是“一眼可懂、拿来就打”
- 高级接口（扩展与调试）
  - `EvidenceRegistry` / typed records / explicit inference rules
  - 目标是“可观测、可推理、可扩展”

## 2. 模块职责

- `core/target.py`
  - ELF/libc 加载
  - 本地进程启动与远程连接
  - GDB attach

- `core/registry/`
  - observation / fact / artifact / context 存储
  - typed query 与显式覆盖规则

- `core/tool.py`
  - 门面类，协调 target/registry/plugin
  - 保留旧脚本常用 API（`add_log`、`puts_log`、`auto_search_libc`）

- `plugins/blind.py`
  - Blind FMT 探测与自动重连
  - 探测结果可回写到 `EvidenceRegistry`

- `utils/display.py`
  - Snapshot 展示/输出格式

- `utils/misc.py`
  - 小工具（如 `itob`）

## 3. 当前 inference 方向

当前已经落地最小 inference 闭环：

- symbol leak observation
- 减去已知 symbol offset
- 写回 base fact

后续可扩展为多泄漏交叉校验、冲突裁决和更完整的规则库。
