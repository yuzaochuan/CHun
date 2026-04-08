# CHun 设计说明（第一阶段）

## 1. 设计原则

1. 单一职责：`core / plugins / utils` 分层，避免功能互相污染
2. 状态收口：泄漏和推导结果统一进入 `PwnRegistry`
3. API 稳定：通过 `Tool`（`MyTool` 别名）统一入口
4. 渐进迁移：保留 `my_tools.py` 兼容层，降低旧脚本迁移风险

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
