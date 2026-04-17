# 路线图

## 近期

- Registry 稳定化：补全记录语义与推导可解释性
- Blind/session 联动：在新的 transport runtime 上重新接回 blind 结果消费路径
- Snapshot/UI 美化：优化 `puts_log()` 的可读性与分组展示

## 中期

- fmt 执行层：在已落地的 `session.fmt` 计划层之上补齐 payload builder / executor
- flow 层：抽象多阶段利用流程的状态推进
- heap 模块：补齐堆题常见分析与记录接口

## 远期

- 自动环境感知：更稳的本地/远程差异处理
- GDB 联动增强：上下文回写与断点信息同步
- 更稳的 base 推断与上下文同步：多泄漏交叉验证与冲突裁决
