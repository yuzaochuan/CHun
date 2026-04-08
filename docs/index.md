# CHun 文档

## CHun 是什么

CHun 是一个以 `chun` 包为核心的 Pwn 工具库，目标是让题目脚本在“顺手写法”和“长期可维护”之间取得平衡。当前实现围绕三个核心对象展开：`Tool`、`Reg`（`PwnRegistry`）和 `Blind`。

## 适用场景

- 本地 ELF 调试与远程切换
- 泄漏地址的统一记录与回看
- 基于符号偏移的 base 候选推导
- 无本地 ELF 的 blind fmt 探测

## 当前能力边界

- 已实现：`Tool.start()`、`add_log()`、`derive_base()`、`Blind` 扫栈/偏移定位
- 已实现：`PwnRegistry` 的 typed 记录与启发式地址分类
- Future work：`plugins/fmt.py`、`plugins/heap.py` 目前仍是占位模块
- Future work：更深的多泄漏联合推导和自动化利用链路尚未落地

## 文档导航

- [快速开始](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/getting-started.md)
- [安装](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/installation.md)
- [架构设计](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/architecture.md)
- [API 总览](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/index.md)
- [Cookbook 总览](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/cookbook/index.md)

## 推荐阅读顺序

1. Getting Started
2. Installation
3. Architecture
4. API
5. Cookbook
