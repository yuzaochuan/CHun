# CHun 文档

## CHun 是什么

CHun 目前处于源码重构第三轮收口阶段。顶层入口已经固定为 `CHun` 工厂与 `CHunSession`，并在 transport / registry / inference 之上接入了 debug、resolve、crash 三类 bridge。

## 适用场景

- 本地 ELF 调试与远程服务题
- HTTP / API / SSRF 类题目
- WebSocket 双向消息交互
- blind 场景下的一次性重连交互

## 当前能力边界

- 已实现：`TargetSpec` / `TransportSpec` / `CHunSession`
- 已实现：`PwntoolsTubeTransport`、`HttpxTransport`、`WebSocketTransport`、`BlindReconnectTransport`
- 已实现：`EvidenceRegistry`、`session.rec`、`session.infer`
- 已实现：`session.dbg`、`session.gdb_mi`、`session.resolve`、`session.crash`
- 刻意未做：fmt/heap/template 主体与 pwngdb/pwndbg 深整合

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
