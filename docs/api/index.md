# API 总览

## `Tool`

职责：面向脚本作者的主入口，协调目标启动、Registry 写入、base 推导和 blind 插件挂载。

详见：[Tool API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/tool.md)

## `Reg` / `PwnRegistry`

职责：统一情报中心，管理地址记录、base 记录、misc 数据，并提供推导与分类能力。

详见：[Registry API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/registry.md)

## `Blind`

职责：盲格式化字符串探测（自动重连、扫栈、扫字符串、offset 定位），并把结果回写 Registry。

详见：[Blind API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/blind.md)

## 数据模型与枚举

职责：为 Registry 提供稳定字段语义（`RecordKind`、`RecordSource`、`AddressClass` 等）。

详见：[Models API](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/models.md)
