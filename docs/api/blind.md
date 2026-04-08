# Blind API

## 使用场景

`Blind`（`BlindFmtTool`）用于盲注/无本地 ELF 的格式化字符串探测：当你无法依赖本地符号和调试信息时，仍可通过 `%p/%s` 逐步建立情报。

## `io_factory` 与 `interact_func` 的职责

- `io_factory: () -> TubeLike`：负责创建新连接，供自动重连使用
- `interact_func(io, payload) -> bytes | None`：定义“如何发送 payload 并拿到响应”

两者解耦后，Blind 不绑定特定菜单协议。

## 自动重连逻辑

`_safe_interact()` 在遇到 `EOFError/BrokenPipeError/ConnectionResetError` 或回调返回 `None` 时会：

1. 关闭当前连接
2. 清空 `current_io`
3. 下次交互时通过 `io_factory` 重建连接

## 关键方法

- `dump_stack_ptrs(start_idx=1, end_idx=50, fast=True, record_hits=True)`
  - 批量发送 `%<idx>$p`
  - 命中地址时可写入 `fmt.stack.<idx>`
  - 检测到 `0x2425/0x7024` 特征时记录 `fmt.input_offset`

- `dump_strings(start_idx=1, end_idx=50)`
  - 批量发送 `%<idx>$s`
  - 命中的可读字符串写入 `fmt.string.<idx>`（misc）

- `find_input_offset(marker=b"PwnTool", max_range=30)`
  - 用 marker 小端特征定位输入 offset
  - 命中后同步写入 `fmt.input_offset`

## 边界与风险

- Blind 结果受目标行为和网络抖动影响，稳定性天然弱于本地调试
- `%s` 探测可能触发崩溃或超时，属于正常风险
- `offset` 命中是启发式，建议后续复核

## 历史兼容说明

- `Blind` 是 `BlindFmtTool` 的别名
- `Tool.new_blind_tool()` 仍保留旧脚本友好的挂载方式
