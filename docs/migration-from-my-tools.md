# 从 `my_tools.py` 迁移

## 旧版能力概述

旧版脚本通常通过单一 `MyTool` 对象完成启动、泄漏记录、blind 试探和地址推导，状态多以松散字典读取。

## 新版对应关系

- `MyTool` -> `Tool`（二者当前仍是同一实现）
- `BlindFmtTool` -> `Blind`
- `leaks_data` -> `PwnRegistry` 统一视图（地址记录 + misc）
- `add_log()` -> 兼容入口，底层进入结构化 Registry

## 常见迁移示例

### `MyTool` -> `Tool`

```python
# old
from my_tools import MyTool
p = MyTool("./challenge")

# new
from chun import Tool
p = Tool("./challenge")
```

### `BlindFmtTool` -> `Blind`

```python
# old
from my_tools import BlindFmtTool

# new
from chun import Blind
```

### `leaks_data` -> Registry/地址记录

```python
# old
print(p.leaks_data.get("puts@libc"))

# new (推荐)
record = p.reg.get_record("puts@libc")
print(record.value if record else None)
```

### `add_log()` 兼容写法与推荐写法

```python
# 兼容写法（仍支持）
p.add_log("puts@libc", leak_addr)
p.add_log(stage="leak-ok")

# 推荐写法（语义更明确）
p.api.record_libc_symbol("puts", leak_addr)
p.api.record_note("stage", "leak-ok")
```

## 兼容与不建议依赖的行为

- 仍兼容：`my_tools.py` 导入、`add_log()`、`show()`/`puts_log()`
- 推荐迁移：优先使用 `Tool.api.record_* / Tool.api.infer_*`
- 不建议继续依赖：把所有状态当单层 dict 读写；推荐改为 `record/base/misc` 分层访问
