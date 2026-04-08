# CHun

CHun: a lightweight and evolving Pwn toolkit by Chenhun.

CHun 是一个面向长期维护的 Python Pwn 工具库，围绕 `Tool`、`Reg`、`Blind` 提供可组合的 Pwn 工作流，并保留 `my_tools.py` 的历史兼容入口。

## 核心特性

- 门面入口：`Tool`/`MyTool`/`CHun` 统一启动与状态操作
- 统一情报中心：`PwnRegistry`（别名 `Reg`）集中管理地址/base/misc
- Blind FMT 探测：`Blind` 支持自动重连、扫栈、offset 定位与回写
- 渐进迁移：兼容 `add_log()` 与旧脚本导入方式

## 安装

```bash
python -m pip install -e .
```

## 最小使用示例

```python
from chun import Tool, Blind, Reg

p = Tool("./challenge")
io = p.start()

p.add_log("puts@libc", 0x7F1234580000)
candidate = p.derive_base("puts@libc", p.libc.sym["puts"], base_name="libc")
print(hex(candidate.aligned_base), candidate.score)
p.show()
```

## 文档入口

- 文档首页：[`docs/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/index.md)
- MkDocs 配置：[`mkdocs.yml`](/Users/zaochuan/Documents/code/python/CHun_pwn/mkdocs.yml)
- API 总览：[`docs/api/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/index.md)

文档主维护位置在 `docs/`，README 只保留项目入口、安装与最小示例。

## 当前模块概览

- `src/chun/core`：`tool.py`、`registry.py`、`target.py`
- `src/chun/plugins`：`blind.py`、`fmt.py`、`heap.py`
- `src/chun/utils`：`display.py`、`misc.py`
- `my_tools.py`：历史兼容导入壳
