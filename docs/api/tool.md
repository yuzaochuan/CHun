# Tool API

## 类作用

`Tool`（别名：`MyTool`、`CHun`）是门面类。它持有：

- `target`：`TargetSession`，负责本地/远程 IO
- `reg`：`PwnRegistry`，负责状态管理
- `blind`：懒加载的 `BlindFmtTool`

## 初始化参数

`Tool(file_path, libc_path=None, host=None, port=None, remote_mode=False, log_level="debug", terminal=("tmux","splitw","-h"))`

核心参数：

- `file_path`：目标 ELF 路径
- `libc_path`：可选 libc 路径
- `host/port/remote_mode`：远程模式参数

## 关键属性

- `elf`：兼容访问 `target.elf`
- `libc`：兼容访问 `target.libc`
- `leaks_data`：兼容视图（地址记录平铺 + misc）
- `api`：推荐用户接口入口（`RecommendedToolAPI`）

## 关键方法

- `start()`：启动本地进程或远程连接
- `gdb()`：仅在 `args.GDB` 时 attach
- `add_log()`：兼容写入口，自动分流地址与 misc
- `show(verbose=False)` / `puts_log(verbose=False)`：打印 Registry 快照（默认简洁，`verbose=True` 展开元信息）
- `classify_address()`：地址启发式分类
- `infer_base()` / `derive_base()`：泄漏 + offset 推导 base 候选
- `auto_search_libc()`：可选依赖 `LibcSearcher` 的自动匹配
- `new_blind_tool()`：创建并挂载共享 Registry 的 `BlindFmtTool`

## 推荐接口（`Tool.api`）

`Tool.api` 暴露高频写题能力，避免主类持续膨胀。

- `api.connect()`：远程连接语义化别名（等价于 `start(remote_mode=True)`）
- `api.record_libc_symbol()` / `api.record_stack_ptr()` / `api.record_heap_ptr()`
- `api.record_base()` / `api.record_derived()` / `api.record_note()`
- `api.infer_libc_base_from()` / `api.infer_pie_base_from()`
- `api.show()`：透传 `Tool.show()`

## 使用示例

```python
from chun import Tool

p = Tool("./challenge", host="127.0.0.1", port=9999)
io = p.start(remote_mode=False)

# 推荐写法：通过 api 记录与推导
p.api.record_libc_symbol("puts", 0x7F1234580000)
ret = p.api.infer_libc_base_from("puts")
print(ret.score)

# 默认简洁快照；调试时可打开详细视图
p.show()
p.show(verbose=True)

blind = p.new_blind_tool(io_factory=lambda: p.start(remote_mode=True), interact_func=lambda io, pl: None)
```

## 注意事项

- `auto_search_libc()` 依赖第三方 `LibcSearcher`，未安装会直接返回空结果
- `leak_stack()` 仍保留但偏历史兼容，不建议作为长期主流程
