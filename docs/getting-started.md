# 快速开始

## 安装前提

- Python 3.10+
- 建议已安装 `pwntools` 运行环境（终端/调试工具链）
- 目标二进制可本地运行，或已有远程连接参数

## Editable install

```bash
python -m pip install -e .
```

## 最小示例

```python
from chun import Tool, Blind, Reg

p = Tool("./challenge")
io = p.start()

p.add_log("puts@libc", 0x7F1234580000)
p.show()
```

## 典型工作流示例

```python
from chun import Tool

p = Tool("./challenge", host="example.com", port=31337)
io = p.start(remote_mode=False)  # 本地起进程

# 1) 记录泄漏
p.add_log("puts@libc", 0x7F1234580000)

# 2) 推导 base
candidate = p.derive_base("puts@libc", p.libc.sym["puts"], base_name="libc")
print(hex(candidate.aligned_base), candidate.score)

# 3) 查看当前全局状态
p.show()
```

## 兼容层 vs 新架构入口

- 兼容层调用：`add_log()`、`leaks_data`、`my_tools.py` 导入
- 推荐入口：`Tool` + `Reg` + `Blind` 组合，状态统一回流 `PwnRegistry`
