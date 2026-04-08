# 远程目标流程

## 场景

目标只能远程访问，且可能存在断线或限流。

## 上下文组织建议

```python
from chun import Tool

p = Tool("./challenge", host="example.com", port=31337, remote_mode=True)
io = p.start()

# 记录远程上下文（非地址信息）
p.add_log(remote_target="example.com:31337", phase="warmup")

# 记录地址类情报
p.add_log("puts@libc", 0x7F1234580000)
p.show()
```

## 非地址信息记录方式

- 非 `int` 值（如 `phase`、`remote_target`）会进入 `misc`
- 地址值进入 typed record，可继续用于分类与 base 推导
