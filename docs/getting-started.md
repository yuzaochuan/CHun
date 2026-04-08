# 快速开始

## 安装前提

- Python 3.10+
- 本地 Pwn 题建议有 `pwntools` 运行环境
- Web / WebSocket 场景建议已安装项目依赖中的 `httpx` / `websockets`

## Editable install

```bash
python -m pip install -e .
```

## 最小示例

```python
from chun import CHun

p = CHun.process("./challenge")
p.io.sendline(b"1")
print(p.io.recvuntil(b"\n"))
```

## 本地 / 远程 / SSH

```python
from chun import CHun

local = CHun.process("./challenge")
remote = CHun.remote("example.com", 31337, binary="./challenge")
ssh_remote = CHun.ssh_process(
    "example.com",
    user="ctf",
    binary="/home/ctf/challenge",
)
```

## HTTP / WebSocket

```python
from chun import CHun

http = CHun.http("http://127.0.0.1:8000")
print(http.io.request("GET", "/health"))

ws = CHun.websocket("ws://127.0.0.1:9001")
ws.io.send_message("ping")
print(ws.io.recv_message())
```

## Blind reconnect

```python
from chun import CHun


def connection_factory():
    return CHun.remote("example.com", 31337).raw


blind = CHun.blind(connection_factory)
result = blind.io.exchange(
    b"%7$p",
    receive=lambda io: io.recvuntil(b"\n"),
    newline=True,
)
print(result)
```

## 当前阶段边界

- 已落地：session 入口、spec 模型、四类 transport
- 暂未重建：完整 Registry 新架构、Inference 新系统、fmt/heap/template 主体
