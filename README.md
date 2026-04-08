# CHun

CHun: a lightweight and evolving Pwn toolkit by Chenhun.

CHun 当前已进入第一阶段架构重构：顶层入口切到 `CHun` / `CHunSession`，运行时以 `TargetSpec + TransportSpec + Transport` 为地基，为后续扩展打 Transport 层基础。

## 核心特性

- 会话入口：`CHun.process()` / `CHun.remote()` / `CHun.ssh_process()`
- Web 方向 transport：`CHun.http()` / `CHun.websocket()`
- Blind transport：`CHun.blind()` + `BlindReconnectTransport`
- 第一阶段主力 transport：`PwntoolsTubeTransport` / `HttpxTransport` / `WebSocketTransport`
- `PwnRegistry` 仍保留为独立状态中心，后续阶段再接回完整 session

## 安装

```bash
python -m pip install -e .
```

## 最小使用示例

```python
from chun import CHun

p = CHun.process("./challenge")
p.io.sendline(b"1")
print(p.io.recvuntil(b"\n"))
```

## 多种连接方式

```python
from chun import CHun

local = CHun.process("./challenge")
remote = CHun.remote("127.0.0.1", 31337, binary="./challenge")
http = CHun.http("http://127.0.0.1:8000")
ws = CHun.websocket("ws://127.0.0.1:9001")

resp = http.io.request("GET", "/health")
print(resp)

ws.io.send_message("ping")
print(ws.io.recv_message())
```

## Blind reconnect 示例

```python
from chun import CHun

blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
response = blind.io.exchange(
    b"%7$p",
    receive=lambda io: io.recvuntil(b"\n"),
    newline=True,
)
print(response)
```

## 文档入口

- 文档首页：[`docs/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/index.md)
- MkDocs 配置：[`mkdocs.yml`](/Users/zaochuan/Documents/code/python/CHun_pwn/mkdocs.yml)
- API 总览：[`docs/api/index.md`](/Users/zaochuan/Documents/code/python/CHun_pwn/docs/api/index.md)

文档主维护位置在 `docs/`，README 只保留项目入口、安装与最小示例。

## 当前模块概览

- `src/chun/facade.py`：`CHun` 顶层工厂入口
- `src/chun/core`：`session.py`、`models/`、`errors.py`、`registry.py`
- `src/chun/transports`：transport 实现与组装工厂
- `src/chun/plugins`：后续 blind/fmt/heap 插件骨架
- `src/chun/utils`：`display.py`、`misc.py`

当前阶段刻意未做完整 Registry 重构、Inference 新系统、fmt/heap/libc/template 主体实现。
