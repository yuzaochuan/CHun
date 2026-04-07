from chun import Blind, Tool


def io_factory():
    # 按你的题目实际情况创建连接（process/remote）
    raise NotImplementedError


def interact(io, payload: bytes) -> bytes | None:
    # 按你的程序协议实现收发逻辑
    io.sendline(payload)
    return io.recvline(timeout=1)


def main() -> None:
    t = Tool("./challenge")
    b: Blind = t.new_blind_tool(io_factory=io_factory, interact_func=interact, delay=0.05)

    b.dump_stack_ptrs(start_idx=1, end_idx=40)
    t.show()


if __name__ == "__main__":
    main()
