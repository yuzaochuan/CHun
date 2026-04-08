from chun import CHun


def main() -> None:
    t = CHun.process("./challenge")
    io = t.io.raw

    io.sendline(b"1")
    io.interactive()


if __name__ == "__main__":
    main()
