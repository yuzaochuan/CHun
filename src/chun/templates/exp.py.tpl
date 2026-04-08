from chun import Tool


def main() -> None:
    t = Tool("./challenge")
    io = t.start()

    # 示例：手工登记泄漏并推导 base
    # t.add_log("puts@libc", 0x7ffff7a5f5e0)
    # t.derive_base("puts@libc", t.libc.sym["puts"], base_name="libc")

    t.show()
    io.interactive()


if __name__ == "__main__":
    main()
