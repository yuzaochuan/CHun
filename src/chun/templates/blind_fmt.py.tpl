from chun import CHun


def main() -> None:
    blind = CHun.blind(lambda: CHun.remote("example.com", 31337).raw)
    blind.io.exchange(
        b"%7$p",
        receive=lambda io: io.recvuntil(b"\n"),
        newline=True,
    )


if __name__ == "__main__":
    main()
