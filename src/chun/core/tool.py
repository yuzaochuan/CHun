"""CHun 门面工具类。

这份文件是理解项目的最好切入口，因为它回答了两个最关键的问题：

1. 使用者平时真正会实例化哪个对象？
2. 这个对象内部又是如何把“启动目标 / 记录情报 / Blind 探测”串起来的？

`MyTool` 保留了传统 Pwn 脚本里“一个类包办大部分常用动作”的手感，
但它自己尽量不承载复杂细节，而是把职责拆给几个内部组件：

- `TargetSession`
  - 管理 ELF / libc 元信息
  - 决定启动本地进程还是远程连接
  - 按需挂载 GDB
- `PwnRegistry`
  - 统一收口地址泄漏、base 推导结果和其他杂项状态
  - 让分析结果不再散落在脚本各个临时变量里
- `BlindFmtTool`
  - 处理 blind fmt 场景的探测、自动重连和结果同步

可以把 `MyTool` 看成“面向题目脚本作者”的稳定 API，而不是底层细节本身。
后续读懂这份文件后，再进入 `registry.py` 和 `target.py` 会顺很多。
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from .._compat import log
from ..plugins.blind import BlindFmtTool, InteractFunc
from ..utils.misc import itob
from .registry import AddressClass, BaseCandidate, PwnRegistry
from .target import DEFAULT_TERMINAL, TargetConfig, TargetSession, TubeLike

if TYPE_CHECKING:
    from .recommended import RecommendedToolAPI


class MyTool:
    """CHun 面向用户的主类。

    对外暴露的是一个尽量顺手的“脚本控制台”对象：

    - 用 `start()` 拿 IO
    - 用 `add_log()` / `derive_base()` 维护分析状态
    - 用 `new_blind_tool()` 切到 blind fmt 工作流

    它本身主要负责“协调”，不直接实现底层启动逻辑或复杂推导逻辑。
    """

    def __init__(
        self,
        file_path: str,
        libc_path: str | None = None,
        host: str | None = None,
        port: int | None = None,
        remote_mode: bool = False,
        log_level: str = "debug",
        terminal: tuple[str, ...] | list[str] = DEFAULT_TERMINAL,
    ) -> None:
        """创建一个完整初始化的 Tool 实例。

        初始化阶段做三件事：

        1. 创建一个空的 `PwnRegistry`，作为全局状态中心
        2. 根据构造参数准备 `TargetSession`
        3. 先不创建 blind 插件，等用户真的需要时再延迟挂载
        """
        self.reg = PwnRegistry()
        self.target = TargetSession(
            TargetConfig(
                binary_path=file_path,
                libc_path=libc_path,
                host=host,
                port=port,
                remote_mode=remote_mode,
                log_level=log_level,
                terminal=terminal,
            )
        )
        self.blind: BlindFmtTool | None = None
        self._api: RecommendedToolAPI | None = None

    @property
    def elf(self) -> Any:
        """暴露目标 ELF，兼容旧脚本调用习惯。

        这样旧代码仍然可以直接写 `p.elf.sym["puts"]`，
        不必先显式下钻到 `p.target.elf`。
        """
        return self.target.elf

    @property
    def libc(self) -> Any:
        """暴露 libc 对象，兼容旧脚本调用习惯。

        这个属性通常配合泄漏推导使用，例如：
        `p.derive_base("puts@libc", p.libc.sym["puts"], base_name="libc")`
        """
        return self.target.libc

    @property
    def leaks_data(self) -> dict[str, Any]:
        """兼容历史 `MyTool.leaks_data` 读法。

        老脚本常把所有分析结果当作一个大字典来读取；
        新架构里这些信息已经分流到：

        - `reg._records`：地址类记录
        - `reg._bases`：已确认 base
        - `reg._misc`：其他非整数杂项

        这里返回的是一个“兼容视图”：
        先把地址记录平铺成 `name -> value`，再合并 misc。
        """
        data: dict[str, Any] = {}
        for record in self.reg.iter_records():
            data[record.name] = record.value
        snapshot = self.reg.to_dict()
        data.update(snapshot["misc"])
        return data

    @property
    def api(self) -> "RecommendedToolAPI":
        """推荐用户接口入口（高频写题能力收口层）。

        这里通过 `@property` 懒加载包装对象，把“便捷 API”放到独立模块，
        避免 `tool.py` 继续膨胀，同时保持 `t.api.xxx()` 的调用手感。
        """
        current = getattr(self, "_api", None)
        if current is None:
            from .recommended import RecommendedToolAPI

            current = RecommendedToolAPI(self)
            self._api = current
        return current

    def start(
        self,
        host: str | None = None,
        port: int | None = None,
        remote_mode: bool | None = None,
    ) -> TubeLike:
        """启动本地进程或远程连接。

        这层只是把“用户熟悉的入口”继续留在 `Tool` 上，
        实际模式判定和 IO 创建由 `TargetSession.start()` 完成。
        """
        return self.target.start(host=host, port=port, remote_mode=remote_mode)

    def gdb(self, io_obj: TubeLike, gdbscript: str = "", show_leaks: bool = True) -> None:
        """根据命令行参数决定是否挂载 GDB。

        设计上这里不会强制 attach，而是沿用 pwntools 常见习惯：
        只有在命令行带 `GDB` 参数时才真正挂载。

        `show_leaks=True` 时，会在 attach 前先打印一次 Registry 快照，
        方便你在调试窗口打开前快速确认当前已经记录了哪些地址。
        """
        self.target.attach_gdb(
            io_obj,
            gdbscript=gdbscript,
            show_summary=self.reg.puts_log if show_leaks else None,
        )

    @staticmethod
    def itob(num: int) -> bytes:
        """把整数转成 ASCII bytes（菜单题常用）。

        这是一个很小的便利封装，保留在门面层是为了维持旧使用习惯：
        题目脚本里可以直接写 `p.itob(3)`，不需要关心工具函数所在模块。
        """
        return itob(num)

    def leak_stack(self, io_obj: TubeLike, until: bytes, cycle: int) -> None:
        """传统 `%p` 栈扫辅助函数（保留兼容，不建议长期重度依赖）。

        这属于“老脚本风格”的快速试探接口：逐个发送 `%n$p`，
        然后把响应直接打印出来，适合初期人工观察。

        更系统的 blind fmt 能力已经转移到 `BlindFmtTool` 中；
        这里保留主要是为了让已有脚本不至于立刻失效。
        """
        for index in range(1, cycle):
            io_obj.recvuntil(until)
            payload = f"%{index}$p".encode()
            io_obj.sendline(payload)
            response = io_obj.recvline()
            print(f"Index {index}: {response.decode(errors='ignore').strip()}")

    def add_log(self, name: str | None = None, value: Any = None, **kwargs: Any) -> None:
        """把手工分析结果写入 Registry。

        这是用户最常用的“状态写入口”之一。

        - 若值是整数，会被当作地址类信息写入 `PwnRegistry`
        - 若值不是整数，会进入 misc 区域
        - 支持为单条地址记录补充 `kind/source/confidence/notes/meta`

        这样做的好处是：题目脚本可以继续保持很松的调用方式，
        但内部状态组织已经变得更统一。
        """
        self.reg.add_log(name=name, value=value, **kwargs)

    def puts_log(self, verbose: bool = False) -> None:
        """打印当前 Registry 快照。

        这个方法偏向“打题中途查看全局态势”：
        - 默认 `verbose=False`：只看核心值
        - `verbose=True`：显示 kind/source/confidence 细节
        """
        self.reg.puts_log(verbose=verbose)

    def show_snapshot(self, verbose: bool = False) -> None:
        """显式输出全量 Registry 快照。"""
        self.reg.show_snapshot(verbose=verbose)

    def show_last_infer(self, verbose: bool = False) -> None:
        """显示最近一次 infer 结果的分层视图。"""
        self.reg.show_last_infer(verbose=verbose)

    def show(self, verbose: bool = False) -> None:
        """`puts_log()` 的短别名。

        保留短名是为了贴近旧代码和手打习惯，减少切换成本。
        """
        self.puts_log(verbose=verbose)

    def classify_address(self, value: int) -> AddressClass:
        """调用 Registry 的地址分类逻辑。

        这通常用于“先看一眼这个地址像不像 libc / PIE / stack”，
        属于分析阶段的启发式辅助，而不是严格判定。
        """
        return self.reg.classify_address(value)

    def infer_base(
        self,
        leak_name: str,
        symbol_offset: int,
        base_name: str | None = None,
        min_accept_score: float | None = None,
        store: bool = True,
        verbose: bool = False,
    ) -> BaseCandidate:
        """推导并按阈值决定是否写入 base。

        调用链最终会落到 `PwnRegistry.infer_base()`：
        输入一个泄漏名和已知符号偏移，得到带评分的 base 候选。

        这里保留这个入口，是为了让“从泄漏推 libc/PIE base”继续像传统脚本那样顺手。
        """
        candidate = self.reg.infer_base(
            leak_name=leak_name,
            symbol_offset=symbol_offset,
            base_name=base_name,
            min_accept_score=min_accept_score,
            store=store,
        )
        self.reg.show_last_infer(verbose=verbose)
        return candidate

    def derive_base(
        self,
        leak_name: str,
        symbol_offset: int,
        base_name: str | None = None,
        min_accept_score: float | None = None,
        verbose: bool = False,
    ) -> BaseCandidate:
        """`infer_base()` 的写题友好别名。

        语义上更贴近“我现在就想从这个泄漏推一个 base 出来”，
        因此 README 里也更推荐使用这个名字。
        """
        candidate = self.reg.infer_base(
            leak_name=leak_name,
            symbol_offset=symbol_offset,
            base_name=base_name,
            min_accept_score=min_accept_score,
            store=True,
        )
        self.reg.show_last_infer(verbose=verbose)
        return candidate

    @staticmethod
    def _normalize_symbol_name(name: str) -> str:
        """把 `puts@libc` 一类键名归一成符号名 `puts`。

        `LibcSearcher` 接受的是符号名，而 Registry 里常见键名会混入语义后缀，
        例如：

        - `puts@libc`
        - `puts.got`

        所以在自动匹配前需要先做一次轻量归一化。
        """
        if "@" in name:
            return name.split("@", 1)[0]
        if "." in name:
            return name.split(".", 1)[0]
        return name

    def auto_search_libc(self) -> dict[str, int]:
        """基于现有泄漏自动调用 LibcSearcher 推导关键地址。

        这是一个“站在门面层上看起来一键完成”的能力：

        1. 从 Registry 收集当前已有泄漏
        2. 归一化符号名，喂给 `LibcSearcher`
        3. 计算 `libc_base` / `system` / `str_bin_sh`
        4. 再把结果反写回 Registry

        因而它既消费 Registry，又更新 Registry，
        很适合用来观察这个项目“状态中心驱动”的设计思路。
        """
        try:
            from LibcSearcher import LibcSearcher  # type: ignore
        except ImportError:
            log.error("未安装 LibcSearcher，无法执行自动匹配。")
            return {}

        leak_items: list[tuple[str, int]] = []
        for record in self.reg.iter_records():
            if record.kind.value == "base":
                continue
            leak_items.append((self._normalize_symbol_name(record.name), record.value))

        if not leak_items:
            log.error("Registry 中没有可用地址泄漏，无法启动 LibcSearcher。")
            return {}

        first_name, first_addr = leak_items[0]
        log.info(f"LibcSearcher 初始条件：{first_name} = {hex(first_addr)}")

        try:
            libc = LibcSearcher(first_name, first_addr)
        except Exception as exc:
            log.error(f"LibcSearcher 初始化失败：{exc}")
            return {}

        for name, addr in leak_items[1:]:
            try:
                libc.add_condition(name, addr)
                log.info(f"追加约束：{name} = {hex(addr)}")
            except Exception:
                log.debug(f"跳过不受支持的约束符号：{name}")

        try:
            libc_base = first_addr - libc.dump(first_name)
            system_addr = libc_base + libc.dump("system")
            str_bin_sh = libc_base + libc.dump("str_bin_sh")
        except Exception as exc:
            log.error(f"LibcSearcher dump 失败：{exc}")
            return {}

        self.reg.add_log(libc_base=libc_base, system=system_addr, bin_sh=str_bin_sh)
        log.success("Libc 关键地址已解析并写入 Registry。")
        return {
            "libc_base": libc_base,
            "system_addr": system_addr,
            "str_bin_sh": str_bin_sh,
        }

    def new_blind_tool(
        self,
        io_factory: Callable[[], TubeLike],
        interact_func: InteractFunc,
        arch: int = 64,
        delay: float = 0.10,
        timeout: float = 2.0,
    ) -> BlindFmtTool:
        """创建并挂载一个共享 Registry 的 Blind 工具实例。

        这里有个很重要的架构点：Blind 插件不是孤立对象，
        它会复用当前 `Tool` 持有的同一个 `PwnRegistry`。

        这意味着 blind 探测出的 offset、stack 指针等结果，
        可以立刻回流到主工具视角下继续参与后续分析，而不是形成另一套状态。
        """
        self.blind = BlindFmtTool(
            io_factory=io_factory,
            interact_func=interact_func,
            registry=self.reg,
            arch=arch,
            delay=delay,
            timeout=timeout,
        )
        return self.blind


Tool = MyTool
CHun = MyTool


__all__ = ["CHun", "MyTool", "Tool"]
