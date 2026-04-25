"""脚本态 gadget 语法糖。"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import dataclass
from typing import Any, Literal, Sequence

_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]*$")


def _script_module() -> Any:
    return sys.modules[__package__]


@dataclass(slots=True, frozen=True)
class _ParsedGadgetToken:
    source: Literal["elf", "libc"]
    token: str
    instructions: tuple[str, ...]


class _ScriptGadgetFacade:
    """脚本态 gadget 查询器。

    设计目标是“手写 exp 的最短路径”：
    - `s.gadget["rdi"]` -> `pop rdi; ret`
    - `s.gadget["rsi_r15"]` -> `pop rsi; pop r15; ret`
    - `s.gadget["ret"]` -> `ret`
    - `s.gadget["leave"]` -> `leave; ret`
    - `s.gadget["libc:rdi"]` -> 从 libc 镜像查找 `pop rdi; ret`
    """

    def __init__(self, entry: Any) -> None:
        self._entry = entry

    def __getitem__(self, token: str) -> int:
        """按 token 语义查找 gadget 地址。"""
        return self.get(token)

    def get(self, token: str, *, index: int = 0) -> int:
        """按 token 语义查找 gadget 地址，可通过 `index` 选择候选。"""
        stage_start = time.perf_counter()
        if index != 0:
            raise ValueError("当前版本仅支持 index=0。")
        parse_start = time.perf_counter()
        parsed = self._parse_token(token)
        self._emit_timing("script.gadget.parse_token", parse_start, extra=f"token={token}")

        select_start = time.perf_counter()
        image = self._select_image(parsed.source)
        self._emit_timing(
            "script.gadget.select_image",
            select_start,
            extra=f"source={parsed.source}",
        )

        find_start = time.perf_counter()
        gadget = self._find_gadget(image, parsed.instructions)
        self._emit_timing(
            "script.gadget.find",
            find_start,
            extra=f"ins={'; '.join(parsed.instructions)}",
        )

        resolve_start = time.perf_counter()
        resolved = self._resolve_runtime_address(
            source=parsed.source,
            image=image,
            gadget_address=int(gadget.address),
        )
        self._emit_timing("script.gadget.resolve_addr", resolve_start)
        self._emit_timing("script.gadget.total", stage_start, extra=f"token={token}")
        return resolved

    @staticmethod
    def _parse_token(raw: str) -> _ParsedGadgetToken:
        token = str(raw).strip().lower()
        if not token:
            raise ValueError("gadget token 不能为空。")

        source: Literal["elf", "libc"] = "elf"
        body = token
        if ":" in token:
            prefix, body = token.split(":", 1)
            if prefix not in {"elf", "libc"}:
                raise ValueError("gadget source 仅支持 elf: 或 libc: 前缀。")
            source = prefix  # type: ignore[assignment]
            body = body.strip()

        if not body:
            raise ValueError("gadget token 不能为空。")
        if not _TOKEN_RE.match(body):
            raise ValueError(f"非法 gadget token: {raw!r}")

        if body == "ret":
            instructions = ("ret",)
        elif body == "leave":
            instructions = ("leave", "ret")
        else:
            regs = tuple(part for part in body.split("_") if part)
            if not regs:
                raise ValueError(f"非法 gadget token: {raw!r}")
            instructions = tuple(f"pop {reg}" for reg in regs) + ("ret",)
        return _ParsedGadgetToken(source=source, token=body, instructions=instructions)

    def _select_image(self, source: Literal["elf", "libc"]) -> object:
        if source == "elf":
            image = self._entry.elf
            if image is None:
                raise RuntimeError("当前脚本未绑定 elf，无法解析 ELF gadget。")
            return image
        libc = self._entry.libc
        if libc is None:
            raise RuntimeError("当前脚本未绑定 libc，无法解析 libc gadget。")
        return libc

    def _find_gadget(self, image: object, instructions: Sequence[str]) -> Any:
        rop_builder = _script_module().ROP
        rop_init_start = time.perf_counter()
        rop = rop_builder(image)
        self._emit_timing("script.gadget.rop_init", rop_init_start)

        find_start = time.perf_counter()
        gadget = rop.find_gadget(list(instructions))
        self._emit_timing("script.gadget.rop_find_gadget", find_start)
        if gadget is None:
            joined = "; ".join(instructions)
            raise LookupError(f"未找到 gadget: {joined}")
        return gadget

    def _resolve_runtime_address(
        self,
        *,
        source: Literal["elf", "libc"],
        image: object,
        gadget_address: int,
    ) -> int:
        # pwntools 在不同对象上可能返回 offset 或已加基址地址。
        base = self._read_image_base(source)
        if base is None:
            return gadget_address

        image_base = getattr(image, "address", 0)
        if isinstance(image_base, int) and image_base > 0:
            if gadget_address >= image_base:
                return base + (gadget_address - image_base)
        if gadget_address < base:
            return base + gadget_address
        return gadget_address

    def _read_image_base(self, source: Literal["elf", "libc"]) -> int | None:
        getter = getattr(self._entry.rec, "get_fact", None)
        if not callable(getter):
            return None
        if source == "libc":
            fact = getter("libc.base")
            value = getattr(fact, "value", None) if fact is not None else None
            return int(value) if isinstance(value, int) else None

        fact = getter("elf.base")
        value = getattr(fact, "value", None) if fact is not None else None
        return int(value) if isinstance(value, int) else None

    def _emit_timing(self, stage: str, start: float, *, extra: str | None = None) -> None:
        emit = getattr(self._entry, "_emit_timing", None)
        if callable(emit):
            emit(stage, start, extra=extra)
            return
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        suffix = f" | {extra}" if extra else ""
        print(f"[script-timing] {stage}: {elapsed_ms:.3f} ms{suffix}", flush=True)
