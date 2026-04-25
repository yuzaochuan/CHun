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

        cache_lookup_start = time.perf_counter()
        cached = self._lookup_cached_gadget(parsed=parsed, image=image)
        self._emit_timing("script.gadget.cache_lookup", cache_lookup_start)
        if cached is not None:
            found, cached_value, address_mode = cached
            if not found:
                joined = "; ".join(parsed.instructions)
                raise LookupError(f"未找到 gadget: {joined}")
            if cached_value is None:
                joined = "; ".join(parsed.instructions)
                raise LookupError(f"未找到 gadget: {joined}")
            if address_mode == "offset":
                resolved = self._resolve_runtime_address(
                    source=parsed.source,
                    image=image,
                    gadget_address=int(cached_value),
                )
            else:
                resolved = self._normalize_vaddr_if_needed(image=image, value=int(cached_value))
            self._emit_timing("script.gadget.total", stage_start, extra=f"token={token}")
            return resolved

        find_start = time.perf_counter()
        gadget = self._find_gadget(parsed=parsed, image=image, instructions=parsed.instructions)
        self._emit_timing(
            "script.gadget.find",
            find_start,
            extra=f"ins={'; '.join(parsed.instructions)}",
        )

        mode = self._address_mode(source=parsed.source, image=image)
        stored_value = self._canonicalize_cached_value(
            image=image,
            gadget_address=int(gadget.address),
            address_mode=mode,
        )
        self._write_cached_gadget(
            parsed=parsed,
            image=image,
            found=True,
            value=stored_value,
            address_mode=mode,
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

    def _find_gadget(
        self,
        *,
        parsed: _ParsedGadgetToken,
        image: object,
        instructions: Sequence[str],
    ) -> Any:
        rop_builder = _script_module().ROP
        rop_image = self._materialize_rop_image(image)
        rop_init_start = time.perf_counter()
        rop = rop_builder(rop_image)
        self._emit_timing("script.gadget.rop_init", rop_init_start)

        find_start = time.perf_counter()
        gadget = rop.find_gadget(list(instructions))
        self._emit_timing("script.gadget.rop_find_gadget", find_start)
        if gadget is None:
            joined = "; ".join(instructions)
            self._write_cached_gadget(
                parsed=parsed,
                image=image,
                found=False,
                value=None,
                address_mode=self._address_mode(source=parsed.source, image=image),
            )
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
        image_base = self._image_base(image)
        if image_base > 0 and 0 <= gadget_address < image_base:
            if base is None:
                return image_base + gadget_address
            return base + gadget_address
        if base is None:
            return gadget_address

        if image_base > 0 and gadget_address >= image_base:
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
            if isinstance(value, int) and value > 0:
                return int(value)
            return None

        fact = getter("elf.base")
        value = getattr(fact, "value", None) if fact is not None else None
        if isinstance(value, int) and value > 0:
            return int(value)
        return None

    def _emit_timing(self, stage: str, start: float, *, extra: str | None = None) -> None:
        emit = getattr(self._entry, "_emit_timing", None)
        if callable(emit):
            emit(stage, start, extra=extra)
            return
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        suffix = f" | {extra}" if extra else ""
        print(f"[script-timing] {stage}: {elapsed_ms:.3f} ms{suffix}", flush=True)

    @staticmethod
    def _materialize_rop_image(image: object) -> object:
        materialize = getattr(image, "materialize_raw", None)
        if callable(materialize):
            return materialize()
        return image

    @staticmethod
    def _pwntools_version() -> str:
        try:
            import pwnlib  # type: ignore

            return str(getattr(pwnlib, "__version__", "unknown"))
        except Exception:
            return "unknown"

    @staticmethod
    def _cache_query_token(parsed: _ParsedGadgetToken) -> str:
        return f"{parsed.source}:{'; '.join(parsed.instructions)}"

    def _lookup_cached_gadget(
        self,
        *,
        parsed: _ParsedGadgetToken,
        image: object,
    ) -> tuple[bool, int | None, Literal["offset", "vaddr"]] | None:
        cache = getattr(self._entry, "_cache", None)
        if cache is None:
            return None
        path = getattr(image, "path", None)
        arch = getattr(image, "arch", None)
        bits = getattr(image, "bits", None)
        if not isinstance(path, str) or not path:
            return None
        if not isinstance(arch, str) or not isinstance(bits, int):
            return None
        query = cache.get_gadget_query(
            path,
            source=parsed.source,
            token=self._cache_query_token(parsed),
            arch=arch,
            bits=bits,
            pwntools_version=self._pwntools_version(),
        )
        if query is None:
            return None
        found = bool(query.get("found", False))
        value = query.get("value")
        address_mode = str(query.get("address_mode", "offset"))
        mode: Literal["offset", "vaddr"] = "vaddr" if address_mode == "vaddr" else "offset"
        return found, int(value) if isinstance(value, int) else None, mode

    def _write_cached_gadget(
        self,
        *,
        parsed: _ParsedGadgetToken,
        image: object,
        found: bool,
        value: int | None,
        address_mode: Literal["offset", "vaddr"],
    ) -> None:
        cache = getattr(self._entry, "_cache", None)
        if cache is None:
            return
        path = getattr(image, "path", None)
        arch = getattr(image, "arch", None)
        bits = getattr(image, "bits", None)
        if not isinstance(path, str) or not path:
            return
        if not isinstance(arch, str) or not isinstance(bits, int):
            return
        cache.set_gadget_query(
            path,
            source=parsed.source,
            token=self._cache_query_token(parsed),
            arch=arch,
            bits=bits,
            pwntools_version=self._pwntools_version(),
            found=found,
            value=value,
            address_mode=address_mode,
        )

    @staticmethod
    def _address_mode(
        *,
        source: Literal["elf", "libc"],
        image: object,
    ) -> Literal["offset", "vaddr"]:
        if source == "libc":
            return "offset"
        pie = getattr(image, "pie", None)
        return "offset" if bool(pie) else "vaddr"

    @staticmethod
    def _canonicalize_cached_value(
        *,
        image: object,
        gadget_address: int,
        address_mode: Literal["offset", "vaddr"],
    ) -> int:
        image_base = getattr(image, "address", 0)
        if not isinstance(image_base, int):
            image_base = 0
        if address_mode == "offset":
            if image_base > 0 and gadget_address >= image_base:
                return int(gadget_address - image_base)
            return int(gadget_address)
        if image_base > 0 and 0 <= gadget_address < image_base:
            return int(image_base + gadget_address)
        return int(gadget_address)

    @staticmethod
    def _image_base(image: object) -> int:
        image_base = getattr(image, "address", 0)
        if isinstance(image_base, int) and image_base > 0:
            return int(image_base)
        ensure_info = getattr(image, "ensure_minimal_info", None)
        if callable(ensure_info):
            try:
                info = ensure_info()
            except Exception:
                return 0
            cached = info.get("image_base") if isinstance(info, dict) else None
            if isinstance(cached, int) and cached > 0:
                return int(cached)
        return 0

    def _normalize_vaddr_if_needed(self, *, image: object, value: int) -> int:
        image_base = self._image_base(image)
        if image_base > 0 and 0 <= value < image_base:
            return int(image_base + value)
        return int(value)
