"""脚本态 gadget 语法糖。"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from typing import Any, Literal, Sequence

_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_MAX_GADGET_SUGGESTIONS = 5


def _script_module() -> Any:
    return sys.modules[__package__]


@dataclass(slots=True, frozen=True)
class _ParsedGadgetToken:
    source: Literal["elf", "libc"]
    token: str
    instructions: tuple[str, ...]


@dataclass(slots=True, frozen=True)
class _CompatibleGadgetCandidate:
    address: int
    instructions: tuple[str, ...]
    extra_pops: int


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
        if index != 0:
            raise ValueError("当前版本仅支持 index=0。")
        parsed = self._parse_token(token)

        image = self._select_image(parsed.source)

        cached = self._lookup_cached_gadget(parsed=parsed, image=image)
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
            return resolved

        gadget = self._find_gadget(parsed=parsed, image=image, instructions=parsed.instructions)

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

        resolved = self._resolve_runtime_address(
            source=parsed.source,
            image=image,
            gadget_address=int(gadget.address),
        )
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
        rop = rop_builder(rop_image)

        gadget = rop.find_gadget(list(instructions))
        if gadget is None:
            joined = "; ".join(instructions)
            self._write_cached_gadget(
                parsed=parsed,
                image=image,
                found=False,
                value=None,
                address_mode=self._address_mode(source=parsed.source, image=image),
            )
            suggestions = self._find_compatible_gadgets(
                parsed=parsed,
                image=image,
                rop=rop,
                limit=_MAX_GADGET_SUGGESTIONS,
            )
            raise LookupError(self._format_not_found_message(joined, suggestions))
        return gadget

    def _find_compatible_gadgets(
        self,
        *,
        parsed: _ParsedGadgetToken,
        image: object,
        rop: object,
        limit: int,
    ) -> tuple[_CompatibleGadgetCandidate, ...]:
        required = parsed.instructions[:-1]
        if not required or parsed.instructions[-1] != "ret":
            return ()
        if not all(instruction.startswith("pop ") for instruction in required):
            return ()

        candidates: list[_CompatibleGadgetCandidate] = []
        for gadget in self._iter_rop_gadgets(rop):
            instructions = self._gadget_instructions(gadget)
            if not self._is_compatible_pop_ret_gadget(instructions, required=required):
                continue
            address = self._gadget_address(gadget)
            if address is None:
                continue
            if instructions == parsed.instructions:
                continue
            extra_pops = len(instructions) - len(required) - 1
            display_address = self._resolve_runtime_address(
                source=parsed.source,
                image=image,
                gadget_address=address,
            )
            candidates.append(
                _CompatibleGadgetCandidate(
                    address=display_address,
                    instructions=instructions,
                    extra_pops=extra_pops,
                )
            )

        candidates.sort(key=lambda item: (item.extra_pops, len(item.instructions), item.address))
        return tuple(candidates[:limit])

    @staticmethod
    def _iter_rop_gadgets(rop: object) -> tuple[object, ...]:
        gadgets = getattr(rop, "gadgets", None)
        if isinstance(gadgets, dict):
            return tuple(gadgets.values())
        if isinstance(gadgets, (list, tuple)):
            return tuple(gadgets)
        return ()

    @staticmethod
    def _gadget_instructions(gadget: object) -> tuple[str, ...]:
        raw = getattr(gadget, "insns", None)
        if raw is None:
            raw = getattr(gadget, "instructions", None)
        if not isinstance(raw, (list, tuple)):
            return ()
        instructions: list[str] = []
        for instruction in raw:
            if isinstance(instruction, bytes):
                text = instruction.decode("latin-1", errors="ignore")
            else:
                text = str(instruction)
            normalized = " ".join(text.strip().lower().split())
            if normalized:
                instructions.append(normalized)
        return tuple(instructions)

    @staticmethod
    def _gadget_address(gadget: object) -> int | None:
        address = getattr(gadget, "address", None)
        if isinstance(address, int):
            return int(address)
        return None

    @staticmethod
    def _is_compatible_pop_ret_gadget(
        instructions: tuple[str, ...],
        *,
        required: tuple[str, ...],
    ) -> bool:
        if len(instructions) <= len(required):
            return False
        if instructions[-1] != "ret":
            return False
        if instructions[: len(required)] != required:
            return False
        extra = instructions[len(required) : -1]
        return bool(extra) and all(instruction.startswith("pop ") for instruction in extra)

    @staticmethod
    def _format_not_found_message(
        joined: str,
        suggestions: Sequence[_CompatibleGadgetCandidate],
    ) -> str:
        if not suggestions:
            return f"未找到 gadget: {joined}"
        lines = [f"未找到 gadget: {joined}", "其他可利用的 gadget:"]
        for candidate in suggestions:
            rendered = "; ".join(candidate.instructions)
            lines.append(f"  [extra={candidate.extra_pops}] {candidate.address:#x}: {rendered}")
        return "\n".join(lines)

    def _resolve_runtime_address(
        self,
        *,
        source: Literal["elf", "libc"],
        image: object,
        gadget_address: int,
    ) -> int:
        base = self._read_image_base(source)
        if source == "elf" and bool(getattr(image, "pie", False)) and base is None:
            self._warn_missing_elf_base_once()
            return self._canonicalize_cached_value(
                image=image,
                gadget_address=gadget_address,
                address_mode="offset",
            )

        # pwntools 在不同对象上可能返回 offset 或已加基址地址。
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

    def _warn_missing_elf_base_once(self) -> None:
        flag = "_warned_missing_elf_base"
        if getattr(self, flag, False):
            return
        setattr(self, flag, True)
        _script_module().log.warning(
            "检测到 PIE，但尚未记录 elf.base；当前返回 gadget 的静态 offset。"
        )

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
