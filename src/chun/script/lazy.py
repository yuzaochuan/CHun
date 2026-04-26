"""脚本态 lazy 二进制代理。"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any, Callable

from ..core.cache import CacheService
from ..core.models.cache import AddressMode


class _LazyLookupMapping(Mapping[str, int]):
    """针对 `symbols/got/plt/sections` 的按需查询映射。"""

    def __init__(self, owner: "LazyELFProxy", table: str) -> None:
        self._owner = owner
        self._table = table

    def __getitem__(self, key: str) -> int:
        return self._owner.lookup(self._table, key)

    def __iter__(self) -> Iterator[str]:
        raw = self._owner.materialize_raw()
        mapping = self._owner._raw_table(raw, self._table)
        return iter(mapping.keys())

    def __len__(self) -> int:
        raw = self._owner.materialize_raw()
        mapping = self._owner._raw_table(raw, self._table)
        return len(mapping)

    def __contains__(self, key: object) -> bool:
        if not isinstance(key, str):
            return False
        cached = self._owner.cache.get_elf_lookup(self._owner.path, table=self._table, name=key)
        if cached is not None:
            return True
        raw = self._owner.materialize_raw()
        mapping = self._owner._raw_table(raw, self._table)
        return key in mapping

    def get(self, key: str, default: int | None = None) -> int | None:
        try:
            return self.__getitem__(key)
        except KeyError:
            return default


class LazyELFProxy:
    """cache-aware 的 ELF lazy 代理。"""

    def __init__(
        self,
        path: str,
        *,
        cache: CacheService,
        loader: Any,
        runtime_base_getter: Callable[[], int | None] | None = None,
        warning_emitter: Callable[[str], None] | None = None,
        runtime_name: str = "elf.base",
    ) -> None:
        self.path = str(path)
        self.cache = cache
        self._loader = loader
        self._runtime_base_getter = runtime_base_getter
        self._warning_emitter = warning_emitter
        self._runtime_name = str(runtime_name)
        self._raw: Any = None
        self._info: dict[str, Any] | None = None
        self._warned_missing_runtime_base: set[tuple[str, str]] = set()
        self._symbols = _LazyLookupMapping(self, "symbols")
        self._got = _LazyLookupMapping(self, "got")
        self._plt = _LazyLookupMapping(self, "plt")
        self._sections = _LazyLookupMapping(self, "sections")

    def ensure_minimal_info(self) -> dict[str, Any]:
        if self._info is not None:
            return self._info
        self._info = dict(self.cache.ensure_elf_record(self.path, self._loader))
        return self._info

    def materialize_raw(self) -> Any:
        if self._raw is not None:
            return self._raw
        self._raw = self.cache._load_elf(self._loader, self.path)
        # 写回最小 ELF info（包括 protection / address_mode）。
        self._info = dict(self.cache.ensure_elf_record(self.path, self._loader))
        return self._raw

    @property
    def symbols(self) -> Mapping[str, int]:
        return self._symbols

    @property
    def sym(self) -> Mapping[str, int]:
        """兼容 pwntools 常用简写：`elf.sym[...]`。"""
        return self._symbols

    @property
    def symbol(self) -> Mapping[str, int]:
        """兼容语义化别名：`elf.symbol[...]`。"""
        return self._symbols

    @property
    def got(self) -> Mapping[str, int]:
        return self._got

    @property
    def plt(self) -> Mapping[str, int]:
        return self._plt

    @property
    def sections(self) -> Mapping[str, int]:
        return self._sections

    @property
    def arch(self) -> str:
        return str(self.ensure_minimal_info().get("arch", ""))

    @property
    def bits(self) -> int:
        return int(self.ensure_minimal_info().get("bits", 0) or 0)

    @bits.setter
    def bits(self, value: int) -> None:
        info = self.ensure_minimal_info()
        info["bits"] = int(value)

    @property
    def bytes(self) -> int:
        info = self.ensure_minimal_info()
        explicit = info.get("bytes")
        if isinstance(explicit, int) and explicit > 0:
            return int(explicit)
        bits = self.bits
        return bits // 8 if bits > 0 else 0

    @bytes.setter
    def bytes(self, value: int) -> None:
        info = self.ensure_minimal_info()
        info["bytes"] = int(value)

    @property
    def little_endian(self) -> bool:
        return str(self.ensure_minimal_info().get("endian", "little")) == "little"

    @property
    def pie(self) -> bool:
        return bool(self.ensure_minimal_info().get("pie", False))

    @property
    def nx(self) -> bool:
        return bool(self.ensure_minimal_info().get("nx", False))

    @property
    def canary(self) -> bool:
        return bool(self.ensure_minimal_info().get("canary", False))

    @property
    def relro(self) -> str:
        return str(self.ensure_minimal_info().get("relro", "none"))

    @property
    def stripped(self) -> bool:
        return bool(self.ensure_minimal_info().get("stripped", False))

    @property
    def static(self) -> bool:
        return bool(self.ensure_minimal_info().get("static", False))

    @property
    def entry(self) -> int:
        return int(self.ensure_minimal_info().get("entry", 0) or 0)

    @property
    def address(self) -> int:
        if self._raw is not None:
            address = getattr(self._raw, "address", None)
            if isinstance(address, int) and address > 0:
                return int(address)
        info = self.ensure_minimal_info()
        cached = info.get("image_base")
        if isinstance(cached, int) and cached > 0:
            return int(cached)
        return 0

    @property
    def libc(self) -> Any:
        raw = self.materialize_raw()
        return getattr(raw, "libc", None)

    def lookup(self, table: str, name: str) -> int:
        cached = self.cache.get_elf_lookup(self.path, table=table, name=name)
        if cached is not None:
            value, mode = cached
            return self._resolve_lookup_value(int(value), mode=mode, table=table, name=name)

        raw = self.materialize_raw()
        mapping = self._raw_table(raw, table)
        if name not in mapping:
            raise KeyError(name)
        value = self._extract_raw_table_value(mapping[name], table=table)
        mode = self._address_mode()
        canonical = self._canonicalize_value(raw, value=value, mode=mode)
        self.cache.set_elf_lookup(
            self.path,
            table=table,
            name=name,
            value=canonical,
            address_mode=mode,
            loader=self._loader,
        )
        return self._resolve_lookup_value(int(canonical), mode=mode, table=table, name=name)

    def _address_mode(self) -> AddressMode:
        info = self.ensure_minimal_info()
        raw = info.get("address_mode", "offset")
        return "vaddr" if str(raw) == "vaddr" else "offset"

    @staticmethod
    def _raw_table(raw: object, table: str) -> Mapping[str, Any]:
        value = getattr(raw, table, None)
        if isinstance(value, Mapping):
            return value
        raise AttributeError(f"ELF 不支持表：{table}")

    @staticmethod
    def _extract_raw_table_value(raw_value: object, *, table: str) -> int:
        if isinstance(raw_value, int):
            return int(raw_value)
        address = getattr(raw_value, "address", None)
        if isinstance(address, int):
            return int(address)
        header = getattr(raw_value, "header", None)
        if header is not None:
            sh_addr = getattr(header, "sh_addr", None)
            if isinstance(sh_addr, int):
                return int(sh_addr)
        raise TypeError(f"无法从 {table} 项解析地址。")

    @staticmethod
    def _canonicalize_value(raw: object, *, value: int, mode: AddressMode) -> int:
        image_base = getattr(raw, "address", 0)
        if not isinstance(image_base, int):
            image_base = 0
        if mode == "offset":
            if image_base > 0 and value >= image_base:
                return int(value - image_base)
            return int(value)
        if image_base > 0 and 0 <= value < image_base:
            return int(value + image_base)
        return int(value)

    def _normalize_vaddr_if_needed(self, value: int, *, mode: AddressMode) -> int:
        if mode != "vaddr":
            return int(value)
        image_base = self.address
        if image_base > 0 and 0 <= value < image_base:
            return int(image_base + value)
        return int(value)

    def _resolve_lookup_value(
        self,
        value: int,
        *,
        mode: AddressMode,
        table: str,
        name: str,
    ) -> int:
        if mode == "vaddr":
            return self._normalize_vaddr_if_needed(int(value), mode=mode)
        runtime_base = self._runtime_base()
        if runtime_base is not None:
            return int(runtime_base + value)
        self._warn_missing_runtime_base_once(table=table, name=name)
        return int(value)

    def _runtime_base(self) -> int | None:
        getter = self._runtime_base_getter
        if getter is None:
            return None
        try:
            value = getter()
        except Exception:
            return None
        if isinstance(value, int) and value > 0:
            return int(value)
        return None

    def _warn_missing_runtime_base_once(self, *, table: str, name: str) -> None:
        if not self.pie:
            return
        key = (table, name)
        if key in self._warned_missing_runtime_base:
            return
        self._warned_missing_runtime_base.add(key)
        emitter = self._warning_emitter
        if emitter is None:
            return
        emitter(
            f"检测到 PIE，但尚未记录 {self._runtime_name}；"
            f"当前返回 {table}[{name!r}] 的静态 offset。"
        )

    def __getattr__(self, name: str) -> Any:
        # 对外保留 raw ELF 能力：未知属性触发真正 materialize。
        raw = self.materialize_raw()
        return getattr(raw, name)


__all__ = ["LazyELFProxy"]
