"""CHun cache 服务。"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Callable, cast

from .fingerprint import CACHE_SCHEMA_VERSION, default_cache_dir, file_cache_key, file_sha256
from ..models.cache import (
    AddressMode,
    ElfCacheRecord,
    GadgetCacheQueryRecord,
    GadgetCacheRecord,
    LibcCacheRecord,
    LibcSource,
)
from .store import JsonCacheStore

ElfLoader = Callable[[str], object]

_NAME_LINE_RE = re.compile(r"^\s*-\s+name:\s*(.+?)\s*$")
_STRING_SYM_ALIASES = {
    "str_bin_sh": "/bin/sh",
    "binsh": "/bin/sh",
    "/bin/sh": "/bin/sh",
}


class CacheService:
    """跨进程静态分析缓存层。"""

    def __init__(
        self,
        root: str | Path | None = None,
        *,
        enabled: bool = True,
        schema_version: int = CACHE_SCHEMA_VERSION,
    ) -> None:
        self.schema_version = int(schema_version)
        env_disabled = os.getenv("CHUN_NO_CACHE") == "1"
        self.enabled = bool(enabled) and not env_disabled
        self.root = Path(root).expanduser() if root is not None else default_cache_dir()
        self.store = JsonCacheStore(self.root, enabled=self.enabled)
        if self.enabled and os.getenv("CHUN_CLEAR_CACHE") == "1":
            self.store.clear()
        self._catalog_symbol_names: tuple[str, ...] | None = None

    def clear(self, namespace: str | None = None) -> None:
        self.store.clear(namespace=namespace)

    def get_elf_record(self, path: str | Path) -> ElfCacheRecord | None:
        key = self._elf_key(path)
        data = self.store.get("elf", key)
        record = cast(ElfCacheRecord | None, data)
        if not self._valid_elf_record(record):
            return None
        return record

    def ensure_elf_record(self, path: str | Path, loader: ElfLoader) -> ElfCacheRecord:
        cached = self.get_elf_record(path)
        if cached is not None:
            return cached
        return self._materialize_elf_record(path, loader)

    def get_elf_lookup(
        self,
        path: str | Path,
        *,
        table: str,
        name: str,
    ) -> tuple[int, AddressMode] | None:
        record = self.get_elf_record(path)
        if record is None:
            return None
        mapping = record.get(table)
        if not isinstance(mapping, dict):
            return None
        value = mapping.get(name)
        if not isinstance(value, int):
            return None
        mode = cast(AddressMode, record.get("address_mode", "offset"))
        return value, mode

    def set_elf_lookup(
        self,
        path: str | Path,
        *,
        table: str,
        name: str,
        value: int,
        address_mode: AddressMode,
        loader: ElfLoader | None = None,
    ) -> None:
        record = self.get_elf_record(path)
        if record is None:
            if loader is None:
                return
            record = self._materialize_elf_record(path, loader)
        mapping = dict(cast(dict[str, int], record.get(table, {})))
        mapping[name] = int(value)
        record[table] = mapping
        record["address_mode"] = address_mode
        self._write_elf_record(path, record)

    def get_libc_record(self, path: str | Path) -> LibcCacheRecord | None:
        key = self._libc_key(path)
        data = self.store.get("libc", key)
        record = cast(LibcCacheRecord | None, data)
        if not self._valid_libc_record(record):
            return None
        return record

    def ensure_libc_record(
        self,
        path: str | Path,
        *,
        loader: ElfLoader,
        source: LibcSource,
        trusted: bool,
        usable_for_remote: bool,
    ) -> LibcCacheRecord:
        cached = self.get_libc_record(path)
        if cached is not None:
            cached["source"] = source
            cached["trusted"] = bool(trusted)
            cached["usable_for_remote"] = bool(usable_for_remote)
            self._write_libc_record(path, cached)
            return cached
        return self._materialize_libc_record(
            path,
            loader=loader,
            source=source,
            trusted=trusted,
            usable_for_remote=usable_for_remote,
        )

    def lookup_libc_offset(self, path: str | Path, symbol: str) -> int | None:
        record = self.get_libc_record(path)
        if record is None:
            return None
        normalized = self.normalize_libc_symbol(symbol)
        if normalized == "/bin/sh":
            strings = cast(dict[str, int], record.get("strings", {}))
            if "/bin/sh" in strings:
                return int(strings["/bin/sh"])
        core = cast(dict[str, int], record.get("core_symbols", {}))
        if normalized in core:
            return int(core[normalized])
        extra = cast(dict[str, int], record.get("extra_symbols", {}))
        if normalized in extra:
            return int(extra[normalized])
        return None

    def materialize_libc_offset(
        self,
        path: str | Path,
        symbol: str,
        *,
        loader: ElfLoader,
    ) -> int | None:
        record = self.get_libc_record(path)
        if record is None:
            return None
        existing = self.lookup_libc_offset(path, symbol)
        if existing is not None:
            return existing

        raw = self._load_elf(loader, path)
        normalized = self.normalize_libc_symbol(symbol)
        offset = self._resolve_symbol_from_elf(raw, normalized)
        if offset is None:
            return None

        if normalized == "/bin/sh":
            strings = dict(cast(dict[str, int], record.get("strings", {})))
            strings["/bin/sh"] = offset
            record["strings"] = strings
        else:
            extra = dict(cast(dict[str, int], record.get("extra_symbols", {})))
            extra[normalized] = offset
            record["extra_symbols"] = extra
        self._write_libc_record(path, record)
        return offset

    def get_gadget_query(
        self,
        path: str | Path,
        *,
        source: str,
        token: str,
        arch: str,
        bits: int,
        pwntools_version: str,
    ) -> GadgetCacheQueryRecord | None:
        record = self._get_gadget_record(
            path,
            source=source,
            arch=arch,
            bits=bits,
            pwntools_version=pwntools_version,
        )
        if record is None:
            return None
        queries = record.get("queries")
        if not isinstance(queries, dict):
            return None
        query = queries.get(token)
        if not isinstance(query, dict):
            return None
        found = query.get("found")
        value = query.get("value")
        mode = query.get("address_mode")
        if not isinstance(found, bool):
            return None
        if value is not None and not isinstance(value, int):
            return None
        if mode not in {"offset", "vaddr"}:
            return None
        return cast(GadgetCacheQueryRecord, query)

    def set_gadget_query(
        self,
        path: str | Path,
        *,
        source: str,
        token: str,
        arch: str,
        bits: int,
        pwntools_version: str,
        found: bool,
        value: int | None,
        address_mode: AddressMode,
    ) -> None:
        record = self._get_gadget_record(
            path,
            source=source,
            arch=arch,
            bits=bits,
            pwntools_version=pwntools_version,
        )
        if record is None:
            record = {
                "schema": self.schema_version,
                "path": str(path),
                "sha256": file_sha256(path),
                "source": source,
                "arch": arch,
                "bits": int(bits),
                "pwntools_version": pwntools_version,
                "queries": {},
            }
        queries = dict(cast(dict[str, GadgetCacheQueryRecord], record.get("queries", {})))
        queries[token] = {
            "found": bool(found),
            "value": int(value) if isinstance(value, int) else None,
            "address_mode": address_mode,
        }
        record["queries"] = queries
        self._write_gadget_record(
            path,
            record,
            source=source,
            arch=arch,
            bits=bits,
            pwntools_version=pwntools_version,
        )

    @staticmethod
    def normalize_libc_symbol(raw_name: str) -> str:
        text = str(raw_name).strip()
        lowered = text.lower()
        if lowered in _STRING_SYM_ALIASES:
            return _STRING_SYM_ALIASES[lowered]
        if lowered.endswith("@got"):
            text = text[:-4]
        if lowered.endswith("@plt"):
            text = text[:-4]
        normalized = text.strip()
        lowered_normalized = normalized.lower()
        if lowered_normalized in _STRING_SYM_ALIASES:
            return _STRING_SYM_ALIASES[lowered_normalized]
        return normalized

    def _materialize_elf_record(self, path: str | Path, loader: ElfLoader) -> ElfCacheRecord:
        raw = self._load_elf(loader, path)
        pie = self._coerce_optional_bool(getattr(raw, "pie", None))
        address_mode: AddressMode = "offset" if pie else "vaddr"
        record: ElfCacheRecord = {
            "schema": self.schema_version,
            "path": str(path),
            "sha256": file_sha256(path),
            "arch": str(getattr(raw, "arch", "")),
            "bits": int(getattr(raw, "bits", 0) or 0),
            "endian": self._binary_endian(raw) or "little",
            "entry": int(getattr(raw, "entry", 0) or 0),
            "pie": bool(pie),
            "nx": bool(self._coerce_optional_bool(getattr(raw, "nx", None))),
            "canary": bool(self._coerce_optional_bool(getattr(raw, "canary", None))),
            "relro": self._normalize_relro(getattr(raw, "relro", None)) or "none",
            "stripped": bool(self._coerce_optional_bool(getattr(raw, "stripped", None))),
            "static": bool(self._coerce_optional_bool(getattr(raw, "static", None))),
            "image_base": int(getattr(raw, "address", 0) or 0),
            "address_mode": address_mode,
            "symbols": {},
            "got": {},
            "plt": {},
            "sections": {},
        }
        self._write_elf_record(path, record)
        return record

    def _materialize_libc_record(
        self,
        path: str | Path,
        *,
        loader: ElfLoader,
        source: LibcSource,
        trusted: bool,
        usable_for_remote: bool,
    ) -> LibcCacheRecord:
        raw = self._load_elf(loader, path)
        core: dict[str, int] = {}
        strings: dict[str, int] = {}
        for symbol_name in self._catalog_symbols():
            normalized = self.normalize_libc_symbol(symbol_name)
            offset = self._resolve_symbol_from_elf(raw, normalized)
            if offset is None:
                continue
            if normalized == "/bin/sh":
                strings["/bin/sh"] = offset
                continue
            core[normalized] = offset

        record: LibcCacheRecord = {
            "schema": self.schema_version,
            "path": str(path),
            "sha256": file_sha256(path),
            "source": source,
            "trusted": bool(trusted),
            "usable_for_remote": bool(usable_for_remote),
            "arch": str(getattr(raw, "arch", "")),
            "bits": int(getattr(raw, "bits", 0) or 0),
            "build_id": self._read_build_id(raw),
            "core_symbols": core,
            "extra_symbols": {},
            "strings": strings,
        }
        self._write_libc_record(path, record)
        return record

    def _resolve_symbol_from_elf(self, elf_obj: object, normalized_name: str) -> int | None:
        if normalized_name == "/bin/sh":
            search = getattr(elf_obj, "search", None)
            if callable(search):
                try:
                    raw_value = next(search(b"/bin/sh"))
                    return self._as_offset(elf_obj, int(raw_value))
                except Exception:
                    return None
            return None

        for attr in ("sym", "symbols"):
            table = getattr(elf_obj, attr, None)
            if not isinstance(table, dict):
                continue
            if normalized_name not in table:
                continue
            try:
                value = int(table[normalized_name])
            except Exception:
                continue
            return self._as_offset(elf_obj, value)
        return None

    @staticmethod
    def _as_offset(elf_obj: object, value: int) -> int:
        base = getattr(elf_obj, "address", None)
        if isinstance(base, int) and base > 0 and value >= base:
            return int(value - base)
        return int(value)

    @staticmethod
    def _read_build_id(binary: object) -> str:
        build_id = getattr(binary, "buildid", None)
        if isinstance(build_id, bytes):
            return build_id.hex()
        if isinstance(build_id, str):
            return build_id
        return ""

    def _catalog_symbols(self) -> tuple[str, ...]:
        if self._catalog_symbol_names is not None:
            return self._catalog_symbol_names

        symbols: list[str] = []
        symbol_file = Path(__file__).resolve().parents[1] / "catalog" / "catalog_symbols.yaml"
        try:
            lines = symbol_file.read_text(encoding="utf-8").splitlines()
        except Exception:
            self._catalog_symbol_names = tuple()
            return self._catalog_symbol_names
        for line in lines:
            match = _NAME_LINE_RE.match(line)
            if match is None:
                continue
            raw = match.group(1).strip()
            if raw.startswith('"') and raw.endswith('"'):
                raw = raw[1:-1]
            elif raw.startswith("'") and raw.endswith("'"):
                raw = raw[1:-1]
            symbols.append(raw)
        self._catalog_symbol_names = tuple(symbols)
        return self._catalog_symbol_names

    def _elf_key(self, path: str | Path) -> str:
        return file_cache_key(path, namespace="elf", schema=self.schema_version)

    def _libc_key(self, path: str | Path) -> str:
        return file_cache_key(path, namespace="libc", schema=self.schema_version)

    def _gadget_key(
        self,
        path: str | Path,
        *,
        source: str,
        arch: str,
        bits: int,
        pwntools_version: str,
    ) -> str:
        extra = f"{source}-{arch}-{int(bits)}-{pwntools_version}"
        return file_cache_key(path, namespace="gadget", schema=self.schema_version, extra=extra)

    def _write_elf_record(self, path: str | Path, record: ElfCacheRecord) -> None:
        key = self._elf_key(path)
        self.store.set("elf", key, record)

    def _write_libc_record(self, path: str | Path, record: LibcCacheRecord) -> None:
        key = self._libc_key(path)
        self.store.set("libc", key, record)

    def _get_gadget_record(
        self,
        path: str | Path,
        *,
        source: str,
        arch: str,
        bits: int,
        pwntools_version: str,
    ) -> GadgetCacheRecord | None:
        key = self._gadget_key(
            path,
            source=source,
            arch=arch,
            bits=bits,
            pwntools_version=pwntools_version,
        )
        data = self.store.get("gadget", key)
        record = cast(GadgetCacheRecord | None, data)
        if not self._valid_gadget_record(record):
            return None
        return record

    def _write_gadget_record(
        self,
        path: str | Path,
        record: GadgetCacheRecord,
        *,
        source: str,
        arch: str,
        bits: int,
        pwntools_version: str,
    ) -> None:
        key = self._gadget_key(
            path,
            source=source,
            arch=arch,
            bits=bits,
            pwntools_version=pwntools_version,
        )
        self.store.set("gadget", key, record)

    def _valid_elf_record(self, record: ElfCacheRecord | None) -> bool:
        if not isinstance(record, dict):
            return False
        if record.get("schema") != self.schema_version:
            return False
        if not isinstance(record.get("path"), str):
            return False
        if not isinstance(record.get("sha256"), str):
            return False
        if not isinstance(record.get("address_mode"), str):
            return False
        return True

    def _valid_libc_record(self, record: LibcCacheRecord | None) -> bool:
        if not isinstance(record, dict):
            return False
        if record.get("schema") != self.schema_version:
            return False
        if not isinstance(record.get("path"), str):
            return False
        if not isinstance(record.get("sha256"), str):
            return False
        if not isinstance(record.get("source"), str):
            return False
        return True

    def _valid_gadget_record(self, record: GadgetCacheRecord | None) -> bool:
        if not isinstance(record, dict):
            return False
        if record.get("schema") != self.schema_version:
            return False
        if not isinstance(record.get("queries"), dict):
            return False
        return True

    @staticmethod
    def _load_elf(loader: ElfLoader, path: str | Path) -> object:
        raw_path = str(path)
        try:
            return loader(raw_path, checksec=False)  # type: ignore[misc]
        except TypeError:
            return loader(raw_path)

    @staticmethod
    def _coerce_optional_bool(value: object) -> bool | None:
        if isinstance(value, bool):
            return value
        if isinstance(value, int) and value in {0, 1}:
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"1", "true", "yes", "on", "enabled"}:
                return True
            if normalized in {"0", "false", "no", "off", "disabled"}:
                return False
        return None

    @staticmethod
    def _binary_endian(binary: object) -> str | None:
        if hasattr(binary, "little_endian"):
            return "little" if bool(getattr(binary, "little_endian", True)) else "big"
        endianness = getattr(binary, "endianness", None)
        if isinstance(endianness, str) and endianness:
            normalized = endianness.lower()
            if normalized in {"little", "big"}:
                return normalized
        endian = getattr(binary, "endian", None)
        if isinstance(endian, str) and endian:
            normalized = endian.lower()
            if normalized in {"little", "big"}:
                return normalized
        return None

    @staticmethod
    def _normalize_relro(value: object) -> str | None:
        if isinstance(value, str):
            normalized = value.strip().lower().replace("_", " ").replace("-", " ")
            if "full" in normalized:
                return "full"
            if "partial" in normalized:
                return "partial"
            if "none" in normalized or "no relro" in normalized:
                return "none"
            return None

        candidate_name = getattr(value, "name", None)
        if isinstance(candidate_name, str):
            return CacheService._normalize_relro(candidate_name)
        candidate_value = getattr(value, "value", None)
        if isinstance(candidate_value, str):
            return CacheService._normalize_relro(candidate_value)
        return None


__all__ = ["CacheService"]
