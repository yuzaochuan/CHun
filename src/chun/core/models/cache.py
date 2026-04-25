"""cache record 类型声明。"""

from __future__ import annotations

from typing import Literal, TypedDict


AddressMode = Literal["offset", "vaddr"]
LibcSource = Literal[
    "specified",
    "local_detected",
    "libcdb",
    "catalog",
    "remote_inferred",
    "unresolved",
]


class ElfCacheRecord(TypedDict, total=False):
    schema: int
    path: str
    sha256: str
    arch: str
    bits: int
    endian: str
    entry: int
    pie: bool
    nx: bool
    canary: bool
    relro: str
    stripped: bool
    static: bool
    image_base: int
    address_mode: AddressMode
    symbols: dict[str, int]
    got: dict[str, int]
    plt: dict[str, int]
    sections: dict[str, int]


class LibcCacheRecord(TypedDict, total=False):
    schema: int
    path: str
    sha256: str
    source: LibcSource
    trusted: bool
    usable_for_remote: bool
    arch: str
    bits: int
    build_id: str
    core_symbols: dict[str, int]
    extra_symbols: dict[str, int]
    strings: dict[str, int]


class GadgetCacheQueryRecord(TypedDict, total=False):
    found: bool
    value: int | None
    address_mode: AddressMode


class GadgetCacheRecord(TypedDict, total=False):
    schema: int
    path: str
    sha256: str
    source: str
    arch: str
    bits: int
    pwntools_version: str
    queries: dict[str, GadgetCacheQueryRecord]


__all__ = [
    "AddressMode",
    "ElfCacheRecord",
    "GadgetCacheQueryRecord",
    "GadgetCacheRecord",
    "LibcCacheRecord",
    "LibcSource",
]
