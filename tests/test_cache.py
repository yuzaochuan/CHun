from __future__ import annotations

from pathlib import Path

import pytest

from chun.core.cache import CacheService, default_cache_dir, file_cache_key, file_sha256
from chun.core.cache.store import JsonCacheStore


class _FakeElf:
    def __init__(self, path: str) -> None:
        self.path = path
        self.arch = "amd64"
        self.bits = 64
        self.endian = "little"
        self.entry = 0x401000
        self.pie = False
        self.nx = True
        self.canary = False
        self.relro = "Partial RELRO"
        self.stripped = False
        self.static = False
        self.address = 0x400000
        self.sym = {"main": 0x401080}
        self.got = {"puts": 0x404018}
        self.plt = {"puts": 0x401030}
        self.sections = {}

    def search(self, needle: bytes):
        if needle == b"/bin/sh":
            return iter((0x1B45BD,))
        return iter(())


def _fake_loader(path: str, checksec: bool = False) -> _FakeElf:
    _ = checksec
    return _FakeElf(path)


def _fake_pie_loader(path: str, checksec: bool = False) -> _FakeElf:
    _ = checksec
    elf = _FakeElf(path)
    elf.pie = True
    elf.address = 0x555555554000
    return elf


def test_default_cache_dir_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CHUN_CACHE_DIR", raising=False)
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    assert default_cache_dir() == Path("~/.cache/chun").expanduser()

    monkeypatch.setenv("XDG_CACHE_HOME", "/tmp/xdg-cache")
    assert default_cache_dir() == Path("/tmp/xdg-cache/chun")

    monkeypatch.setenv("CHUN_CACHE_DIR", "/tmp/chun-cache")
    assert default_cache_dir() == Path("/tmp/chun-cache")


def test_file_sha256_is_stable(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"abcdef")
    first = file_sha256(sample)
    second = file_sha256(sample)
    assert first == second


def test_json_cache_store_set_get_and_clear(tmp_path: Path) -> None:
    store = JsonCacheStore(tmp_path / "cache")
    store.set("elf", "abc", {"ok": 1})
    assert store.get("elf", "abc") == {"ok": 1}
    store.clear("elf")
    assert store.get("elf", "abc") is None


def test_cache_service_schema_mismatch_is_miss(tmp_path: Path) -> None:
    binary_path = tmp_path / "chall"
    binary_path.write_bytes(b"fake-binary")
    cache = CacheService(root=tmp_path / "cache")
    key = file_cache_key(binary_path, namespace="elf", schema=cache.schema_version)
    cache.store.set(
        "elf",
        key,
        {
            "schema": cache.schema_version + 1,
            "path": str(binary_path),
            "sha256": "deadbeef",
            "address_mode": "offset",
        },
    )
    assert cache.get_elf_record(binary_path) is None


def test_corrupted_json_is_miss(tmp_path: Path) -> None:
    binary_path = tmp_path / "chall"
    binary_path.write_bytes(b"fake-binary")
    cache = CacheService(root=tmp_path / "cache")
    key = file_cache_key(binary_path, namespace="elf", schema=cache.schema_version)
    target = cache.root / "elf" / f"{key}.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("{broken-json", encoding="utf-8")
    assert cache.get_elf_record(binary_path) is None


def test_chun_no_cache_disables_disk_rw(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("CHUN_NO_CACHE", "1")
    cache = CacheService(root=tmp_path / "cache", enabled=True)
    binary_path = tmp_path / "chall"
    binary_path.write_bytes(b"fake-binary")
    _ = cache.ensure_elf_record(binary_path, _fake_loader)
    assert not (cache.root / "elf").exists()


def test_chun_clear_cache_clears_existing_files(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    root = tmp_path / "cache"
    stale = root / "elf" / "old.json"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_text('{"stale": true}', encoding="utf-8")
    monkeypatch.setenv("CHUN_CLEAR_CACHE", "1")
    _ = CacheService(root=root, enabled=True)
    assert not stale.exists()


def test_elf_cache_address_mode_uses_offset_for_pie(tmp_path: Path) -> None:
    binary_path = tmp_path / "pie"
    binary_path.write_bytes(b"fake-pie")
    cache = CacheService(root=tmp_path / "cache")
    record = cache.ensure_elf_record(binary_path, _fake_pie_loader)
    assert record["address_mode"] == "offset"


def test_elf_cache_address_mode_uses_vaddr_for_non_pie(tmp_path: Path) -> None:
    binary_path = tmp_path / "nopie"
    binary_path.write_bytes(b"fake-nopie")
    cache = CacheService(root=tmp_path / "cache")
    record = cache.ensure_elf_record(binary_path, _fake_loader)
    assert record["address_mode"] == "vaddr"


def test_bind_elf_libc_writes_link_metadata(tmp_path: Path) -> None:
    binary_path = tmp_path / "chall"
    libc_path = tmp_path / "libc.so.6"
    binary_path.write_bytes(b"fake-binary")
    libc_path.write_bytes(b"fake-libc")
    cache = CacheService(root=tmp_path / "cache")

    _ = cache.ensure_elf_record(binary_path, _fake_loader)
    _ = cache.ensure_libc_record(
        libc_path,
        loader=_fake_loader,
        source="specified",
        trusted=True,
        usable_for_remote=True,
    )
    cache.bind_elf_libc(
        binary_path,
        libc_path=libc_path,
        source="specified",
    )

    elf_record = cache.get_elf_record(binary_path)
    libc_record = cache.get_libc_record(libc_path)
    assert elf_record is not None
    assert libc_record is not None
    assert elf_record.get("linked_libc_path") == str(libc_path)
    assert elf_record.get("linked_libc_sha256") == file_sha256(libc_path)
    assert elf_record.get("linked_libc_source") == "specified"
    assert file_sha256(binary_path) in libc_record.get("linked_binaries", [])
