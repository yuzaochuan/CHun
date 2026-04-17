"""Libc catalog 离线构建工具。"""

from __future__ import annotations

import ast
import csv
import hashlib
import json
import sqlite3
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib import resources
from pathlib import Path
from typing import Iterable

SCRIPT_VERSION = "1"
ROOT_DIR = Path(__file__).resolve().parents[4]
DEFAULT_RAW_DIR = ROOT_DIR / "data" / "libc" / "raw"
DEFAULT_DB_PATH = ROOT_DIR / "data" / "libc" / "libc.db"
SYMBOL_PRIORITY_SCORES = {
    1: 10.0,
    2: 3.0,
    3: 1.0,
}
DEFAULT_SYMBOL_SCORE = 0.1


@dataclass(slots=True)
class RawSymbolRecord:
    """构建阶段使用的标准化符号记录。"""

    symbol_name: str
    offset: int
    score: float


@dataclass(slots=True)
class CatalogSymbolPolicy:
    """catalog 核心符号词典。"""

    alias_to_canonical: dict[str, str]
    priorities: dict[str, int]


@dataclass(slots=True)
class RawLibcRecord:
    """构建阶段使用的标准化 libc 记录。"""

    name: str
    arch: str
    symbols: tuple[RawSymbolRecord, ...]
    build_id: str | None = None
    sha256: str | None = None
    source: str | None = None
    source_ref: str | None = None


@dataclass(slots=True)
class CatalogBuildSummary:
    """一次 catalog 构建的汇总信息。"""

    output_path: Path
    raw_dir: Path
    source_hash: str
    libc_count: int
    symbol_count: int
    dataset_meta: dict[str, str] = field(default_factory=dict)


def default_raw_dir() -> Path:
    """返回默认原始数据目录。"""
    return DEFAULT_RAW_DIR


def default_db_path() -> Path:
    """返回默认 SQLite 产物路径。"""
    return DEFAULT_DB_PATH


def load_schema() -> str:
    """读取 catalog schema SQL。"""
    return (
        resources.files("chun.core.catalog")
        .joinpath("schema.sql")
        .read_text(encoding="utf-8")
    )


def load_symbol_policy() -> CatalogSymbolPolicy:
    """读取核心符号词典。"""
    text = (
        resources.files("chun.core.catalog")
        .joinpath("catalog_symbols.yaml")
        .read_text(encoding="utf-8")
    )
    items = _parse_catalog_symbols_yaml(text)
    alias_to_canonical: dict[str, str] = {}
    priorities: dict[str, int] = {}
    for item in items:
        canonical_name = str(item["name"])
        priority = int(item["priority"])
        priorities[canonical_name] = priority
        alias_to_canonical[canonical_name] = canonical_name
        for alias in item.get("aliases", []):
            alias_to_canonical[str(alias)] = canonical_name
    return CatalogSymbolPolicy(
        alias_to_canonical=alias_to_canonical,
        priorities=priorities,
    )


def build_libc_database(
    raw_dir: str | Path | None = None,
    output_path: str | Path | None = None,
    *,
    include_all: bool = False,
) -> CatalogBuildSummary:
    """从原始数据目录构建 sqlite libc catalog。"""
    resolved_raw_dir = Path(raw_dir) if raw_dir is not None else default_raw_dir()
    resolved_output_path = (
        Path(output_path) if output_path is not None else default_db_path()
    )

    resolved_raw_dir.mkdir(parents=True, exist_ok=True)
    resolved_output_path.parent.mkdir(parents=True, exist_ok=True)

    symbol_policy = load_symbol_policy()
    records = load_raw_records(
        resolved_raw_dir,
        symbol_policy=symbol_policy,
        include_all=include_all,
    )
    source_files = list_catalog_source_files(resolved_raw_dir)
    source_hash = compute_source_hash(source_files)

    if resolved_output_path.exists():
        resolved_output_path.unlink()

    schema_sql = load_schema()
    libc_rows: list[tuple[object, ...]] = []
    symbol_rows: list[tuple[int, str, int, float]] = []

    for libc_id, record in enumerate(records, start=1):
        libc_rows.append(
            (
                libc_id,
                record.name,
                record.arch,
                record.build_id,
                record.sha256,
                record.source,
                record.source_ref,
            )
        )
        for symbol in record.symbols:
            symbol_rows.append(
                (libc_id, symbol.symbol_name, symbol.offset, symbol.score)
            )

    built_at = datetime.now(timezone.utc).isoformat()
    dataset_meta = {
        "built_at": built_at,
        "script_version": SCRIPT_VERSION,
        "source_dir": str(resolved_raw_dir),
        "source_hash": source_hash,
        "build_mode": "all" if include_all else "core-only",
        "libc_count": str(len(libc_rows)),
        "symbol_count": str(len(symbol_rows)),
    }

    connection = sqlite3.connect(resolved_output_path)
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(schema_sql)
        with connection:
            connection.executemany(
                """
                INSERT INTO libc_versions (
                    id,
                    name,
                    arch,
                    build_id,
                    sha256,
                    source,
                    source_ref
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                libc_rows,
            )
            connection.executemany(
                """
                INSERT INTO symbols (
                    libc_id,
                    symbol_name,
                    offset,
                    score
                )
                VALUES (?, ?, ?, ?)
                """,
                symbol_rows,
            )
            connection.executemany(
                "INSERT INTO dataset_meta (key, value) VALUES (?, ?)",
                dataset_meta.items(),
            )
        connection.execute("PRAGMA optimize")
    finally:
        connection.close()

    return CatalogBuildSummary(
        output_path=resolved_output_path,
        raw_dir=resolved_raw_dir,
        source_hash=source_hash,
        libc_count=len(libc_rows),
        symbol_count=len(symbol_rows),
        dataset_meta=dataset_meta,
    )


def load_raw_records(
    raw_dir: Path,
    *,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> list[RawLibcRecord]:
    """加载并标准化全部原始数据。"""
    db_dir = raw_dir / "db"
    if db_dir.is_dir() and any(db_dir.glob("*.symbols")):
        return _load_flat_db_records(
            db_dir,
            symbol_policy=symbol_policy,
            include_all=include_all,
        )

    records: list[RawLibcRecord] = []
    for path in list_source_files(raw_dir):
        suffix = path.suffix.lower()
        if suffix == ".json":
            records.extend(
                _load_json_records(
                    path,
                    symbol_policy=symbol_policy,
                    include_all=include_all,
                )
            )
            continue
        if suffix in {".jsonl", ".ndjson"}:
            records.extend(
                _load_jsonl_records(
                    path,
                    symbol_policy=symbol_policy,
                    include_all=include_all,
                )
            )
            continue
        if suffix == ".csv":
            records.extend(
                _load_tabular_records(
                    path,
                    delimiter=",",
                    symbol_policy=symbol_policy,
                    include_all=include_all,
                )
            )
            continue
        if suffix in {".tsv", ".txt"}:
            records.extend(
                _load_tabular_records(
                    path,
                    delimiter="\t",
                    symbol_policy=symbol_policy,
                    include_all=include_all,
                )
            )
            continue
        raise ValueError(f"不支持的 raw 数据格式: {path}")
    return records


def list_catalog_source_files(raw_dir: Path) -> list[Path]:
    """列出参与构建哈希和导入的数据文件。"""
    db_dir = raw_dir / "db"
    if db_dir.is_dir() and any(db_dir.glob("*.symbols")):
        files: list[Path] = []
        for pattern in ("*.info", "*.symbols", "*.url", "*.so"):
            files.extend(sorted(db_dir.glob(pattern)))
        return files
    return list_source_files(raw_dir)


def list_source_files(raw_dir: Path) -> list[Path]:
    """列出用于构建的数据文件。"""
    return [
        path
        for path in sorted(raw_dir.rglob("*"))
        if path.is_file()
        and not path.name.startswith(".")
        and ".git" not in path.parts
        and path.suffix.lower()
        in {".json", ".jsonl", ".ndjson", ".csv", ".tsv", ".txt"}
    ]


def compute_source_hash(paths: Iterable[Path]) -> str:
    """基于源目录内容计算稳定哈希。"""
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path).encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _load_flat_db_records(
    db_dir: Path,
    *,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> list[RawLibcRecord]:
    records: list[RawLibcRecord] = []
    for info_path in sorted(db_dir.glob("*.info")):
        libc_id = info_path.stem
        symbols_path = db_dir / f"{libc_id}.symbols"
        url_path = db_dir / f"{libc_id}.url"
        so_path = db_dir / f"{libc_id}.so"
        if not symbols_path.is_file():
            continue

        source = _optional_text(info_path.read_text(encoding="utf-8"))
        source_ref = (
            _optional_text(url_path.read_text(encoding="utf-8"))
            if url_path.is_file()
            else None
        )
        sha256 = _sha256_file(so_path) if so_path.is_file() else None
        records.append(
            RawLibcRecord(
                name=libc_id,
                arch=_infer_arch_from_libc(libc_id, so_path),
                build_id=None,
                sha256=sha256,
                source=source or "libc-database",
                source_ref=source_ref or symbols_path.name,
                symbols=_select_and_score_symbols(
                    _load_flat_db_symbols(symbols_path),
                    symbol_policy=symbol_policy,
                    include_all=include_all,
                ),
            )
        )
    return records


def _load_flat_db_symbols(symbols_path: Path) -> dict[str, int]:
    symbols: dict[str, int] = {}
    for line_number, line in enumerate(
        symbols_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) != 2:
            raise ValueError(f"{symbols_path}:{line_number} 不是合法的 symbol 记录。")
        symbol_name, offset = parts
        parsed_offset = int(offset, 16)
        existing_offset = symbols.get(symbol_name)
        if existing_offset is not None:
            # 社区 libc 数据集中同名导出可能出现多次；保留首个偏移以保证构建连续性。
            if existing_offset == parsed_offset:
                continue
            continue
        symbols[symbol_name] = parsed_offset
    return symbols


def _infer_arch_from_libc_id(libc_id: str) -> str:
    for arch in ("amd64v3", "amd64", "i386", "arm64"):
        if libc_id.endswith(f"_{arch}"):
            return arch
    return "unknown"


def _infer_arch_from_file_output(output: str) -> str | None:
    text = output.lower()
    if "elf 32-bit" in text and "intel 80386" in text:
        return "i386"
    if "elf 64-bit" in text and "x86-64" in text:
        return "amd64"
    if "aarch64" in text or "arm64" in text:
        return "arm64"
    return None


def _infer_arch_from_shared_object(so_path: Path) -> str | None:
    if not so_path.is_file():
        return None
    try:
        output = subprocess.check_output(
            ["file", str(so_path)],
            text=True,
            stderr=subprocess.DEVNULL,
        )
    except (FileNotFoundError, OSError, subprocess.CalledProcessError):
        return None
    return _infer_arch_from_file_output(output)


def _infer_arch_from_libc(libc_id: str, so_path: Path) -> str:
    so_arch = _infer_arch_from_shared_object(so_path)
    if so_arch is not None:
        return so_arch
    return _infer_arch_from_libc_id(libc_id)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json_records(
    path: Path,
    *,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> list[RawLibcRecord]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return _normalize_payload(
        payload,
        path,
        symbol_policy=symbol_policy,
        include_all=include_all,
    )


def _load_jsonl_records(
    path: Path,
    *,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> list[RawLibcRecord]:
    records: list[RawLibcRecord] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            payload = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_number} 不是合法 JSONL 记录。") from exc
        records.extend(
            _normalize_payload(
                payload,
                path,
                symbol_policy=symbol_policy,
                include_all=include_all,
            )
        )
    return records


def _load_tabular_records(
    path: Path,
    *,
    delimiter: str,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> list[RawLibcRecord]:
    grouped: dict[tuple[str, ...], dict[str, object]] = {}
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter=delimiter)
        for row_number, row in enumerate(reader, start=2):
            if not row:
                continue
            name = _require_text(row.get("name"), path, "name", row_number)
            arch = _normalize_arch(
                _require_text(row.get("arch"), path, "arch", row_number)
            )
            build_id = _optional_text(row.get("build_id") or row.get("buildid"))
            sha256 = _optional_text(row.get("sha256"))
            source = (
                _optional_text(row.get("source")) or path.suffix.lstrip(".") or "raw"
            )
            source_ref = _optional_text(row.get("source_ref")) or path.name
            symbol_name = _require_text(
                row.get("symbol_name") or row.get("symbol"),
                path,
                "symbol_name",
                row_number,
            )
            offset = _parse_offset(
                row.get("offset") or row.get("symbol_offset"),
                path=path,
                field_name="offset",
                row_number=row_number,
            )
            key = (
                name,
                arch,
                build_id or "",
                sha256 or "",
                source,
                source_ref,
            )
            payload = grouped.setdefault(
                key,
                {
                    "name": name,
                    "arch": arch,
                    "build_id": build_id,
                    "sha256": sha256,
                    "source": source,
                    "source_ref": source_ref,
                    "symbols": {},
                },
            )
            symbols = payload["symbols"]
            assert isinstance(symbols, dict)
            if symbol_name in symbols:
                raise ValueError(f"{path}:{row_number} 出现重复 symbol: {symbol_name}")
            symbols[symbol_name] = offset
    return [
        _normalize_record(
            payload,
            path,
            symbol_policy=symbol_policy,
            include_all=include_all,
        )
        for payload in grouped.values()
    ]


def _normalize_payload(
    payload: object,
    path: Path,
    *,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> list[RawLibcRecord]:
    if isinstance(payload, list):
        items = payload
    elif isinstance(payload, dict):
        for key in ("libcs", "items", "records"):
            nested = payload.get(key)
            if isinstance(nested, list):
                items = nested
                break
        else:
            items = [payload]
    else:
        raise ValueError(f"{path} 的内容必须是 JSON object 或 JSON array。")

    records: list[RawLibcRecord] = []
    for item in items:
        if not isinstance(item, dict):
            raise ValueError(f"{path} 中存在非法记录，必须是 JSON object。")
        records.append(
            _normalize_record(
                item,
                path,
                symbol_policy=symbol_policy,
                include_all=include_all,
            )
        )
    return records


def _normalize_record(
    payload: dict[str, object],
    path: Path,
    *,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> RawLibcRecord:
    name = _require_text(payload.get("name"), path, "name")
    arch = _normalize_arch(_require_text(payload.get("arch"), path, "arch"))
    build_id = _optional_text(payload.get("build_id") or payload.get("buildid"))
    sha256 = _optional_text(payload.get("sha256"))
    source = _optional_text(payload.get("source")) or path.suffix.lstrip(".") or "raw"
    source_ref = _optional_text(payload.get("source_ref")) or path.name
    raw_symbols = _normalize_symbols(
        payload.get("symbols") or payload.get("symbol_offsets"),
        path,
    )
    return RawLibcRecord(
        name=name,
        arch=arch,
        build_id=build_id,
        sha256=sha256,
        source=source,
        source_ref=source_ref,
        symbols=_select_and_score_symbols(
            raw_symbols,
            symbol_policy=symbol_policy,
            include_all=include_all,
        ),
    )


def _normalize_symbols(symbols_payload: object, path: Path) -> dict[str, int]:
    if isinstance(symbols_payload, dict):
        symbols: dict[str, int] = {}
        for symbol_name, offset in symbols_payload.items():
            normalized_name = _require_text(symbol_name, path, "symbol_name")
            if normalized_name in symbols:
                raise ValueError(f"{path} 中存在重复 symbol: {normalized_name}")
            symbols[normalized_name] = _parse_offset(
                offset, path=path, field_name=normalized_name
            )
        return symbols

    if isinstance(symbols_payload, list):
        symbols = {}
        for index, item in enumerate(symbols_payload, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"{path} 的 symbols[{index}] 必须是 object。")
            symbol_name = _require_text(
                item.get("symbol_name") or item.get("name") or item.get("symbol"),
                path,
                f"symbols[{index}].symbol_name",
            )
            if symbol_name in symbols:
                raise ValueError(f"{path} 中存在重复 symbol: {symbol_name}")
            symbols[symbol_name] = _parse_offset(
                item.get("offset") or item.get("value"),
                path=path,
                field_name=f"symbols[{index}].offset",
            )
        return symbols

    raise ValueError(f"{path} 缺少合法的 symbols 定义。")


def _normalize_arch(value: str) -> str:
    arch = value.strip().lower()
    aliases = {
        "x86_64": "amd64",
        "amd64": "amd64",
        "i386": "i386",
        "i486": "i386",
        "i586": "i386",
        "i686": "i386",
        "x86": "i386",
        "aarch64": "arm64",
        "arm64": "arm64",
    }
    return aliases.get(arch, arch)


def _require_text(
    value: object,
    path: Path,
    field_name: str,
    row_number: int | None = None,
) -> str:
    normalized = _optional_text(value)
    if normalized is None:
        location = f"{path}:{row_number}" if row_number is not None else str(path)
        raise ValueError(f"{location} 缺少必填字段 {field_name}。")
    return normalized


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_offset(
    value: object,
    *,
    path: Path,
    field_name: str,
    row_number: int | None = None,
) -> int:
    try:
        if isinstance(value, bool):
            raise TypeError
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            if not value.is_integer():
                raise ValueError
            return int(value)
        if value is None:
            raise ValueError
        return int(str(value).strip(), 0)
    except (TypeError, ValueError) as exc:
        location = f"{path}:{row_number}" if row_number is not None else str(path)
        raise ValueError(f"{location} 中的 {field_name} 不是合法整数偏移。") from exc


def _score_for_priority(priority: int) -> float:
    return SYMBOL_PRIORITY_SCORES.get(priority, DEFAULT_SYMBOL_SCORE)


def _select_and_score_symbols(
    raw_symbols: dict[str, int],
    *,
    symbol_policy: CatalogSymbolPolicy,
    include_all: bool,
) -> tuple[RawSymbolRecord, ...]:
    selected: dict[str, RawSymbolRecord] = {}
    for raw_name, offset in raw_symbols.items():
        if raw_name in symbol_policy.priorities:
            symbol_name = raw_name
            score = _score_for_priority(symbol_policy.priorities[raw_name])
        else:
            canonical_name = symbol_policy.alias_to_canonical.get(raw_name)
            if canonical_name is None:
                if not include_all:
                    continue
                symbol_name = raw_name
                score = DEFAULT_SYMBOL_SCORE
            else:
                # Prefer the exact canonical symbol when both canonical and alias
                # exist in the same libc and point to different offsets.
                if canonical_name in raw_symbols:
                    continue
                symbol_name = canonical_name
                score = _score_for_priority(symbol_policy.priorities[canonical_name])
        existing = selected.get(symbol_name)
        if existing is None:
            selected[symbol_name] = RawSymbolRecord(
                symbol_name=symbol_name,
                offset=offset,
                score=score,
            )
            continue
        if existing.offset != offset:
            raise ValueError(
                f"符号 {symbol_name} 在同一 libc 记录中出现多个不同 offset。"
            )
        if score > existing.score:
            selected[symbol_name] = RawSymbolRecord(
                symbol_name=symbol_name,
                offset=offset,
                score=score,
            )
    return tuple(sorted(selected.values(), key=lambda item: item.symbol_name))


def _parse_catalog_symbols_yaml(text: str) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    current: dict[str, object] | None = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- "):
            if current is not None:
                items.append(current)
            current = {}
            stripped = stripped[2:]
        if current is None:
            raise ValueError("catalog_symbols.yaml 格式非法。")
        key, _, raw_value = stripped.partition(":")
        current[key.strip()] = _parse_simple_yaml_value(raw_value.strip())
    if current is not None:
        items.append(current)
    return items


def _parse_simple_yaml_value(value: str) -> object:
    if value == "":
        return ""
    if value.startswith(("[", "{", '"', "'")):
        return ast.literal_eval(value)
    if value.isdigit():
        return int(value)
    return value


__all__ = [
    "CatalogBuildSummary",
    "SCRIPT_VERSION",
    "build_libc_database",
    "default_db_path",
    "default_raw_dir",
    "load_raw_records",
    "load_schema",
]
