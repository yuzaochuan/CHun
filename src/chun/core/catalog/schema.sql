CREATE TABLE libc_versions (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    arch TEXT NOT NULL,
    build_id TEXT,
    sha256 TEXT,
    source TEXT,
    source_ref TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE symbols (
    libc_id INTEGER NOT NULL,
    symbol_name TEXT NOT NULL,
    offset INTEGER NOT NULL,
    score REAL NOT NULL,
    offset_12bit INTEGER GENERATED ALWAYS AS (offset & 4095) STORED,
    PRIMARY KEY (libc_id, symbol_name),
    FOREIGN KEY (libc_id) REFERENCES libc_versions(id) ON DELETE CASCADE
) WITHOUT ROWID;

CREATE TABLE dataset_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE INDEX idx_symbols_name_tail_libc
ON symbols(symbol_name, offset_12bit, libc_id);

CREATE INDEX idx_libc_versions_arch_name
ON libc_versions(arch, name);

CREATE UNIQUE INDEX idx_libc_versions_build_id
ON libc_versions(build_id)
WHERE build_id IS NOT NULL;
