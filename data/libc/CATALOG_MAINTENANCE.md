# CHun Libc Catalog Maintenance Notes

This file is a handoff note for future full-refresh work on CHun's local libc
catalog. It records the current data sources, schema shape, build flow,
important implementation choices, and the public interfaces that already depend
on this data.

Use this file as the first stop before touching:

- `data/libc/raw/db/`
- `data/libc/libc.db`
- `src/chun/core/catalog/`
- `scripts/build_libc_db.py`
- `scripts/import_libc_database.py`
- `scripts/collect_ubuntu_libcs.py`

## Snapshot

Current built SQLite snapshot:

- output: `data/libc/libc.db`
- build mode: `core-only`
- libc count: `668`
- symbol count: `50123`
- source hash: `807a87fad0ef6e823ad4154ac731eea06efe9ec2aa367c1d77e46669a7d4948d`
- file size at freeze time: about `2.6M`

Practical version counts at freeze time:

- all entries in `libc.db`: `668`
- main libc entries excluding `_2` debug variants: `563`
- `amd64`: `262`
- `i386`: `262`
- `arm64`: `31`
- `amd64v3`: `8`

This snapshot is Ubuntu-heavy by design. That was an intentional tradeoff for
CTF/PWN usefulness.

## Main Data Sources

The current `raw/db` is not from one source. It is a merged dataset.

### 1. Original local raw clone

`data/libc/raw/` started from a `libc-database` style repository layout:

- `db/<id>.info`
- `db/<id>.symbols`
- `db/<id>.so`
- `db/<id>.url`

This remains the canonical local raw source that CHun builds from.

### 2. Ubuntu-oriented official collection

Used source pools:

- Ubuntu archive
- Ubuntu security
- Ubuntu old-releases
- related Ubuntu package pools reachable by the collector scripts

Supporting script:

- `scripts/collect_ubuntu_libcs.py`

Purpose:

- expand common Ubuntu patch-level coverage for PWN-heavy glibc versions
- especially `2.23`, `2.27`, `2.31`, `2.35`, `2.39`

Result:

- useful for official pool coverage
- not enough alone to reach deep patch coverage or `1000+` versions

### 3. Community `libc-database` clone

Local path:

- `data/libc/community/libc-database/`

This became the main secondary source for patch-level Ubuntu variants.

Supporting script:

- `scripts/import_libc_database.py`

Important detail:

- this source was enriched using `bash ./get launchpad`
- downloads were run through local proxy `127.0.0.1:7890`

This source materially added versions like:

- `libc6_2.23-0ubuntu10_amd64`
- `libc6_2.23-0ubuntu11_amd64`
- `libc6_2.31-0ubuntu9.10_amd64`
- many `2.35-0ubuntu3.x`
- many `2.39-0ubuntu8.x`
- newer `2.42-*` / `2.43-*`
- both `amd64` and `i386`

### 4. `glibc-all-in-one`

Local path:

- `data/libc/community/glibc-all-in-one/`

This was used only as a version-list reference, not as the main payload store.

Important distinction:

- `update_list` refreshes `list` / `old_list`
- it does not automatically materialize a large local libc payload directory

So if the directory looks small, that is expected.

## Why Symbol Extraction Was Fixed

Early on, many `.symbols` files in `raw/db` were too sparse, in some cases only
one or two lines. That made local matching much worse than `LibcSearcher`.

To fix this, `data/libc/raw/common/libc.sh` was patched so symbol extraction is
more robust:

- prefer richer symbol dumping
- tolerate environments where only some ELF tools are available
- use network fallbacks via `curl` when `wget` is not sufficient

The community clone's `common/libc.sh` was also patched similarly to make
Launchpad and package downloads work more reliably through the local proxy.

## Current SQLite Schema

Relevant schema file:

- `src/chun/core/catalog/schema.sql`

Main tables:

- `libc_versions`
- `symbols`
- `dataset_meta`

Important schema choices:

- `symbols` uses composite primary key `(libc_id, symbol_name)`
- `symbols` is `WITHOUT ROWID`
- `symbols.offset_12bit` is a stored generated column
- `symbols.score` is persisted
- covering index:
  - `idx_symbols_name_tail_libc(symbol_name, offset_12bit, libc_id)`

This schema is optimized for leak-tail lookup, not for general-purpose package
inventory.

## Builder Design

Builder implementation:

- `src/chun/core/catalog/builder.py`
- CLI wrapper: `scripts/build_libc_db.py`

The builder currently supports two modes:

- default: `core-only`
- `--all`: keep all symbols

### Core-only mode

Default behavior:

- only symbols from `src/chun/core/catalog/catalog_symbols.yaml` are kept
- aliases are normalized to canonical names
- each canonical symbol gets a weight based on `priority`

Current score mapping:

- `priority: 1` -> `10.0`
- `priority: 2` -> `3.0`
- `priority: 3` -> `1.0`
- unknown symbols in `--all` mode -> `0.1`

This default mode exists specifically so `data/libc/libc.db` can stay small
enough to commit into Git.

### Full mode

`python3 scripts/build_libc_db.py --all`

Use this only for local research when maximum symbol coverage matters more than
artifact size.

## Duplicate Symbol Handling

Community datasets exposed a real issue: some `.symbols` files contain duplicate
symbol names.

Current builder behavior:

- keep the first offset seen for a duplicate symbol
- ignore later duplicates

Rationale:

- community-rich datasets should not break the build
- stability of the build mattered more than strict rejection

This behavior lives in:

- `src/chun/core/catalog/builder.py`

## How `libc_id` Works

This is important.

Current `libc_id` values are assigned during build using enumeration order over
the normalized raw records.

That means:

- `libc_id` is stable only for the exact same raw dataset ordering
- `libc_id` can shift when new raw files are added
- `libc_id` is an internal SQLite key, not a long-term stable external ID

Do not design long-lived user-facing workflows around `libc_id`.

For user-facing selection, CHun moved to candidate `index`, not `libc_id`.

## Public Interfaces Already Depending on This Catalog

### Build / import side

- `python3 scripts/build_libc_db.py`
- `python3 scripts/build_libc_db.py --all`
- `python3 scripts/collect_ubuntu_libcs.py`
- `python3 scripts/import_libc_database.py /path/to/libc-database`

### Runtime catalog services

Relevant modules:

- `src/chun/core/catalog/service.py`
- `src/chun/core/catalog/repository.py`
- `src/chun/core/inference/service.py`
- `src/chun/core/resolve/service.py`

Important runtime methods already in use:

- `LibcCatalogService.find_candidates(...)`
- `LibcCatalogService.get_offset(libc_id, symbol_name)`
- `InferenceService.search_libc(...)`
- `InferenceService.libc_candidates_from_leaks(...)`
- `ResolveService.symbol(name)`

### Current `search_libc` behavior

`InferenceService.search_libc(...)` currently:

- scans registry for `RecordDomain.LIBC` + `ObservationKind.SYMBOL_LEAK`
- collects symbol leaks automatically
- queries the local SQLite catalog
- writes full result to artifact `libc.candidates`
- if exactly one candidate exists, or caller passed `index=...`:
  - writes fact `libc.version`
  - writes fact `libc.base`

Current key parameters:

- `arch: str | None = "amd64"`
- `require_all: bool = True`
- `min_match_count: int | None = None`
- `limit: int = 50`
- `artifact_name: str = "libc.candidates"`
- `index: int | None = None`

Important note:

- `index` is the public-facing selection mechanism
- `libc_id` should be treated as internal

### Current `ResolveService.symbol(name)` behavior

This method:

- reads `libc.base` from registry
- reads `libc.version` metadata to get `libc_id`
- resolves offsets via catalog
- supports service-layer symbol normalization

So names like these are intended to work at the service layer:

- `puts@got`
- `write_plt`
- `str_bin_sh`

## What Was Discussed But Not Yet Implemented

These ideas were discussed and considered good directions, but they are not
part of the frozen current implementation unless separately landed later.

### 1. Better `search_libc` candidate UI

Preferred direction:

- use indexed multi-line output
- no raw `libc_id` in user-facing output
- show:
  - index
  - libc name
  - arch
  - matched count
  - score
  - matched symbols

Preferred style discussed:

```text
[0] libc6_2.39-0ubuntu8.6_amd64
    matched=2  score=13.0  arch=amd64
    symbols=puts, read
```

### 2. Unique-hit success output

Preferred direction:

- use `log.success(...)`
- include the resolved libc name

Preferred message style discussed:

```text
[+] confirmed libc: libc6_2.39-0ubuntu8.6_amd64
```

### 3. Single-architecture narrowing

Preferred direction:

- allow `search_libc` to use the script/session ELF architecture by default
- still allow opt-out to full-arch matching

Preferred parameter name discussed:

- `single_arch: bool = True`

Rationale:

- clearer than `auto_arch`
- expresses result, not implementation detail

At freeze time this is a design decision, not a recorded implementation
guarantee.

## Recommended Refresh Workflow

If a future refresh is needed, use this order.

### 1. Preserve the frozen baseline

Before doing anything large:

- branch from the current frozen state
- keep the current `data/libc/libc.db` available for regression comparison

### 2. Refresh community source

Typical commands:

```bash
export HTTP_PROXY=http://127.0.0.1:7890
export HTTPS_PROXY=http://127.0.0.1:7890
export ALL_PROXY=socks5://127.0.0.1:7890
cd data/libc/community/libc-database
bash ./get launchpad
```

This is the most effective path for Ubuntu patch-level expansion.

### 3. Import into CHun raw/db

```bash
python3 scripts/import_libc_database.py data/libc/community/libc-database
```

If source `.symbols` files are weak but `.so` files exist:

```bash
python3 scripts/import_libc_database.py data/libc/community/libc-database --rebuild-sparse-symbols
```

### 4. Rebuild the lightweight DB

```bash
python3 scripts/build_libc_db.py
```

### 5. Validate practical coverage

Do not stop at counts alone. Validate with real leak patterns from past CTFs.

Recommended checks:

- known `puts/read` Ubuntu 2.23 cases
- `2.31-0ubuntu9.x`
- `2.35-0ubuntu3.x`
- `2.39-0ubuntu8.x`

### 6. Treat `libc_id` as rebuild-local

If future code or docs mention specific `libc_id` values, revisit that work.
They are not stable across large refreshes.

## Freeze Recommendation

At the time this note was written, the catalog was considered ready to freeze
into `develop` so feature work could continue without branch churn.

Why this freeze was considered acceptable:

- local matching had become stable across multiple real CTF tests
- Ubuntu `amd64/i386` coverage had improved significantly
- `data/libc/libc.db` remained small enough for GitHub
- future expansion can continue through raw source refresh + rebuild
