# Cache API

## 目标与定位

`CacheService` 是 CHun 的跨进程静态分析缓存层，目标是降低 `CHun.script(...).start()` 的重复初始化成本。

核心边界：

- cache 只保存静态事实（offset / 元信息）
- 运行时事实（如 `libc.base` / `elf.base`）仍属于 `session.rec`
- cache 不直接持久化 runtime base；脚本层若已存在 `elf.base` / `libc.base`，可在读取时临时组合成绝对地址

## 接入范围

当前只接入脚本态：

- `CHun.script(...)`
- `ScriptEntry` 热路径（ELF / libc / gadget）

暂未接入：

- workflow launcher/runtime

## 启用与关闭

`CHun.script` 支持：

```python
from chun import CHun

s = CHun.script(
    "./challenge",
    cache=True,               # 默认 True
    cache_dir=None,           # 默认按环境变量优先级解析
    auto_local_libc=False,    # 默认不自动探测本机 libc
).start()
```

环境变量：

- `CHUN_NO_CACHE=1`：禁用读写缓存
- `CHUN_CLEAR_CACHE=1`：本次启动先清缓存再运行
- `CHUN_CACHE_DIR=/path/to/cache`：覆盖默认缓存目录

## 默认目录优先级

`cache_dir` 解析顺序：

1. `CHun.script(..., cache_dir=...)` 显式参数
2. `CHUN_CACHE_DIR`
3. `XDG_CACHE_HOME/chun`
4. `~/.cache/chun`

默认命名空间：

- `elf/`
- `libc/`
- `gadget/`

## Key 与 Schema

cache key 基于文件内容 `sha256`，不是仅基于路径。

典型格式：

- `elf`: `<sha256>-elf-schema<version>.json`
- `libc`: `<sha256>-libc-schema<version>.json`
- `gadget`: `<sha256>-gadget-schema<version>-<source>-<arch>-<bits>-<pwntools_version>.json`

失效机制：

- 文件内容变化 -> 自动失效（sha 变化）
- schema 版本变化 -> 自动失效
- gadget 维度包含 pwntools 版本，避免结构不兼容复用

## 存储格式

当前使用 JSON + 原子写：

1. 写入 `*.json.tmp`
2. `replace` 到正式文件

损坏 JSON / schema 不匹配 / 字段不合法会被当作 cache miss，不会中断 exp。

## 缓存内容

### ELF

缓存最小元信息：

- `arch/bits/endian/entry`
- `pie/nx/canary/relro/stripped/static`
- `address_mode`（`offset` 或 `vaddr`）
- `image_base`

动态表按需缓存（lazy）：

- `symbols`
- `got`
- `plt`
- `sections`

说明：

- `s.elf.sym[...]` / `s.elf.symbol[...]` / `s.elf.symbols[...]` 统一写入 `symbols` 表

### libc

仅在“有可信来源”时建立缓存（如显式 `libc=...`）：

- `source/trusted/usable_for_remote`
- `arch/bits/build_id`
- `core_symbols`（catalog 核心符号）
- `extra_symbols`（运行时按需补充）
- `strings`（如 `/bin/sh`）

默认未指定 libc 时 `source=unresolved`，不会自动落本机 libc cache。

### gadget

只缓存查询结果，不 pickle `ROP` 对象：

- query token
- `found=true/false`
- `value`
- `address_mode`

`found=false` 也会缓存，避免重复初始化 `ROP(elf)`。

## 地址语义

- libc symbol/string/gadget：始终保存 offset
- PIE ELF：保存 offset（`address_mode=offset`）
- non-PIE ELF：保存 vaddr（`address_mode=vaddr`）

运行时地址由 runtime base（`libc.base` / `elf.base`）在消费期解释。

脚本态当前语义：

- `s.elf.sym/got/plt/sections[...]`
  - non-PIE：直接返回静态 vaddr
  - PIE 且已记录 `elf.base`：返回 `elf.base + offset`
  - PIE 但尚未记录 `elf.base`：warning 一次，并退回静态 offset
- gadget cache 仍只保存 offset/vaddr；脚本态 `s.gadget[...]` 也按同样规则解释 `elf.base`

## CLI 查看缓存

可直接查看某个 binary/libc 的缓存状态：

```bash
chun cache state ./challenge
```

可选参数：

```bash
chun cache state ./challenge --cache-dir ./.chun_cache
```

输出包含：

- `elf/libc/gadget` 的 hit/miss 状态
- ELF 元信息摘要与 `symbols/got/plt/sections` 明细
- gadget 记录摘要与每条 query 的 `found/value/mode`
- 当目标是 binary 时，`libc` 状态会优先读取 ELF 记录里的 `linked_libc_*` 关联（若存在），因此可直接看到该 binary 对应的 libc cache 命中情况

## 当前边界

- 不做 SQLite 缓存
- 不做 ELF/libc/ROP 对象 pickle
- 不持久化 `search_libc()` 的远端识别结果（避免不同目标混淆）
- workflow 暂未接入 cache（后续可复用同一 `CacheService`）
