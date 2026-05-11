# ak_search

High-throughput exact text search for very large trace-like files.

> **Upstream**: [AlgoKiller/tools/search](https://github.com/lidongyooo/AlgoKiller/tree/main/tools/search) by [@lidongyooo](https://github.com/lidongyooo).
> Source mirrored into this plugin repo so non-arm64-macOS users can build their own `ak_search` binary. **Copyright and license of `search.c` / `Makefile` / `build.sh` belong to the upstream author**; the plugin itself is MIT.

---

## Why this directory exists

This is the source of `ak_search`, mirrored from upstream so non-arm64-macOS users can build their own binary.

- `./ak_search`  —— upstream prebuilt **arm64-macOS** binary (same hash as `server/bin/ak_search`, kept for reference / direct run)
- `./search.c`   —— full source (single C11 translation unit, ~28 KB)
- `./Makefile`   —— minimal builder
- `./build.sh`   —— thin wrapper around `make`

### Build for your platform

```bash
cd tools/search
make                              # produces ./ak_search
cp ak_search ../../server/bin/    # replace the prebuilt arm64 binary
chmod +x ../../server/bin/ak_search
```

The plugin auto-runs `chmod +x` + Gatekeeper xattr cleanup on `daemon.start()`. If you cross-compile or grab from CI, drop the binary at `server/bin/ak_search` and the plugin picks it up.

## Build flags

The Makefile is intentionally minimal:

```makefile
CC      ?= cc
CFLAGS  ?= -O3 -std=c11 -Wall -Wextra -Wpedantic
LDFLAGS ?=
```

Override at command line:

```bash
make CC=clang CFLAGS='-O3 -march=native -std=c11'
make CC=aarch64-linux-gnu-gcc                       # cross compile for Linux arm64
```

## CLI surface (what the plugin's MCP server drives)

### Exact match

Return lines containing an exact string. Matching is ASCII case-insensitive: the query is folded to lowercase once, and file bytes are folded during scan without materializing a lowercase copy of the file. Line numbers are 1-based.

```bash
./ak_search match --file trace.log --query "x0=0x1234" --from-line 1000000 --limit 20
./ak_search match --file trace.log --query "mem_w=0x1234" --before-line 1000000 --limit 20
```

`--before-line` searches only lines before the anchor and returns nearest earlier matches first. Mutually exclusive with `--from-line`.

### Context

Return surrounding lines for a target line.

```bash
./ak_search context --file trace.log --line 1000000 --context 5
./ak_search context --file trace.log --line 1000000 --before 2 --after 8
```

Output is JSONL:

```json
{"type":"match","line":42,"byte_offset":8192,"text":"..."}
```

### Daemon

The plugin's MCP server uses daemon mode to mmap the trace and build a line-offset index once, then reuse the same process for repeated `match` and `context` calls.

```bash
./ak_search daemon --file trace.log
```
