# algokiller-plugin

**Language**: [中文](README.md) | **English**

Claude Desktop plugin for ARM64 trace evidence analysis and cipher/algorithm recovery. Bundles the AlgoKiller methodology as skills, with a local MCP server driving the native `ak_search` engine over GB-scale traces.

> **Upstream methodology & `ak_search` engine**: [AlgoKiller](https://github.com/lidongyooo/AlgoKiller) by [@lidongyooo](https://github.com/lidongyooo)
> This repo is the Claude Desktop plugin wrapper; all methodology, the native engine, and the original harness belong to the upstream author.

---

## Capabilities

1. **Skills** (model-invoked, auto-loaded)
   - `algokiller:ciphertext-recovery` — reverse-recover encryption / signing / encoding algorithms from a ciphertext / header / token
   - `algokiller:trace-analysis` — field semantics / execution flow / detection points / buffer lifecycle
2. **Slash commands** (strong activation)
   - `/algokiller:ciphertext <trace> <task>`
   - `/algokiller:general <trace> <task>`
3. **7 MCP tools**
   - `bind_trace` / `trace_search` / `trace_context` / `write_artifact` / `list_artifacts` / `read_artifact`
   - `run_static_tool` — allow-listed system CLIs (radare2 / binutils / LLVM / jtool2 / class-dump / ripgrep / jq)
4. **Anti-drift reinjection**
   - Every tool return carries `discipline_reminder`; every 20 calls also includes `discipline_full_reinjection`

---

## Platform requirements

- **macOS** (Apple Silicon / Intel — `bin/ak_search` is built for the host arch)
- **Python 3.11+**
- **No external Python deps** (MCP server speaks JSON-RPC 2.0 over stdio using only the standard library)

Rebuild the binary when the arch doesn't match:

```bash
cd tools/search && make
cp ak_search ../../server/bin/ak_search
```

---

## Install

**Option 1 (recommended)**: Claude Desktop → `+` → **Plugins** → **Add plugin** → pick directory or zip.

**Option 2**:

```bash
zip -r algokiller-plugin.zip algokiller-plugin -x '*.pyc' '__pycache__/*'
# upload via Plugins → Add plugin → Upload a file
```

After install you should see `algokiller` under **Plugins** and `/algokiller:ciphertext` + `/algokiller:general` under **Slash commands**.

---

## How to generate a trace

This plugin expects the trace format produced by **[GumTrace](https://github.com/lidongyooo/GumTrace)** — an ARM64 dynamic instruction tracer built on the Frida Gum Stalker engine, by [@lidongyooo](https://github.com/lidongyooo).

| Aspect | Detail |
|---|---|
| Platforms | Android (ARM64) + iOS (ARM64) |
| Engine | Frida Gum Stalker |
| Output | `[module] 0xABS!0xREL mnemonic operands; ...` + `call func:` + `ret:` (5 line types) |
| Relationship to this plugin | **Companion toolchain**: GumTrace produces traces → algokiller plugin analyzes them |

### End-to-end workflow

```bash
# 1. Build GumTrace (first time)
git clone https://github.com/lidongyooo/GumTrace.git
cd GumTrace
./build_android.sh    # or ./build_ios.sh

# 2. Push to device and attach via Frida
adb push build_android/libGumTrace.so /data/local/tmp/
frida -U -f com.example.app -l example.js

# 3. Trigger the target operation inside the app (login / messaging / token generation, etc.)

# 4. Pull the trace back to macOS
adb pull /data/data/com.example.app/trace.log ~/captures/login.trace.log

# 5. Feed it to this plugin (free-form or slash in Claude Desktop)
#    e.g. "Use algokiller ciphertext mode on ~/captures/login.trace.log to recover the X-Sign cipher a3b2c1..."
```

For detailed hook scripts, see GumTrace's [example.js](https://github.com/lidongyooo/GumTrace/blob/main/example.js) / [example_ios.js](https://github.com/lidongyooo/GumTrace/blob/main/example_ios.js).

> Frida's native trace formats (`frida-trace` / Stalker default emit) are NOT compatible — GumTrace's custom emitter is required.

---

## Usage

**Strong activation (recommended)**:

```
/algokiller:ciphertext /path/to/login.trace.log Recover the ciphertext a3b2c1d4... inside header X-Sign
/algokiller:general    /path/to/risk.trace.log  Explain how the x0 return on line 99999 is computed
```

**Free-form** (Claude auto-loads the skill by description):

> Here's an ARM64 trace at `/path/to/trace.log`. Recover the algorithm that produced this ciphertext: `a3b2c1...`

Slash form is more deterministic; free-form is more natural.

---

## Deliverables

Each `bind_trace` creates a session directory:

```
~/AlgoKiller/artifacts/<trace_basename>/<YYYYMMDD_HHMMSS>/
```

`write_artifact("recovered.py", source)` writes `recovered_CIPHERTEXT_<ts>.py`; notes are saved alongside as `*.notes.md`.

---

## Directory layout

```
algokiller-plugin/
├── .claude-plugin/plugin.json
├── .mcp.json                       # MCP server declaration
├── LICENSE                         # MIT
├── server/                         # JSON-RPC 2.0 MCP server (stdio)
│   ├── algokiller_mcp.py
│   ├── state.py / daemon.py / discipline.py / artifacts.py
│   ├── static_tools.py             # allow-listed CLI runner
│   └── bin/ak_search               # native search engine (Mach-O), **NOT injected into Bash PATH**
├── skills/                         # all skills (slash activation entries + methodologies)
│   ├── ciphertext/SKILL.md         # /algokiller:ciphertext strong activation (user-only)
│   ├── general/SKILL.md            # /algokiller:general strong activation (user-only)
│   ├── ciphertext-recovery/SKILL.md  # full ciphertext recovery methodology (model + user)
│   └── trace-analysis/SKILL.md       # full general trace-analysis methodology (model + user)
└── README.md / README.en.md
```

---

## Local smoke test (no Claude Desktop)

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python3 server/algokiller_mcp.py
```

Expect: `initialize` response + `tools/list` advertising 7 tools.

---

## Companion: Binary Ninja MCP (dynamic + static pairing)

Trace tools show *what happened*; BN shows *what the code looks like*. Install either BN MCP and the linkage activates automatically:

| Plugin | License | Transport |
|---|---|---|
| [fosdickio/binary_ninja_mcp](https://github.com/fosdickio/binary_ninja_mcp) | GPL-3.0 | stdio |
| [jtang613/BinAssistMCP](https://github.com/jtang613/BinAssistMCP) | MIT | HTTP/SSE |

Both are Binary Ninja plugins and require a BN commercial license. The SKILLs detect the online side by namespace (`binary_ninja_mcp.*` / `binassist.*`); no extra config. With BN offline the plugin still runs (slower but viable) — the SKILLs won't pretend BN tools exist, and the final deliverable recommends static follow-up.

---

## System CLI linkage — `run_static_tool`

Allow-list-controlled shell (argv mode, command injection impossible). Tools installed on the host are auto-available:

| Category | Tools |
|---|---|
| Basics | `file`, `lipo`, `rax2`, `rg`, `jq`, `c++filt`, `llvm-cxxfilt`, `addr2line` |
| radare2 | `rabin2`, `rasm2`, `r2` (strictly bounded) |
| GNU binutils | `readelf`, `objdump`, `nm`, `strings` |
| LLVM | `llvm-objdump`, `llvm-nm`, `llvm-readelf`, `llvm-strings` |
| Mach-O / iOS | `otool`, `jtool2`, `class-dump` |

If a tool isn't installed, the response includes a `hint` with the install command.

**r2 boundary**: must include `-q -2 -n -c "<single cmd>"`; `-A` / `aaa` / `aac` / full-analysis commands rejected by the wrapper.

**Priority**: `binary_ninja_mcp.*` online > `run_static_tool` > trace-only.

---

## Troubleshooting

### Plugin loads but tools aren't visible

Most likely cause: `${CLAUDE_PLUGIN_ROOT}` was not expanded by your Desktop build. Edit the installed `.mcp.json` to use absolute paths:

```json
{
  "mcpServers": {
    "algokiller": {
      "command": "python3",
      "args": ["-u", "/ABS/PATH/server/algokiller_mcp.py"],
      "cwd": "/ABS/PATH",
      "env": {
        "ALGOKILLER_PLUGIN_ROOT": "/ABS/PATH",
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

Check the Claude Desktop MCP server logs and grep for `[algokiller-mcp]` stderr lines.

### `bind_trace` fails with "binary not found" / "Permission denied"

The plugin auto-runs `chmod +x` + `xattr -d com.apple.quarantine` on `daemon.start()`. If that fails, do it manually:

```bash
chmod +x server/bin/ak_search
xattr -d com.apple.quarantine server/bin/ak_search
file server/bin/ak_search    # expect: Mach-O 64-bit executable arm64
```

Wrong arch? Rebuild: `cd tools/search && make && cp ak_search ../../server/bin/`.

### `bind_trace` appears to hang on a GB-scale trace

`ak_search` builds its line-offset index on first load — 5 GB takes ~30-60 s on Apple Silicon. `pgrep -lf ak_search` will show the process saturating CPU during indexing; subsequent calls are millisecond-fast.

### Artifacts pile up

```bash
ls -dt ~/AlgoKiller/artifacts/*/*/ | tail -n +11 | xargs rm -rf
```

### Leftover daemon processes

The plugin registers `atexit` + SIGTERM/SIGINT cleanup. If Desktop is force-killed:

```bash
pkill -f "ak_search daemon"
```

Safe — daemons are stateless and rebuilt on the next `bind_trace`.
