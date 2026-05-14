# algokiller-plugin

**Language**: [中文](README.md) | **English**

Claude plugin (works in both Claude Code CLI and Claude Desktop) for ARM64 trace evidence analysis and cipher/algorithm recovery. Bundles the AlgoKiller methodology as skills, with a local MCP server driving the native `ak_search` engine (14 subcommands) over GB-scale traces.

> **Methodology + ak_search engine origin**: [AlgoKiller](https://github.com/lidongyooo/AlgoKiller) by [@lidongyooo](https://github.com/lidongyooo)
> Upstream contributes the three core subcommands (`match` / `context` / `daemon` — mmap + BMH + line index + tab-protocol daemon) and the original methodology harness.
> This repo extends the native engine with 11 additional subcommands (`regflow` / `producer` / `semop` / `lint` / `fold` / `callgraph` / `modgraph` / `hexblock` / `constscan` / `cryptoinstr` / `bytes` — see [tools/search/README.md](tools/search/README.md)) and packages everything as a Claude plugin (loadable from both Claude Code and Claude Desktop). Original code copyright belongs to upstream; plugin extensions are MIT.

---

## 🚀 Quick install

```bash
claude plugin marketplace add icloudza/algokiller-plugin
claude plugin install ak@ak-suite
```

Updates:

```bash
claude plugin marketplace update
claude plugin update ak@ak-suite
```

> Inside the Claude Code REPL you can also use the equivalent `/plugin marketplace add ...` / `/plugin install ...` slash commands. Manual install is covered below in [Install](#install).

**Cursor / Codex**: this repo also ships standard stdio MCP server setup examples. Cursor can use `.cursor/mcp.json` directly; Codex users can copy `examples/mcp/codex.config.toml` into `~/.codex/config.toml`. See [Cursor and Codex MCP setup](docs/mcp-clients.md). Non-Claude clients can use the MCP tools directly, but they do not automatically get Claude slash commands or skill auto-loading.

---

## Capabilities

1. **Skills** (model-invoked, auto-loaded)
   - `ak:ciphertext-recovery` — reverse-recover encryption / signing / encoding algorithms from a ciphertext / header / token
   - `ak:trace-analysis` — field semantics / execution flow / detection points / buffer lifecycle
2. **Slash commands** (strong activation)
   - `/ak:ciphertext <trace> <task>`
   - `/ak:general <trace> <task>`
3. **28 MCP tools** (21 trace/artifact/static + 7 hypothesis-ledger; v1.2.0 added `trace_function` + `trace_immseq` for OLLVM-flattened binary analysis)
   - Binding / artifacts: `bind_trace` / `pick_output_dir` (native folder picker) / `write_artifact` / `list_artifacts` / `read_artifact`
   - Core search: `trace_search` / `trace_context`
   - Data flow: `trace_regflow` (register-value evolution) / `trace_producer` (nearest writer of a value) / `trace_semop` (11-class instruction classifier)
   - Health & volume: `trace_lint` (one-pass JSON summary) / `trace_fold` (block-aware folding, 115 MB → 1.1 MB)
   - Call graph: `trace_callgraph` (Top-K / xref) / `trace_modgraph` (cross-module matrix) / `trace_hexblock` (structured call+args+hexdump+ret)
   - Crypto fingerprints: `trace_constscan` (**97** hash / cipher / ecc / crc / mac constants — 95 scalar literals + 2 NEON SIMD broadcasts; covers MD5 init+T-table / SHA-256 init+K-table / SM3 init+T_j / SHA-3 / CRC32 / AES sbox+Te0 / SM4 / ChaCha20 / Poly1305 / SipHash / HMAC ipad-opad (scalar + SIMD) / P-256 / secp256k1 / Ed25519 / Curve25519; each hit carries a `verdict` ∈ `real` / `real_simd` / `weak` / `alu_only`; MD5.T[i] / SHA256.K[i] etc. also expose `block_count_estimate`) / `trace_cryptoinstr` (ARM Crypto Extensions hardware instructions: AES / SHA-1 / SHA-256 / SHA-512 / SHA-3 / SM3 / SM4 / GHASH) / `trace_bytes` (hex literal + auto byte-reverse variants)
   - Static analysis: `run_static_tool` — allow-listed system CLIs (radare2 / binutils / LLVM / jtool2 / class-dump / ripgrep / jq)
4. **Anti-drift reinjection**
   - Every tool return carries `discipline_reminder`; every 20 calls also includes `discipline_full_reinjection`
5. **Sub-agents**
   - `hypothesis-reviewer` — Independent blue-team reviewer spawned via the `Agent` tool before any `hypothesis_conclude(final_confidence="high")` on a load-bearing hypothesis. Read-only access to the ledger and trace; recommends `confirm` / `refute` / `abandon`. See [docs/agents.md](docs/agents.md).
6. **Multi-threaded scan for large traces**
   - `trace_constscan` / `trace_cryptoinstr` auto-partition the trace line range across worker threads (default = host CPU, capped at 16; overridable via the `threads` parameter). On a 4.5 GB / 48 M-line trace `constscan` runs in ~19 s with 8 threads (vs 121 s single-threaded); output is byte-identical across thread counts.

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

> One-line install is at the top under [🚀 Quick install](#-quick-install).

**Manual install (fallback)**: clone the repo, then
- **Claude Desktop**: `+` → **Plugins** → **Add plugin** → pick the directory
- **Claude Code**: run `claude plugin install .` from the repo root (or register it as a local marketplace via `claude plugin marketplace add <local-path>`)

```bash
git clone https://github.com/icloudza/algokiller-plugin
```

After install you should see `ak` under **Plugins** and `/ak:ciphertext` + `/ak:general` under **Slash commands**.

> If you previously registered the plugin from a local directory under the same name, uninstall it via `claude plugin uninstall <name>@<old-source>` after switching to the marketplace install to avoid double-registration.

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

# 5. Feed it to this plugin (free-form or slash in Claude Code / Claude Desktop)
#    e.g. "Use algokiller ciphertext mode on ~/captures/login.trace.log to recover the X-Sign cipher a3b2c1..."
```

For detailed hook scripts, see GumTrace's [example.js](https://github.com/lidongyooo/GumTrace/blob/main/example.js) / [example_ios.js](https://github.com/lidongyooo/GumTrace/blob/main/example_ios.js), plus this repo's three production templates under [`examples/frida-gumtrace/`](examples/frida-gumtrace/) (including an anti-jailbreak-bypass spawn pattern).

> **Full iOS jailbreak deployment guide** (iproxy + scp + ldid + anti-jailbreak / anti-frida bypass) is in **[docs/setup-ios.md](docs/setup-ios.md)** — covers Dopamine, known_hosts collisions, TweakInject injection failures, the Dopamine "Hide Jailbreak" ↔ GumTrace loading conflict, and resilient transfer for multi-GB traces over USB.

> Frida's native trace formats (`frida-trace` / Stalker default emit) are NOT compatible — GumTrace's custom emitter is required.

---

## Usage

**Strong activation (recommended)**:

```
/ak:ciphertext /path/to/login.trace.log Recover the ciphertext a3b2c1d4... inside header X-Sign
/ak:general    /path/to/risk.trace.log  Explain how the x0 return on line 99999 is computed
```

**Free-form** (Claude auto-loads the skill by description):

> Here's an ARM64 trace at `/path/to/trace.log`. Recover the algorithm that produced this ciphertext: `a3b2c1...`

Slash form is more deterministic; free-form is more natural.

---

## Deliverables

Each `bind_trace` resolves the output base directory via a **5-priority chain** and reports the result back in `output_dir_resolved` + `output_dir_source`; the agent surfaces this to the user before the first `write_artifact`.

```
① bind_trace(output_dir=...)              ← explicit argument
② $ALGOKILLER_OUTPUT_DIR                  ← env global override (CI / power users)
③ <project>/.algokiller.toml [output] dir ← project-level config
④ <project>/.algokiller/<trace>/<ts>/     ← walk up to 4 levels from the trace's
                                            parent for project markers (.git /
                                            pyproject.toml / Cargo.toml /
                                            package.json / go.mod / Makefile …)
⑤ <Documents>/AlgoKiller-Reports/<trace>/<ts>/   ← fallback
   (Linux honours XDG_DOCUMENTS_DIR; macOS / Windows use ~/Documents)
```

Each new bind creates a fresh `<timestamp>/` so multiple analyses of the same trace stay side by side for comparison.

**`pick_output_dir`** pops the host's native folder picker — macOS Finder `choose folder`, Windows `FolderBrowserDialog`, Linux `zenity` / `kdialog`; headless / web clients return `unsupported` and the agent falls back to asking for the path in chat.

**`.algokiller.toml` example** (drop this in your project root):

```toml
[output]
dir = "build/algokiller-reports"   # relative resolves against the project root;
                                   # absolute paths are also accepted
```

`write_artifact("recovered.py", source)` writes `recovered_CIPHERTEXT_<ts>.py`. The `.notes.md` sidecar is no longer written — analysis reports carry their narrative inline, so the sidecar was 100 % redundant token spend.

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
│   ├── ciphertext/SKILL.md         # /ak:ciphertext strong activation (user-only)
│   ├── general/SKILL.md            # /ak:general strong activation (user-only)
│   ├── ciphertext-recovery/SKILL.md  # full ciphertext recovery methodology (model + user)
│   └── trace-analysis/SKILL.md       # full general trace-analysis methodology (model + user)
└── README.md / README.en.md
```

---

## Local smoke test (no Claude client needed)

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | python3 server/algokiller_mcp.py
```

Expect: `initialize` response + `tools/list` advertising 28 tools (21 trace/artifact/static tools + 7 hypothesis-ledger tools, including `pick_output_dir` / `mark_hypothesis_reviewed` / `hypothesis_archive` / `trace_function` / `trace_immseq`).

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

Check the Claude client MCP server logs (Claude Desktop's application logs, or Claude Code session stderr) and grep for `[algokiller-mcp]` stderr lines.

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
