# Security Policy

## Reporting a vulnerability

Open a private security advisory on GitHub:
**<https://github.com/icloudza/algokiller-plugin/security/advisories/new>**

Do **not** open a public issue for security bugs.

If GitHub advisories are unavailable, email the maintainer directly via
the email listed on the [author's GitHub profile](https://github.com/icloudza).

Include:
- Affected version (`plugin.json` → `version`)
- Reproduction steps (a minimal trace fixture or static-tool argv that
  triggers the issue is enough — keep it self-contained)
- Impact assessment (sandbox escape, command injection, RCE, path
  escape, plugin-tool denial of service, etc.)
- Any mitigation you've already prototyped

Reports get triaged within **5 business days** and a CVE-numbered fix
release within **30 days** of confirmation.

## Threat model

`algokiller-plugin` is invoked by a Claude client (Claude Code or
Claude Desktop) with the user's local privileges. It does **not** open
network sockets, fetch remote content, or accept input from anywhere
other than:

1. The Claude client's MCP runtime (JSON-RPC 2.0 over stdio).
2. The bound trace file (mmap, read-only).
3. The user's local static-analysis CLIs invoked via
   `algokiller.run_static_tool` (argv list — never `/bin/sh`).
4. Artifacts written under `~/AlgoKiller/artifacts/<trace>/<ts>/` and
   guarded against directory escape.

The plugin is therefore **not** a remote-exposure surface. The primary
security concerns are:

- **Command injection via `run_static_tool`** — mitigated by argv-list
  execution (never `subprocess.run(..., shell=True)`), hard tool
  allow-list, per-tool `forbid_args` policy, NUL-byte rejection.
- **`r2` runaway analysis** — mitigated by mandatory `-q -2 -n` flags
  and a forbidden-verb scan that rejects `aaa`/`aac`/`aae`/`aab`/
  `aav`/`aar`/`aap` family commands and `-A`/`-AA`/`-AAA` flags.
- **Write/sign operations via security tools** — `codesign --sign`,
  `codesign --remove-signature`, `ldid -S`, `lipo --create`/`--replace`/
  `--remove` are explicitly forbidden by `static_tools.forbid_args`.
- **Artifact path escape** — `ArtifactStore.write()` resolves the final
  path and rejects anything not `is_relative_to(self.base_dir)`.
- **JSON-RPC payload poisoning** — raw trace bytes can contain lone
  UTF-8 surrogates; `daemon._scrub_text()` and `static_tools._scrub()`
  re-encode with `errors="replace"` before returning to the MCP layer.
- **Daemon resource leaks** — `atexit` + SIGTERM / SIGINT cleanup; the
  daemon process is killed on plugin shutdown and restarted on
  re-bind / `BrokenPipeError`.

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.8.x   | ✅        |
| < 0.8   | ❌ (please upgrade — Hypothesis Ledger v2 is required to keep deliverables auditable) |

## Out of scope

- Trace files crafted to mislead the user (this is an analysis tool, not
  a verifier; users decide whether a trace is trustworthy).
- The user's own static-analysis binaries (`rabin2`, `r2`, `objdump`,
  `class-dump`, etc.) — vulnerabilities in those tools should be
  reported upstream.
- The `ak_search` C engine running on malformed traces — please still
  report any crash, but mitigation may be a parser hardening rather
  than a CVE-class fix.
