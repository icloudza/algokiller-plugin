# Contributing to algokiller-plugin

Thanks for taking the time to look. Quick rules first, rationale below.

## TL;DR — what gates a PR

1. `tools/search/tests/run_tests.sh` — **132 PASS / 0 FAIL** on the
   native C engine harness. Required.
2. `python3 -m unittest discover -s tests/python -v` — Python unit
   tests for the MCP server (Hypothesis Ledger gates, artifact path
   escape, static-tool boundary). Standard-library only — no `pytest`
   needed. Required.
3. Conventional-commit message: `feat(<area>): ...`, `fix(<area>): ...`,
   `docs(<area>): ...`, `chore(<area>): ...`. `<area>` should match a
   real subsystem (`ledger`, `constscan`, `daemon`, `skill`,
   `manifest`, ...). Squashed PRs follow the same convention.
4. No new external Python dependency unless previously discussed in an
   issue — the MCP server is intentionally **standard-library only**.
   Easier install, smaller blast radius.
5. Docs that mention a number (fingerprint count, tool count, test
   count, file size) get updated in the same PR as the code that
   changed the number. Drift between README and reality is a fail.

## Repo layout

```
algokiller-plugin/
├── .claude-plugin/plugin.json   # Claude Desktop plugin manifest
├── .mcp.json                    # MCP server declaration (stdio)
├── server/                      # Python MCP server (stdlib only)
│   ├── algokiller_mcp.py        # JSON-RPC 2.0 router + tool handlers
│   ├── state.py / daemon.py / discipline.py / artifacts.py / hypothesis.py
│   └── static_tools.py
├── tools/search/                # Native C engine (mmap + BMH + line index)
│   ├── search.c / Makefile
│   └── tests/                   # POSIX-sh harness, 132 assertions
├── skills/                      # Claude skills (model + slash entries)
└── tests/python/                # Python unit tests for the MCP server
```

## Development setup

```bash
git clone https://github.com/icloudza/algokiller-plugin
cd algokiller-plugin

# Build the native engine for your platform.
( cd tools/search && make )
cp tools/search/ak_search server/bin/

# Run both test suites.
./tools/search/tests/run_tests.sh
python3 -m unittest discover -s tests/python -v
```

No virtualenv, no `pip install` — both the runtime MCP server **and**
its test suite are standard-library only.

## Pull-request checklist

- [ ] Both test suites pass locally on macOS arm64 (and Linux x86_64 if
      you touched portability surface).
- [ ] Added regression tests for any bug fix or new MCP tool.
- [ ] Updated `CHANGELOG.md` under `## [Unreleased]`.
- [ ] Updated `README.md` / `README.en.md` / `tools/search/README.md`
      if you changed user-facing surface or numbers.
- [ ] No new entries in `server/static_tools.ALLOWED_TOOLS` without a
      corresponding `forbid_args` review (write operations stay out).
- [ ] No `subprocess.run(..., shell=True)` introduced anywhere.

## Anti-patterns we reject

- **Bypassing the Hypothesis Ledger.** Don't loosen FIX #1–#4 gates to
  "make the AI happier". The whole product is the anti-hallucination
  guarantee — gates that are easy to satisfy are no guarantee at all.
- **Adding network calls.** This plugin is fully local. If you need
  remote data, fetch it outside the plugin and feed it as a static
  trace / artifact.
- **Shell-string commands.** All subprocess execution goes through
  argv lists. Never compose a command from user-controlled strings.
- **Skipping discipline injection.** Tool returns must continue to
  carry `discipline_reminder` and the per-20-call full reinjection.
  This is what keeps long traces from drifting.

## Reporting bugs

Open a GitHub issue with: version, platform, repro steps. For security
issues see [`SECURITY.md`](SECURITY.md) — please don't open public issues
for those.
