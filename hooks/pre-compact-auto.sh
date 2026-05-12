#!/usr/bin/env bash
# PreCompact (matcher: auto) — runs before Claude auto-compacts the
# conversation. Two-step:
#
#   1. lock-check.py — if a long algokiller scan holds the kernel lock,
#      exit 2 and refuse the compact (we'd corrupt mid-scan state).
#   2. dump-session-state.py — best-effort persist ledger summary so
#      SessionStart(matcher=compact) can rehydrate it.
#
# Steps 1 and 2 are independent; lock-check decides the exit code,
# dump-session-state always runs (no harm even when blocked, helps the
# subsequent manual /compact).
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

# Run the lock probe first. Exit 2 is the documented "block compact"
# signal Claude Code honours.
python3 "${PLUGIN_ROOT}/hooks/lock-check.py"
rc=$?
if [ "$rc" -eq 2 ]; then
    # Still dump state — when the user later runs /compact manually,
    # the SessionStart rehydration uses this file.
    python3 "${PLUGIN_ROOT}/hooks/dump-session-state.py" || true
    exit 2
fi

# Lock free → dump state and let compact proceed.
python3 "${PLUGIN_ROOT}/hooks/dump-session-state.py" || true
exit 0
