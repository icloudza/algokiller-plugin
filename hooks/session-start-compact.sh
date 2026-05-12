#!/usr/bin/env bash
# SessionStart (matcher: compact) — runs after Claude finishes
# auto/manual compact and starts the post-compact session.
#
# We rehydrate the ledger summary that pre-compact-auto / pre-compact-
# manual persisted, by cat'ing _compact_state.json + the static
# post-compact-rules markdown. Both go to stdout, which Claude Code
# interprets as additional system context for the new session.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

# 1. Static rules — these survive every compact; they're the rules
# Claude needs to remember about ledger discipline regardless of any
# specific session's state.
RULES_FILE="${PLUGIN_ROOT}/context/post-compact-rules.md"
if [ -f "$RULES_FILE" ]; then
    cat "$RULES_FILE"
    echo
fi

# 2. Per-session dump from the latest active session.
DUMP=$(python3 "${PLUGIN_ROOT}/hooks/find-latest-compact-state.py" 2>/dev/null)
if [ -n "$DUMP" ] && [ -f "$DUMP" ]; then
    echo "## Pre-compact session snapshot (auto-recovered)"
    echo
    echo "The following summary was captured immediately before the"
    echo "previous compact and is replayed here so ledger references"
    echo "in the conversation history still resolve. Treat it as raw"
    echo "evidence, not narrative."
    echo
    echo '```json'
    cat "$DUMP"
    echo '```'
fi
exit 0
