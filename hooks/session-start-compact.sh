#!/usr/bin/env bash
# SessionStart (matcher: compact) — runs after Claude finishes
# auto/manual compact and starts the post-compact session.
#
# Two stdout streams concatenated (Claude Code interprets SessionStart
# hook stdout as additional system context):
#
# 1. Static rules — context/post-compact-rules.md. Tied to compact
#    semantics (ledger references survive, raw output dropped, etc).
#    These rules don't depend on any specific session.
#
# 2. Per-session snapshot — the structured markdown rendered by
#    dump-session-state.py into _compact_state.md. Active hypotheses,
#    rejected paths, recent tool-call ledger, artifacts written.
#    Markdown beats JSON-in-codefence here: the model reads section
#    headers, scans past raw JSON.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

# 1. Static post-compact rules.
RULES_FILE="${PLUGIN_ROOT}/context/post-compact-rules.md"
if [ -f "$RULES_FILE" ]; then
    cat "$RULES_FILE"
    echo
fi

# 2. Per-session snapshot — prefer the markdown file produced by
# dump-session-state.py (schema v2+); fall back to the legacy JSON
# blob if only the old schema is present, so an in-flight upgrade
# doesn't break post-compact rehydration.
DUMP_JSON=$(python3 "${PLUGIN_ROOT}/hooks/find-latest-compact-state.py" 2>/dev/null)
if [ -n "$DUMP_JSON" ] && [ -f "$DUMP_JSON" ]; then
    DUMP_MD="${DUMP_JSON%.json}.md"
    if [ -f "$DUMP_MD" ]; then
        cat "$DUMP_MD"
    else
        # Legacy schema-1 fallback: cat the JSON in a code fence so
        # the model still gets *something* useful. New sessions go
        # straight through the md branch above.
        echo "## Pre-compact session snapshot (auto-recovered, legacy schema)"
        echo
        echo "The following summary was captured immediately before the"
        echo "previous compact. New sessions render this as structured"
        echo "markdown; the JSON form below is a v0.9.x compatibility"
        echo "fallback."
        echo
        echo '```json'
        cat "$DUMP_JSON"
        echo '```'
    fi
fi
exit 0
