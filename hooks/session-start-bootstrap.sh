#!/usr/bin/env bash
# SessionStart bootstrap (matchers: startup | resume):
#
# Two responsibilities on every fresh / resumed session:
#
# 1. Stream context/critical-rules.md to stdout. Claude Desktop treats
#    SessionStart hook stdout as additional system context — this is
#    the plugin's equivalent of `--append-system-prompt`. It guarantees
#    the anti-hallucination hard rules (SIMD ≠ AES Tbox, ARC bookkeeping
#    ≠ algo input, `block_count_estimate` is the block count not /4 or
#    /16, etc.) are loaded every time, regardless of whether the agent
#    later triggers any specific SKILL.md.
#
# 2. Diagnostics / pyright install (stderr only, doesn't enter context).
#
# Never blocks session start.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

# 1. Critical rules — single source of truth for anti-hallucination
# discipline. Output to stdout so Claude Desktop injects it as system
# context. Stays under 200 lines / 8 KB so the budget impact is bounded.
RULES_FILE="${PLUGIN_ROOT}/context/critical-rules.md"
if [ -f "$RULES_FILE" ]; then
    cat "$RULES_FILE"
    echo
fi

# 2. Environment diagnostics + pyright auto-install. stderr only.
python3 "${PLUGIN_ROOT}/hooks/session-start-bootstrap.py" || true
exit 0
