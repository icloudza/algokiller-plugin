#!/usr/bin/env bash
# PreToolUse hook on write_artifact: warn when the draft cites fewer
# [H<n>] hypotheses than the ledger has concluded ones. Soft signal
# only; the actual gate is server-side.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 "${PLUGIN_ROOT}/hooks/pre-write-artifact.py" || true
exit 0
