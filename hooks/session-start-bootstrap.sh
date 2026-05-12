#!/usr/bin/env bash
# SessionStart bootstrap (matchers: startup | resume):
# - auto-install pyright if missing (drives .lsp.json type-checking)
# - emit environment diagnostics once per session
# Never blocks session start.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 "${PLUGIN_ROOT}/hooks/session-start-bootstrap.py" || true
exit 0
