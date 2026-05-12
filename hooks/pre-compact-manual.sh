#!/usr/bin/env bash
# PreCompact (matcher: manual) — user explicitly typed /compact.
#
# We DO NOT block manual compact even if a scan is in progress; the
# user typed the command deliberately and may be aware. We still dump
# the ledger state so the rehydration on SessionStart(compact) works.
set -u
PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
python3 "${PLUGIN_ROOT}/hooks/dump-session-state.py" || true
exit 0
