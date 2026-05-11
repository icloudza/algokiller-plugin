#!/usr/bin/env python3
"""algokiller MCP server — JSON-RPC 2.0 over stdio, zero external deps.

Speaks MCP 2024-11-05 directly (initialize / tools/list / tools/call / ping).
Designed to be launched by Claude Desktop's plugin runtime via .mcp.json.

The tool layer (schemas + handlers + dispatch table) lives in
`server/tools/`; this module is now a thin JSON-RPC plumbing layer plus
the discipline-injection and process-lifecycle hooks.
"""

from __future__ import annotations

import atexit
import json
import signal
import sys
import traceback
from pathlib import Path
from typing import Any

_HERE = Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

from state import STATE, AK_SEARCH_BIN, PLUGIN_ROOT  # noqa: E402
from discipline import build_reminder  # noqa: E402
from tools import TOOLS, HANDLERS  # noqa: E402
from tools.handlers import LEDGER_INTERNAL_TOOLS  # noqa: E402


PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "algokiller"
SERVER_VERSION = "0.8.1"


# ---------------------------------------------------------------------------
# JSON-RPC plumbing
# ---------------------------------------------------------------------------

def _send(msg: dict) -> None:
    sys.stdout.write(json.dumps(msg, ensure_ascii=False) + "\n")
    sys.stdout.flush()


def _log(msg: str) -> None:
    sys.stderr.write(f"[algokiller-mcp] {msg}\n")
    sys.stderr.flush()


def _attach_discipline(name: str, payload: dict, args: dict | None = None) -> dict:
    """Merge anti-drift reminders + persist the result into ToolCallLog
    so the Hypothesis Ledger's evidence-excerpt verification can later
    audit the citation."""
    # Skip discipline injection on protocol-level errors (no bound trace).
    if payload.get("status") == "error" and STATE.daemon is None and name != "bind_trace":
        return payload
    call_count = STATE.bump_tool_call()
    payload.update(build_reminder(mode=STATE.mode, call_count=call_count))
    payload["_tool_call_id"] = call_count
    # FIX #1 anchor: persist tool result for evidence-excerpt verification.
    # The ledger checks "did this excerpt actually appear in tool_call_id N's
    # output?" — we have to actually store the output for that to work.
    if STATE.tool_log is not None and name not in LEDGER_INTERNAL_TOOLS:
        try:
            STATE.tool_log.record(call_count, name, args or {}, payload)
        except Exception as exc:
            _log(f"tool_log.record failed for #{call_count} {name}: {exc}")
    if STATE.ledger is not None and call_count > 0 and call_count % 5 == 0:
        summary = STATE.ledger.summary_for_inject()
        if summary:
            payload["ledger_state"] = summary
    return payload


def handle_request(req: dict) -> dict | None:
    method = req.get("method")
    req_id = req.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        }
    if method == "notifications/initialized":
        return None  # notification, no response expected
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = req.get("params") or {}
        name = params.get("name")
        arguments = params.get("arguments") or {}
        handler = HANDLERS.get(name)
        if handler is None:
            # M3: don't return a JSON-RPC protocol error — return a normal tool
            # result with a strong self-correction instruction so the agent
            # doesn't stall on an unknown-tool reply.
            known = ", ".join(HANDLERS.keys())
            payload = {
                "status": "error",
                "error": f"Unknown tool: {name}",
                "instruction": (
                    "This tool does not exist and has been skipped. Do NOT stop, do NOT ask the user; "
                    f"retry using one of the available tools: {known}. "
                    "If you intended to search trace evidence, use trace_search / trace_context. "
                    "If you intended to deliver a final artifact, use write_artifact."
                ),
                "available_tools": list(HANDLERS.keys()),
            }
            payload = _attach_discipline(name, payload, arguments)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}]},
            }
        try:
            payload = handler(arguments)
        except Exception as exc:
            _log(f"tool '{name}' raised: {exc}\n{traceback.format_exc()}")
            payload = {
                "status": "error",
                "error": str(exc),
                "instruction": (
                    "Tool call failed and has been skipped. Do NOT stop, do NOT ask the user; "
                    "fix the arguments or switch to another tool and continue the previous task."
                ),
            }

        payload = _attach_discipline(name, payload, arguments)
        text = json.dumps(payload, ensure_ascii=False)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": text}]},
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": req_id, "result": {}}
    if method and method.startswith("notifications/"):
        return None  # ignore other notifications silently

    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": {"code": -32601, "message": f"Unknown method: {method}"},
    }


def _shutdown(_signum: int | None = None, _frame: Any = None) -> None:
    # P11: ensure the ak_search daemon is reaped on normal exit, SIGTERM, or
    # SIGINT. Without this the daemon can survive plugin reload and pile up.
    if STATE.daemon is not None:
        try:
            STATE.daemon.close()
        except Exception:
            pass
        STATE.daemon = None
    if _signum is not None:
        raise SystemExit(0)


def main() -> int:
    # P9: force line buffering so every JSON-RPC response leaves the process
    # immediately. Belt + suspenders with the `-u` flag and PYTHONUNBUFFERED=1
    # set in .mcp.json — if any of the three is honored we are safe.
    try:
        sys.stdout.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
        sys.stderr.reconfigure(line_buffering=True)  # type: ignore[attr-defined]
    except Exception:
        pass

    # P11: register cleanup hooks before serving any request.
    atexit.register(_shutdown)
    try:
        signal.signal(signal.SIGTERM, _shutdown)
        signal.signal(signal.SIGINT, _shutdown)
    except (ValueError, OSError):
        # Not in main thread, or running on a platform that disallows the
        # handler. Plugin still works, just without graceful signal cleanup.
        pass

    _log(f"starting (plugin_root={PLUGIN_ROOT}, binary={AK_SEARCH_BIN})")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            _log(f"invalid JSON-RPC line: {exc}")
            continue
        try:
            resp = handle_request(req)
        except Exception as exc:
            _log(f"handle_request crashed: {exc}\n{traceback.format_exc()}")
            resp = {
                "jsonrpc": "2.0",
                "id": req.get("id"),
                "error": {"code": -32000, "message": str(exc)},
            }
        if resp is not None:
            _send(resp)

    if STATE.daemon is not None:
        STATE.daemon.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
