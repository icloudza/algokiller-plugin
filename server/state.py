"""Session-level state for the algokiller MCP server.

Holds the bound trace file, ak_search daemon handle, the analysis mode,
the per-session artifacts directory, and a monotonic tool-call counter
used by the discipline reinjection mechanism.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional


_HERE = Path(__file__).resolve()
PLUGIN_ROOT = Path(os.environ.get("ALGOKILLER_PLUGIN_ROOT") or _HERE.parent.parent).resolve()
# ak_search lives under server/bin/ (NOT plugin-root bin/) so the executable
# is NOT auto-injected into Claude's Bash tool PATH. All access must go
# through the MCP server's tools, which preserves daemon reuse and discipline
# reinjection. See README "Design rationale".
AK_SEARCH_BIN = PLUGIN_ROOT / "server" / "bin" / "ak_search"


class SessionState:
    def __init__(self) -> None:
        self.trace_file: Optional[Path] = None
        self.trace_basename: Optional[str] = None
        self.mode: str = "unknown"
        self.daemon = None
        self.tool_call_count: int = 0
        self.artifacts_dir: Optional[Path] = None
        self.artifacts_dir_source: Optional[str] = None  # 'explicit' / 'env' / 'project_config' / 'project_marker' / 'documents'
        self.artifacts_dir_reason: Optional[str] = None  # human-readable rationale for the chosen source
        self.artifacts_project_root: Optional[Path] = None  # project root if source ∈ {project_config, project_marker}
        self.ledger = None  # HypothesisLedger, initialised on bind()
        self.tool_log = None  # ToolCallLog, initialised on bind()

    def bind(self, trace_path: Path, mode: str, artifacts_dir: Path,
             source: str = "explicit",
             reason: Optional[str] = None,
             project_root: Optional[Path] = None) -> None:
        """Bind the session to a trace, with a pre-resolved artifacts_dir.

        The resolution happens upstream in `server.output_dir.resolve_output_dir`;
        this method just trusts the chosen path and stamps the surrounding
        per-session state (ledger, tool-call log, counters). `source` /
        `reason` / `project_root` are stored so the MCP wrapper can echo
        them back to the agent.
        """
        self.trace_file = trace_path
        self.trace_basename = trace_path.stem
        self.mode = mode
        # FIX A-2: reset tool_call_count on (re-)bind. Previously the counter
        # was monotonic across rebinds, so the new session's first tool call
        # would be #47 (carrying over from the prior session) and its
        # tool_call_log file would be 000047.json — leaving 1..46 missing on
        # disk. Ledger evidence-id range check (1..current) still passed but
        # tool_log.get() returned None and excerpt verification spuriously
        # failed. Documented as "fresh per-session"; this now actually
        # delivers it.
        self.tool_call_count = 0
        self.artifacts_dir = artifacts_dir
        self.artifacts_dir_source = source
        self.artifacts_dir_reason = reason
        self.artifacts_project_root = project_root
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        # Lazy import to avoid circular dependency with algokiller_mcp.
        # New per-session ledger + tool call log — never carries state across
        # bind() calls (FIX #6 temporal isolation: fresh per-session).
        from hypothesis import HypothesisLedger, ToolCallLog
        self.tool_log = ToolCallLog(self.artifacts_dir)
        self.ledger = HypothesisLedger(
            artifacts_dir=self.artifacts_dir,
            get_tool_call_count=lambda: self.tool_call_count,
            tool_call_log=self.tool_log,
        )

    def bump_tool_call(self) -> int:
        self.tool_call_count += 1
        return self.tool_call_count


STATE = SessionState()
