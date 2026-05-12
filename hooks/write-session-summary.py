#!/usr/bin/env python3
"""Stop hook helper: persist a human-readable ``session-summary.md`` to
the most recent algokiller session directory.

Goal: when the user comes back to a session dir hours / days later,
``session-summary.md`` is the file they open first. It surfaces the
hypothesis ledger's final state and the artifact tree in one place.

We re-use the session-finder from ``dump-session-state.py``; if no
session can be located (user never bound a trace), we exit silently.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime
from pathlib import Path


HOOK_DIR = Path(__file__).resolve().parent


def _load_helper():
    """Re-use ``dump-session-state.py``'s session locator + ledger
    reader without re-implementing them. The hyphenated filename
    blocks normal import so we exec the file into a namespace."""
    helper = HOOK_DIR / "dump-session-state.py"
    if not helper.is_file():
        return None
    ns: dict = {}
    try:
        exec(helper.read_text(encoding="utf-8"), ns)  # noqa: S102
    except Exception:
        return None
    return ns


def _format_hypotheses(ledger: dict) -> str:
    lines: list[str] = []
    concluded = []
    active = []
    abandoned = []
    for h in (ledger.get("hypotheses") or []):
        state = h.get("state")
        if state == "concluded":
            concluded.append(h)
        elif state == "active":
            active.append(h)
        elif state in ("abandoned", "archived"):
            abandoned.append(h)
    if concluded:
        lines.append("### Concluded hypotheses\n")
        for h in concluded:
            hid = h.get("id", "?")
            conf = h.get("final_confidence") or h.get("confidence") or "?"
            statement = h.get("final_statement") or h.get("statement") or ""
            lines.append(f"- **[{hid}]** ({conf}) — {statement}")
        lines.append("")
    if active:
        lines.append("### Active hypotheses (open threads)\n")
        for h in active:
            hid = h.get("id", "?")
            conf = h.get("confidence", "?")
            statement = h.get("statement", "")
            lines.append(f"- **[{hid}]** ({conf}) — {statement}")
        lines.append("")
    if abandoned:
        lines.append("### Abandoned / archived\n")
        for h in abandoned:
            hid = h.get("id", "?")
            reason = h.get("abandon_reason") or h.get("archive_reason") or ""
            statement = h.get("statement", "")
            lines.append(f"- ~~[{hid}]~~ {statement} ({reason})")
        lines.append("")
    return "\n".join(lines) or "_No hypotheses recorded this session._\n"


def _format_artifacts(session_dir: Path) -> str:
    files = []
    for p in sorted(session_dir.glob("*"), key=lambda x: x.stat().st_mtime):
        if not p.is_file():
            continue
        if p.name in {"ledger.json", "_compact_state.json", "session-summary.md"}:
            continue
        if p.name.startswith("."):
            continue
        size = p.stat().st_size
        files.append(f"- `{p.name}` ({size:,} bytes)")
    return "\n".join(files) or "_No artifacts written._"


def main() -> int:
    sys.path.insert(0, str(HOOK_DIR))
    helper = _load_helper()
    if helper is None:
        return 0
    finder = helper.get("_find_latest_session")
    reader = helper.get("_read_ledger")
    if not (callable(finder) and callable(reader)):
        return 0
    try:
        session_dir = finder()
    except Exception:
        return 0
    if session_dir is None:
        return 0

    try:
        ledger = reader(session_dir)
    except Exception:
        ledger = {}

    summary = [
        "# Session summary",
        "",
        f"_Generated at {datetime.now().isoformat(timespec='seconds')} by"
        f" algokiller Stop hook_",
        "",
        f"- Session directory: `{session_dir}`",
        f"- Trace basename: `{session_dir.parent.name}`",
        "",
        "## Hypothesis ledger",
        "",
        _format_hypotheses(ledger),
        "",
        "## Artifacts written",
        "",
        _format_artifacts(session_dir),
        "",
    ]
    try:
        out = Path(session_dir) / "session-summary.md"
        out.write_text("\n".join(summary), encoding="utf-8")
    except OSError as exc:
        print(f"# algokiller write-session-summary: write failed ({exc})",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
