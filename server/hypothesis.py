"""Hypothesis Ledger — structured working memory for trace analysis.

Maintains an in-session list of active / concluded / abandoned hypotheses
with strong evidence binding. The point is NOT to make the agent smarter —
it is to force the agent's reasoning into a falsifiable, auditable shape
so that:

  1. Every claim in write_artifact is anchored to a concrete hypothesis_id.
  2. Every hypothesis is anchored to concrete tool_call_ids (server-side
     verified to actually have happened during this session).
  3. confidence=high requires a non-trivial bar (>=3 supporting + an
     actual falsification attempt), not just a verbal flourish.
  4. Hypothesis dependency is tracked; abandoning a hypothesis surfaces
     downstream hypotheses that depended on it.

This is the anti-hallucination scaffold. Without these constraints, a
hypothesis ledger would *make hallucinations more dangerous* (they would
appear with structured, scientific veneer). The constraints turn the
veneer back into something the server can actually verify.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


VALID_CONFIDENCE = ("unknown", "low", "medium", "high")
VALID_STATE = ("active", "concluded", "abandoned")


@dataclass
class Evidence:
    tool_call_id: int                # server-verified: must be in [1, current_tool_call_count]
    summary: str                     # short, human-readable
    line_range: Optional[list] = None  # [start, end] if applicable
    note: Optional[str] = None       # optional clarification


@dataclass
class Hypothesis:
    id: str                          # "H1", "H2", ...
    statement: str
    state: str                       # active | concluded | abandoned
    confidence: str                  # unknown | low | medium | high
    falsification_plan: str          # MUST be supplied at add()
    falsification_attempted: bool = False
    supporting: list = field(default_factory=list)      # list of Evidence dicts
    contradicting: list = field(default_factory=list)
    depends_on: list = field(default_factory=list)      # other hypothesis ids
    next_experiment: Optional[str] = None
    conclude_statement: Optional[str] = None
    abandon_reason: Optional[str] = None
    created_at_tool_call: int = 0
    created_at_iso: str = ""
    updated_at_iso: str = ""


class HypothesisLedger:
    """Per-session ledger. State is held in memory AND appended to a
    `hypothesis_ledger.jsonl` event log under the session artifacts dir
    for cross-session resume and post-mortem.
    """

    # confidence gates — must hold at conclude time
    GATE = {
        "low":    {"min_supporting": 0, "require_falsification_attempted": False},
        "medium": {"min_supporting": 2, "require_falsification_attempted": False},
        "high":   {"min_supporting": 3, "require_falsification_attempted": True},
    }

    def __init__(self, artifacts_dir: Path, get_tool_call_count) -> None:
        self.artifacts_dir = artifacts_dir
        self.log_path = artifacts_dir / "hypothesis_ledger.jsonl"
        self.get_tool_call_count = get_tool_call_count  # callable returning int
        self._by_id: dict[str, Hypothesis] = {}
        self._next_seq: int = 1

    def _now_iso(self) -> str:
        return datetime.now().isoformat(timespec="seconds")

    def _append_log(self, event: dict) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False) + "\n")
        except OSError:
            pass  # logging best-effort

    # ------------------------------------------------------------------ helpers

    def _validate_evidence(self, items, current_call: int) -> tuple[bool, str, list]:
        """Coerce + validate. Each item must contain tool_call_id (int in
        [1, current_call]) and a non-empty summary string. Returns
        (ok, error, normalised_list).
        """
        out: list[dict] = []
        if items is None:
            return True, "", out
        if not isinstance(items, list):
            return False, "evidence must be a list", out
        for i, item in enumerate(items):
            if not isinstance(item, dict):
                return False, f"evidence[{i}] must be an object", out
            tcid = item.get("tool_call_id")
            try:
                tcid_int = int(tcid)
            except (TypeError, ValueError):
                return False, f"evidence[{i}].tool_call_id must be integer", out
            if not (1 <= tcid_int <= current_call):
                return False, (
                    f"evidence[{i}].tool_call_id={tcid_int} is outside "
                    f"the actual tool-call history (1..{current_call}). "
                    "Cite only tool calls that really happened this session."
                ), out
            summary = str(item.get("summary", "")).strip()
            if not summary:
                return False, f"evidence[{i}].summary must not be empty", out
            ev = {"tool_call_id": tcid_int, "summary": summary[:400]}
            if "line_range" in item:
                lr = item["line_range"]
                if (isinstance(lr, (list, tuple)) and len(lr) == 2
                        and all(isinstance(x, int) for x in lr)):
                    ev["line_range"] = [int(lr[0]), int(lr[1])]
            if "note" in item and item["note"]:
                ev["note"] = str(item["note"])[:400]
            out.append(ev)
        return True, "", out

    def _check_dependencies(self, deps) -> tuple[bool, str]:
        if deps is None:
            return True, ""
        if not isinstance(deps, list):
            return False, "depends_on must be a list of hypothesis ids"
        for d in deps:
            if not isinstance(d, str) or d not in self._by_id:
                return False, f"depends_on references unknown hypothesis '{d}'"
        return True, ""

    # ------------------------------------------------------------------ ops

    def add(self, statement: str, confidence: str, falsification_plan: str,
            supporting=None, contradicting=None, depends_on=None,
            next_experiment: Optional[str] = None) -> dict:
        if not isinstance(statement, str) or len(statement.strip()) < 6:
            return {"status": "error", "error": "statement must be a non-trivial string (>=6 chars)"}
        if confidence not in VALID_CONFIDENCE:
            return {"status": "error", "error": f"confidence must be one of {VALID_CONFIDENCE}"}
        if not isinstance(falsification_plan, str) or len(falsification_plan.strip()) < 10:
            return {"status": "error", "error":
                    "falsification_plan must be a non-trivial string (>=10 chars). "
                    "Describe which concrete tool / result would refute this hypothesis. "
                    "Anti-hallucination scaffold requires this — every hypothesis must be "
                    "falsifiable before it can exist."}
        current = self.get_tool_call_count()
        ok, err, sup = self._validate_evidence(supporting, current)
        if not ok:
            return {"status": "error", "error": err}
        ok, err, contra = self._validate_evidence(contradicting, current)
        if not ok:
            return {"status": "error", "error": err}
        ok, err = self._check_dependencies(depends_on)
        if not ok:
            return {"status": "error", "error": err}

        hid = f"H{self._next_seq}"
        self._next_seq += 1
        h = Hypothesis(
            id=hid,
            statement=statement.strip(),
            state="active",
            confidence=confidence,
            falsification_plan=falsification_plan.strip(),
            supporting=sup,
            contradicting=contra,
            depends_on=list(depends_on) if depends_on else [],
            next_experiment=next_experiment.strip() if next_experiment else None,
            created_at_tool_call=current,
            created_at_iso=self._now_iso(),
            updated_at_iso=self._now_iso(),
        )
        self._by_id[hid] = h
        self._append_log({"event": "add", "iso": h.created_at_iso, **asdict(h)})
        return {"status": "ok", "hypothesis": asdict(h)}

    def update(self, hid: str, confidence: Optional[str] = None,
               add_supporting=None, add_contradicting=None,
               next_experiment: Optional[str] = None,
               falsification_attempted: Optional[bool] = None) -> dict:
        h = self._by_id.get(hid)
        if h is None:
            return {"status": "error", "error": f"unknown hypothesis '{hid}'"}
        if h.state != "active":
            return {"status": "error",
                    "error": f"hypothesis {hid} is {h.state} (not active) — cannot update"}
        if confidence is not None and confidence not in VALID_CONFIDENCE:
            return {"status": "error", "error": f"confidence must be one of {VALID_CONFIDENCE}"}
        current = self.get_tool_call_count()
        if add_supporting is not None:
            ok, err, sup = self._validate_evidence(add_supporting, current)
            if not ok:
                return {"status": "error", "error": err}
            h.supporting.extend(sup)
        if add_contradicting is not None:
            ok, err, contra = self._validate_evidence(add_contradicting, current)
            if not ok:
                return {"status": "error", "error": err}
            h.contradicting.extend(contra)
        if confidence is not None:
            h.confidence = confidence
        if next_experiment is not None:
            h.next_experiment = next_experiment.strip() or None
        if falsification_attempted is not None:
            h.falsification_attempted = bool(falsification_attempted)
        h.updated_at_iso = self._now_iso()
        self._append_log({"event": "update", "iso": h.updated_at_iso, **asdict(h)})
        return {"status": "ok", "hypothesis": asdict(h)}

    def conclude(self, hid: str, final_statement: str, final_confidence: str) -> dict:
        h = self._by_id.get(hid)
        if h is None:
            return {"status": "error", "error": f"unknown hypothesis '{hid}'"}
        if h.state != "active":
            return {"status": "error",
                    "error": f"hypothesis {hid} is already {h.state}; cannot re-conclude"}
        if final_confidence not in ("low", "medium", "high"):
            return {"status": "error", "error":
                    "final_confidence must be one of low / medium / high"}
        gate = self.GATE[final_confidence]
        if len(h.supporting) < gate["min_supporting"]:
            return {"status": "error", "error": (
                f"conclude(confidence={final_confidence}) requires >= "
                f"{gate['min_supporting']} supporting evidence; current has "
                f"{len(h.supporting)}. Collect more evidence via update() "
                "or conclude at a lower confidence.")}
        if gate["require_falsification_attempted"] and not h.falsification_attempted:
            return {"status": "error", "error": (
                "conclude(confidence=high) requires falsification_attempted=true. "
                "Run the experiment from falsification_plan first, then "
                "update(falsification_attempted=True) before concluding high.")}
        if not isinstance(final_statement, str) or len(final_statement.strip()) < 6:
            return {"status": "error", "error":
                    "final_statement must be a non-trivial string (>=6 chars)"}
        h.state = "concluded"
        h.confidence = final_confidence
        h.conclude_statement = final_statement.strip()
        h.updated_at_iso = self._now_iso()
        self._append_log({"event": "conclude", "iso": h.updated_at_iso, **asdict(h)})
        return {"status": "ok", "hypothesis": asdict(h)}

    def abandon(self, hid: str, reason: str) -> dict:
        h = self._by_id.get(hid)
        if h is None:
            return {"status": "error", "error": f"unknown hypothesis '{hid}'"}
        if h.state != "active":
            return {"status": "error",
                    "error": f"hypothesis {hid} is already {h.state}"}
        if not isinstance(reason, str) or len(reason.strip()) < 6:
            return {"status": "error", "error":
                    "abandon reason must be a non-trivial string (>=6 chars)"}
        h.state = "abandoned"
        h.abandon_reason = reason.strip()
        h.updated_at_iso = self._now_iso()
        self._append_log({"event": "abandon", "iso": h.updated_at_iso, **asdict(h)})
        # Surface dependents
        affected = [other.id for other in self._by_id.values()
                    if hid in other.depends_on and other.state == "active"]
        return {"status": "ok", "hypothesis": asdict(h),
                "downstream_active_hypotheses": affected,
                "warning": (f"downstream active hypotheses {affected} depend on {hid}; "
                            "re-evaluate them") if affected else None}

    def list(self, state: Optional[str] = None, with_evidence: bool = False) -> dict:
        items = []
        for h in self._by_id.values():
            if state and h.state != state:
                continue
            d = asdict(h)
            if not with_evidence:
                d.pop("supporting", None)
                d.pop("contradicting", None)
            items.append(d)
        return {"status": "ok", "count": len(items), "hypotheses": items,
                "tool_call_count_now": self.get_tool_call_count()}

    def get(self, hid: str) -> Optional[Hypothesis]:
        return self._by_id.get(hid)

    def summary_for_inject(self) -> str:
        """Tight one-liner per active hypothesis, used by the periodic
        reinjection mechanism. Hidden cost: token budget — keep terse."""
        active = [h for h in self._by_id.values() if h.state == "active"]
        if not active:
            return ""
        lines = [f"[ledger] {len(active)} active hypothes(e)s:"]
        for h in active:
            n_sup = len(h.supporting)
            n_con = len(h.contradicting)
            falsify_tag = "✓falsify-tried" if h.falsification_attempted else "✗falsify-pending"
            lines.append(f"  {h.id} [{h.confidence}] {h.statement[:80]} "
                         f"(sup={n_sup} contra={n_con} {falsify_tag})")
        return "\n".join(lines)

    def validate_artifact_references(self, content: str) -> dict:
        """Scan content for H<id> references and check each one resolves
        to a concluded hypothesis with confidence >= medium and with
        truly recorded evidence (anti-hallucination final guard).

        Returns:
          {"ok": bool, "errors": [...], "referenced_ids": [...]}
        """
        import re
        ids = sorted(set(re.findall(r"\bH(\d+)\b", content or "")))
        errors: list[str] = []
        referenced = []
        for n in ids:
            hid = f"H{n}"
            referenced.append(hid)
            h = self._by_id.get(hid)
            if h is None:
                errors.append(f"{hid} referenced but not in ledger")
                continue
            if h.state != "concluded":
                errors.append(f"{hid} is '{h.state}', not 'concluded' — "
                              "cannot cite as evidence in deliverable")
                continue
            if h.confidence not in ("medium", "high"):
                errors.append(f"{hid} confidence='{h.confidence}', need >=medium")
                continue
            if not h.supporting:
                errors.append(f"{hid} has empty supporting evidence list")
                continue
        return {"ok": not errors, "errors": errors, "referenced_ids": referenced}
