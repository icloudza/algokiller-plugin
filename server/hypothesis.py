"""Hypothesis Ledger v2 — anti-hallucination scaffold for trace analysis.

v0.8.0 introduced the ledger with falsification + conclude gates + artifact
reference guard. External review surfaced 4 critical gaps; this revision
closes them:

  Fix #1  Evidence excerpt verification — every evidence item MUST cite an
          excerpt string that the server can locate inside the actual
          stored tool result (via ToolCallLog). Stops "I have evidence" with
          fabricated summaries.
  Fix #2  Contradiction pressure — conclude gates now look at
          supporting:contradicting ratio. High requires support >= 2×
          contradict; medium requires support >= contradict+1; any time
          contradict > support, confidence is hard-capped at low.
  Fix #3  Source diversity — high confidence requires supporting evidence
          from at least 2 distinct tool_name buckets (e.g. cannot conclude
          high with 3 constscan hits alone). tool_name is derived
          server-side from ToolCallLog, not user-supplied.
  Fix #4  Conflict graph — hypotheses can declare conflicts_with, and
          conclude rejects if a conflicting hypothesis is already
          concluded with confidence >= medium.

Out of scope for this revision (intentional):
  - Bayesian / numeric belief scores: AI doesn't actually compute
    P(H|E), forcing numbers invites fake precision. Discrete
    confidence + contradiction pressure already covers 80%.
  - Cross-session trace epoch: ledger is per-bind_trace, fresh state
    each session — no contamination risk in current usage.
  - Independent Decision Ledger: the next_experiment + reason fields
    on hypotheses approximate decision tracking adequately.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


VALID_CONFIDENCE = ("unknown", "low", "medium", "high")
VALID_STATE = ("active", "concluded", "abandoned")


# ---------------------------------------------------------------------------
# Tool Call Log — server-side immutable record of every MCP tool result, so
# Evidence can be verified to come from a real call (not just a real id).
# ---------------------------------------------------------------------------

class ToolCallLog:
    """Records (id, tool_name, args, result_text, result_sha256) per tool
    invocation. Used by HypothesisLedger to:
      - verify Evidence.excerpt is a real substring of the cited tool's output
      - derive Evidence.tool_name server-side (not user-claimed)
      - support cross-session post-mortem via on-disk records
    """

    def __init__(self, artifacts_dir: Path) -> None:
        self.dir = artifacts_dir / "tool_call_log"
        self._mem: dict[int, dict] = {}

    def record(self, call_id: int, tool_name: str, args: dict, result: dict) -> None:
        """Persist + cache a tool call. result is the full JSON-able payload."""
        # Serialise compactly for hashing + grep
        result_text = json.dumps(result, ensure_ascii=False, default=str)
        sha = hashlib.sha256(result_text.encode("utf-8", "replace")).hexdigest()
        record = {
            "id": call_id,
            "tool_name": tool_name,
            "args": args,
            "result_text": result_text,
            "result_sha256": sha,
        }
        self._mem[call_id] = record
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            with (self.dir / f"{call_id:06d}.json").open("w", encoding="utf-8") as f:
                json.dump(record, f, ensure_ascii=False, indent=2, default=str)
        except OSError:
            pass  # best-effort persistence

    def get(self, call_id: int) -> Optional[dict]:
        if call_id in self._mem:
            return self._mem[call_id]
        # try disk
        path = self.dir / f"{call_id:06d}.json"
        if path.exists():
            try:
                with path.open("r", encoding="utf-8") as f:
                    rec = json.load(f)
                self._mem[call_id] = rec
                return rec
            except Exception:
                return None
        return None

    def excerpt_in_result(self, call_id: int, excerpt: str) -> bool:
        rec = self.get(call_id)
        if rec is None:
            return False
        return excerpt in rec["result_text"]

    def tool_name(self, call_id: int) -> Optional[str]:
        rec = self.get(call_id)
        return rec["tool_name"] if rec else None


# ---------------------------------------------------------------------------
# Hypothesis dataclasses
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    tool_call_id: int                # server-verified: in [1, tool_call_count]
    excerpt: str                     # server-verified: must be substring of stored tool result
    tool_name: str = ""              # server-derived from tool_call_log (ignore user input)
    summary: str = ""                # optional, human commentary only
    line_range: Optional[list] = None
    note: Optional[str] = None


@dataclass
class Hypothesis:
    id: str                          # "H1", "H2", ...
    statement: str
    state: str                       # active | concluded | abandoned
    confidence: str                  # unknown | low | medium | high
    falsification_plan: str
    falsification_attempted: bool = False
    supporting: list = field(default_factory=list)
    contradicting: list = field(default_factory=list)
    depends_on: list = field(default_factory=list)
    conflicts_with: list = field(default_factory=list)   # FIX #4
    next_experiment: Optional[str] = None
    reason_for_experiment: Optional[str] = None
    conclude_statement: Optional[str] = None
    abandon_reason: Optional[str] = None
    created_at_tool_call: int = 0
    created_at_iso: str = ""
    updated_at_iso: str = ""


# ---------------------------------------------------------------------------
# HypothesisLedger
# ---------------------------------------------------------------------------

class HypothesisLedger:

    def __init__(self, artifacts_dir: Path, get_tool_call_count,
                 tool_call_log: Optional[ToolCallLog] = None) -> None:
        self.artifacts_dir = artifacts_dir
        self.log_path = artifacts_dir / "hypothesis_ledger.jsonl"
        self.get_tool_call_count = get_tool_call_count
        self.tool_log = tool_call_log if tool_call_log is not None else ToolCallLog(artifacts_dir)
        self._by_id: dict[str, Hypothesis] = {}
        self._next_seq: int = 1

    # ---------------------- helpers ----------------------

    def _now_iso(self) -> str:
        return datetime.now().isoformat(timespec="seconds")

    def _append_log(self, event: dict) -> None:
        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(event, ensure_ascii=False, default=str) + "\n")
        except OSError:
            pass

    def _validate_evidence(self, items, current_call: int) -> tuple[bool, str, list]:
        """FIX #1: every evidence MUST cite a tool_call_id + excerpt that
        the server can verify against ToolCallLog. tool_name is derived
        server-side, not user-supplied (FIX #3 anchor).
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
                    f"evidence[{i}].tool_call_id={tcid_int} is outside the actual "
                    f"tool-call history (1..{current_call}). Cite only tool calls "
                    "that really happened this session."), out

            excerpt = str(item.get("excerpt", "")).strip()
            if not excerpt:
                return False, (
                    f"evidence[{i}].excerpt is required: a verbatim substring "
                    "(min 8 chars) of the cited tool's output. summary is for "
                    "human-readable commentary only and cannot replace excerpt."), out
            if len(excerpt) < 8:
                return False, (
                    f"evidence[{i}].excerpt too short ({len(excerpt)} chars). "
                    "Need >=8 chars of verbatim output substring to make the "
                    "citation auditable (a typical mnemonic, function name, or "
                    "JSON key/value fragment)."), out
            if not self.tool_log.excerpt_in_result(tcid_int, excerpt):
                # Show a short prefix of the actual result so the agent can self-correct
                rec = self.tool_log.get(tcid_int)
                preview = (rec["result_text"][:200] if rec else "<no record>")
                return False, (
                    f"evidence[{i}].excerpt NOT found in tool_call_id={tcid_int} "
                    f"output. This is the anti-hallucination check — quote the "
                    f"output verbatim, do not paraphrase. Tool output preview: "
                    f"{preview!r}"), out

            ev = {
                "tool_call_id": tcid_int,
                "excerpt": excerpt[:600],
                "tool_name": self.tool_log.tool_name(tcid_int) or "unknown",
                "summary": str(item.get("summary", "")).strip()[:400],
            }
            if "line_range" in item:
                lr = item["line_range"]
                if (isinstance(lr, (list, tuple)) and len(lr) == 2
                        and all(isinstance(x, int) for x in lr)):
                    ev["line_range"] = [int(lr[0]), int(lr[1])]
            if "note" in item and item["note"]:
                ev["note"] = str(item["note"])[:400]
            out.append(ev)
        return True, "", out

    def _check_id_list(self, ids, field_name: str) -> tuple[bool, str]:
        if ids is None:
            return True, ""
        if not isinstance(ids, list):
            return False, f"{field_name} must be a list of hypothesis ids"
        for d in ids:
            if not isinstance(d, str) or d not in self._by_id:
                return False, f"{field_name} references unknown hypothesis '{d}'"
        return True, ""

    # ---------------------- core gate logic ----------------------

    def _effective_max_confidence(self, h: Hypothesis) -> str:
        """FIX #2: contradiction pressure hard cap. If contradicting outweighs
        supporting, no matter how many supporting you stack, max is 'low'.
        """
        n_sup = len(h.supporting)
        n_con = len(h.contradicting)
        if n_con > n_sup:
            return "low"
        return "high"  # caller still applies fine-grained min_supporting

    def _supporting_tool_diversity(self, h: Hypothesis) -> int:
        """FIX #3: count distinct tool_names across supporting evidence."""
        names = {ev.get("tool_name", "") for ev in h.supporting}
        names.discard("")
        names.discard("unknown")
        return len(names)

    def _can_conclude(self, h: Hypothesis, target_confidence: str) -> tuple[bool, str]:
        if target_confidence not in ("low", "medium", "high"):
            return False, "final_confidence must be low / medium / high"

        n_sup = len(h.supporting)
        n_con = len(h.contradicting)
        cap = self._effective_max_confidence(h)
        if target_confidence != "low":
            order = {"low": 0, "medium": 1, "high": 2}
            if order[target_confidence] > order[cap]:
                return False, (
                    f"contradicting={n_con} > supporting={n_sup}: confidence "
                    f"hard-capped at 'low' (FIX #2 contradiction pressure). "
                    "Either gather more supporting or resolve the contradicting items.")

        if target_confidence == "high":
            if n_sup < 3:
                return False, (f"conclude(high) needs >=3 supporting; current={n_sup}")
            if n_sup < n_con * 2:
                return False, (
                    f"conclude(high) requires supporting >= 2 × contradicting; "
                    f"have supporting={n_sup}, contradicting={n_con}. "
                    "Either gather more supporting (need >= {target}) or address "
                    "contradictions explicitly.".format(target=n_con * 2))
            if not h.falsification_attempted:
                return False, (
                    "conclude(high) requires falsification_attempted=true. Run "
                    "your falsification_plan first then update(falsification_attempted=True).")
            diversity = self._supporting_tool_diversity(h)
            if diversity < 2:
                return False, (
                    f"conclude(high) requires supporting evidence from >=2 distinct "
                    f"tool sources (FIX #3 source diversity); currently from "
                    f"{diversity} distinct tool(s). 3 hits from the same tool is "
                    "correlated evidence, not independent.")

        elif target_confidence == "medium":
            if n_sup < 2:
                return False, (f"conclude(medium) needs >=2 supporting; current={n_sup}")
            if n_sup < n_con + 1:
                return False, (
                    f"conclude(medium) requires supporting > contradicting; "
                    f"have supporting={n_sup}, contradicting={n_con}.")

        return True, ""

    def _check_conflicts_for_conclude(self, h: Hypothesis,
                                      target_confidence: str) -> tuple[bool, str]:
        """FIX #4: if any conflicts_with id is itself concluded with
        confidence >= medium, this conclude must be blocked.
        """
        if not h.conflicts_with or target_confidence == "low":
            return True, ""
        order = {"low": 0, "medium": 1, "high": 2}
        for cid in h.conflicts_with:
            other = self._by_id.get(cid)
            if other is None:
                continue
            if other.state == "concluded" and order.get(other.confidence, 0) >= 1:
                return False, (
                    f"FIX #4 conflict: {cid} is already concluded with "
                    f"confidence={other.confidence}; {h.id} declares conflicts_with={cid}. "
                    f"Either abandon {cid} first (if {h.id} is the better explanation), "
                    f"or conclude {h.id} at 'low' (compatible) confidence.")
        return True, ""

    # ---------------------- ops ----------------------

    def add(self, statement: str, confidence: str, falsification_plan: str,
            supporting=None, contradicting=None, depends_on=None,
            conflicts_with=None, next_experiment: Optional[str] = None,
            reason_for_experiment: Optional[str] = None) -> dict:
        if not isinstance(statement, str) or len(statement.strip()) < 6:
            return {"status": "error", "error": "statement must be a non-trivial string (>=6 chars)"}
        if confidence not in VALID_CONFIDENCE:
            return {"status": "error", "error": f"confidence must be one of {VALID_CONFIDENCE}"}
        if not isinstance(falsification_plan, str) or len(falsification_plan.strip()) < 10:
            return {"status": "error", "error":
                    "falsification_plan must be a non-trivial string (>=10 chars) "
                    "describing a concrete tool + result that would refute this hypothesis."}
        current = self.get_tool_call_count()
        ok, err, sup = self._validate_evidence(supporting, current)
        if not ok:
            return {"status": "error", "error": err}
        ok, err, contra = self._validate_evidence(contradicting, current)
        if not ok:
            return {"status": "error", "error": err}
        ok, err = self._check_id_list(depends_on, "depends_on")
        if not ok:
            return {"status": "error", "error": err}
        ok, err = self._check_id_list(conflicts_with, "conflicts_with")
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
            conflicts_with=list(conflicts_with) if conflicts_with else [],
            next_experiment=next_experiment.strip() if next_experiment else None,
            reason_for_experiment=(reason_for_experiment.strip()
                                   if reason_for_experiment else None),
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
               reason_for_experiment: Optional[str] = None,
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
        if reason_for_experiment is not None:
            h.reason_for_experiment = reason_for_experiment.strip() or None
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
        if not isinstance(final_statement, str) or len(final_statement.strip()) < 6:
            return {"status": "error", "error":
                    "final_statement must be a non-trivial string (>=6 chars)"}

        ok, err = self._can_conclude(h, final_confidence)
        if not ok:
            return {"status": "error", "error": err}

        ok, err = self._check_conflicts_for_conclude(h, final_confidence)
        if not ok:
            return {"status": "error", "error": err}

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
        active = [h for h in self._by_id.values() if h.state == "active"]
        if not active:
            return ""
        lines = [f"[ledger] {len(active)} active hypothes(e)s:"]
        for h in active:
            n_sup = len(h.supporting)
            n_con = len(h.contradicting)
            diversity = self._supporting_tool_diversity(h)
            falsify_tag = "✓falsify-tried" if h.falsification_attempted else "✗falsify-pending"
            ratio_tag = "" if n_sup >= n_con else " ⚠CONTRA-DOMINANT"
            div_tag = f" sources={diversity}" if h.supporting else ""
            lines.append(f"  {h.id} [{h.confidence}] {h.statement[:80]} "
                         f"(sup={n_sup} contra={n_con}{div_tag} "
                         f"{falsify_tag}{ratio_tag})")
        return "\n".join(lines)

    def validate_artifact_references(self, content: str) -> dict:
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
