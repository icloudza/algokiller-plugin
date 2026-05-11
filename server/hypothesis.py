"""Hypothesis Ledger v3 — anti-hallucination scaffold for trace analysis.

v0.8.0 introduced the ledger with falsification + conclude gates + artifact
reference guard. v0.8.1 closed four review-surfaced gaps (FIX #1-#4).
v0.9.1 closes the next layer:

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
  Fix #5  Falsification evidence (v0.9.1) — conclude(high) now requires a
          verifiable falsification_evidence item ({tool_call_id, excerpt})
          whose tool_call_id is GREATER than the hypothesis's
          created_at_tool_call (experiment must run after hypothesis was
          formed). Replaces the v0.8.x boolean self-report which could be
          set without ever running the experiment. excerpt is verbatim-
          checked through the same FIX#1 anchor.
  Fix #6  Reviewer gate (v0.9.1) — conclude(high) requires the
          hypothesis-reviewer sub-agent to have called
          mark_hypothesis_reviewed(verdict="confirm") within the last 30
          tool calls. Closes the sunk-cost-bias hole that server-side
          gates cannot detect: an agent that worked on H<N> for 20 calls
          will pick the *minimally sufficient* evidence to clear the
          gates. An independent context with no sunk cost stays objective.
  Fix #7  Archive state (v0.9.1) — concluded hypotheses that turn out NOT
          to be load-bearing for the final deliverable can be archived
          (state=archived), exempting them from the validate_artifact_
          references "concluded but unreferenced → bypass" gate. Removes
          the reverse-prompt-injection failure mode where agents were
          forced to either cite irrelevant H<id>s or abandon (impossible
          on concluded state).

Out of scope for this revision (intentional):
  - Bayesian / numeric belief scores: AI doesn't actually compute
    P(H|E), forcing numbers invites fake precision. Discrete
    confidence + contradiction pressure already covers 80%.
  - Evidence weighting / Independence anchor model / Confidence decay:
    deferred to v0.9.5+; building those on top of tools with structural
    biases (see CHANGELOG v0.9.1 deferred items) amplifies error.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Optional


VALID_CONFIDENCE = ("unknown", "low", "medium", "high")
# FIX #7 (v0.9.1): "archived" is concluded-but-deliberately-deprioritised so
# the artifact-reference gate doesn't force agents to cite hypotheses that
# turned out non-load-bearing. Cannot transition from abandoned.
VALID_STATE = ("active", "concluded", "abandoned", "archived")
# FIX #6 (v0.9.1): reviewer verdict alphabet shared with the sub-agent.
VALID_REVIEWER_VERDICT = ("confirm", "refute", "abandon")
# FIX #6 staleness window: a reviewer verdict older than this many tool
# calls back from the conclude attempt no longer satisfies the gate.
REVIEWER_STALENESS_LIMIT = 30


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
        if excerpt in rec["result_text"]:
            return True
        # The agent sees tool stdout in its un-escaped form (Claude unwraps
        # the JSON-RPC content[0].text once); result_text is the JSON-dumped
        # payload where `"` became `\"`, `\n` became `\\n`, etc. If the
        # agent copies a verbatim substring containing those characters,
        # `excerpt in result_text` will fail spuriously. Re-encode the
        # excerpt the same way the result was serialised and try again —
        # fabricated strings still fail both checks, real ones now pass.
        escaped = json.dumps(excerpt, ensure_ascii=False)[1:-1]
        return escaped in rec["result_text"]

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
    state: str                       # active | concluded | abandoned | archived
    confidence: str                  # unknown | low | medium | high
    falsification_plan: str
    falsification_attempted: bool = False     # deprecated: derived from falsification_evidence (v0.9.1)
    falsification_evidence: Optional[dict] = None  # FIX #5: verifiable replacement for the boolean
    supporting: list = field(default_factory=list)
    contradicting: list = field(default_factory=list)
    depends_on: list = field(default_factory=list)
    conflicts_with: list = field(default_factory=list)   # FIX #4
    # FIX #6: independent-reviewer gate
    reviewed_at_tool_call: int = 0
    reviewer_verdict: Optional[str] = None
    reviewer_reason: Optional[str] = None
    next_experiment: Optional[str] = None
    reason_for_experiment: Optional[str] = None
    conclude_statement: Optional[str] = None
    abandon_reason: Optional[str] = None
    archive_reason: Optional[str] = None     # FIX #7
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
            # Gate order = cheapest-first → most-expensive last. Diversity
            # and contradiction are both count-only and run before the
            # FIX#5 / FIX#6 lookups so the agent sees the most fundamental
            # problem with its evidence pile first (otherwise it would chase
            # the falsification-evidence message back through ledger updates
            # only to hit a diversity wall on the retry).
            if n_sup < 3:
                return False, (f"conclude(high) needs >=3 supporting; current={n_sup}")
            if n_sup < n_con * 2:
                return False, (
                    f"conclude(high) requires supporting >= 2 × contradicting; "
                    f"have supporting={n_sup}, contradicting={n_con}. "
                    "Either gather more supporting (need >= {target}) or address "
                    "contradictions explicitly.".format(target=n_con * 2))
            diversity = self._supporting_tool_diversity(h)
            if diversity < 2:
                return False, (
                    f"conclude(high) requires supporting evidence from >=2 distinct "
                    f"tool sources (FIX #3 source diversity); currently from "
                    f"{diversity} distinct tool(s). 3 hits from the same tool is "
                    "correlated evidence, not independent.")
            # FIX #5: verifiable falsification evidence replaces the boolean
            # self-report. The boolean was bypassable — agents could pass the
            # gate without ever running the experiment.
            if h.falsification_evidence is None:
                return False, (
                    "conclude(high) requires falsification_evidence — a single "
                    "{tool_call_id, excerpt} pair from running the falsification_plan "
                    "experiment (FIX #5). Setting falsification_attempted=True alone "
                    "no longer satisfies the gate. Call "
                    "hypothesis_update(id, falsification_evidence={tool_call_id, excerpt}) "
                    "with the actual tool call that performed the refutation attempt.")
            # FIX #6: independent reviewer gate. Closes the sunk-cost bias
            # hole that server-side counting cannot see.
            if h.reviewer_verdict != "confirm":
                return False, (
                    f"conclude(high) requires an independent hypothesis-reviewer "
                    f"verdict of 'confirm' (current: {h.reviewer_verdict or 'none'}). "
                    f"Spawn the reviewer via "
                    f"Agent(subagent_type='hypothesis-reviewer', "
                    f"prompt='Review {h.id}'); the reviewer will call "
                    f"mark_hypothesis_reviewed once it has audited the evidence "
                    f"(FIX #6).")
            current_call_now = self.get_tool_call_count()
            staleness = current_call_now - h.reviewed_at_tool_call
            if h.reviewed_at_tool_call > 0 and staleness > REVIEWER_STALENESS_LIMIT:
                return False, (
                    f"hypothesis-reviewer verdict is stale (reviewed at call "
                    f"{h.reviewed_at_tool_call}, currently at call {current_call_now} — "
                    f"{staleness} > {REVIEWER_STALENESS_LIMIT} call window). "
                    f"Spawn a fresh reviewer before concluding (evidence may have "
                    f"shifted since the review).")

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
               falsification_attempted: Optional[bool] = None,
               falsification_evidence: Optional[dict] = None) -> dict:
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
        # FIX #5: falsification_evidence — a single verifiable Evidence-form
        # entry. Validates through the same FIX#1 verbatim check as supporting
        # evidence, plus a temporal constraint (experiment must run AFTER the
        # hypothesis was formed; otherwise it's pre-existing data being
        # repackaged as deliberate refutation).
        if falsification_evidence is not None:
            ok, err, items = self._validate_evidence([falsification_evidence], current)
            if not ok:
                return {"status": "error",
                        "error": f"falsification_evidence: {err}"}
            ev = items[0]
            if ev["tool_call_id"] <= h.created_at_tool_call:
                return {"status": "error", "error": (
                    f"falsification_evidence.tool_call_id={ev['tool_call_id']} must be "
                    f"GREATER than hypothesis created_at_tool_call={h.created_at_tool_call}. "
                    "The falsification experiment must run AFTER the hypothesis is created — "
                    "otherwise the evidence is pre-existing observation, not a deliberate "
                    "refutation attempt (FIX #5).")}
            h.falsification_evidence = ev
            h.falsification_attempted = True
        elif falsification_attempted is not None:
            # Backward-compat: the boolean still flips, but conclude(high)
            # now reads falsification_evidence — setting only the boolean
            # no longer satisfies the gate. Emit a hint in the response.
            h.falsification_attempted = bool(falsification_attempted)
        h.updated_at_iso = self._now_iso()
        self._append_log({"event": "update", "iso": h.updated_at_iso, **asdict(h)})
        response = {"status": "ok", "hypothesis": asdict(h)}
        if (falsification_attempted is True and falsification_evidence is None
                and h.falsification_evidence is None):
            response["warning"] = (
                "falsification_attempted=True alone no longer satisfies conclude(high) "
                "(FIX #5): supply falsification_evidence={tool_call_id, excerpt} from "
                "the actual experiment run.")
        return response

    def mark_reviewed(self, hid: str, verdict: str, reason: str) -> dict:
        """FIX #6: hypothesis-reviewer sub-agent records its verdict here.

        This tool is callable in principle by any agent context; the
        anti-cheat is on the gate side — conclude(high) only accepts a
        recent verdict, and the reviewer sub-agent's tool permission set
        (declared in agents/hypothesis-reviewer.md) is the narrowest of
        any agent in the project. Pre-meditated bypass (main agent calling
        this directly) is reflected on the on-disk hypothesis_ledger.jsonl
        audit log — the call sequence shows mark_reviewed was followed by
        conclude on the same agent context, which a post-mortem catches.
        """
        h = self._by_id.get(hid)
        if h is None:
            return {"status": "error", "error": f"unknown hypothesis '{hid}'"}
        if h.state != "active":
            return {"status": "error", "error":
                    f"hypothesis {hid} is {h.state}, not 'active' — cannot review"}
        if verdict not in VALID_REVIEWER_VERDICT:
            return {"status": "error", "error":
                    f"verdict must be one of {VALID_REVIEWER_VERDICT}"}
        if not isinstance(reason, str) or len(reason.strip()) < 6:
            return {"status": "error", "error":
                    "review reason must be a non-trivial string (>=6 chars)"}
        h.reviewed_at_tool_call = self.get_tool_call_count()
        h.reviewer_verdict = verdict
        h.reviewer_reason = reason.strip()[:600]
        h.updated_at_iso = self._now_iso()
        self._append_log({"event": "reviewed", "iso": h.updated_at_iso,
                          "hypothesis_id": hid, "verdict": verdict,
                          "reviewed_at_tool_call": h.reviewed_at_tool_call,
                          "reason": h.reviewer_reason})
        return {"status": "ok", "hypothesis": asdict(h)}

    def archive(self, hid: str, reason: str) -> dict:
        """FIX #7: move a concluded (or active) hypothesis to 'archived' so
        the validate_artifact_references gate doesn't force agents to cite
        non-load-bearing hypotheses in the final deliverable. abandoned
        cannot be archived (it's already terminal-negative); archived
        cannot be cited via [H<n>] in the artifact."""
        h = self._by_id.get(hid)
        if h is None:
            return {"status": "error", "error": f"unknown hypothesis '{hid}'"}
        if h.state == "archived":
            return {"status": "error",
                    "error": f"hypothesis {hid} is already archived"}
        if h.state == "abandoned":
            return {"status": "error", "error":
                    f"hypothesis {hid} is abandoned — archive does not apply "
                    "(abandoned is already terminal-negative)"}
        if not isinstance(reason, str) or len(reason.strip()) < 6:
            return {"status": "error",
                    "error": "archive reason must be a non-trivial string (>=6 chars)"}
        h.state = "archived"
        h.archive_reason = reason.strip()[:600]
        h.updated_at_iso = self._now_iso()
        self._append_log({"event": "archive", "iso": h.updated_at_iso, **asdict(h)})
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
            # FIX #5: prefer verifiable evidence tag over the bare boolean
            if h.falsification_evidence is not None:
                falsify_tag = "✓falsify-evidence"
            elif h.falsification_attempted:
                falsify_tag = "✗falsify-bool-only"  # boolean without evidence: gate will reject
            else:
                falsify_tag = "✗falsify-pending"
            # FIX #6: surface reviewer state
            if h.reviewer_verdict == "confirm":
                rev_tag = " ✓reviewed"
            elif h.reviewer_verdict in ("refute", "abandon"):
                rev_tag = f" ⚠reviewer={h.reviewer_verdict}"
            else:
                rev_tag = ""
            ratio_tag = "" if n_sup >= n_con else " ⚠CONTRA-DOMINANT"
            div_tag = f" sources={diversity}" if h.supporting else ""
            lines.append(f"  {h.id} [{h.confidence}] {h.statement[:80]} "
                         f"(sup={n_sup} contra={n_con}{div_tag} "
                         f"{falsify_tag}{rev_tag}{ratio_tag})")
        return "\n".join(lines)

    def validate_artifact_references(self, content: str) -> dict:
        # FIX A-8: bracketed [H<n>] is the canonical citation form.
        # The pre-v0.9.1 regex \bH(\d+)\b silently false-matched on:
        #   - Python source variable names (H1 = some_value)
        #   - SHA-3 / SHA-512 state vector names (h0, h1, ...) when capitalised
        #   - Any markdown header / acronym containing 'H<digit>' at a word
        #     boundary in the deliverable narrative
        # Requiring an explicit bracket makes citations syntactically obvious
        # to both human readers and the validator. Skill docs are updated to
        # teach the [H<n>] form.
        import re
        # Capture bracketed and angle-bracketed forms — both visually obvious
        # citations that no naturally-occurring identifier would collide with.
        ids = sorted(set(re.findall(r"\[H(\d+)\]|<H(\d+)>", content or "")))
        ids_flat = [a or b for (a, b) in ids]
        errors: list[str] = []
        referenced = []
        for n in ids_flat:
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
