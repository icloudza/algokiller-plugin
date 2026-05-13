"""Regression tests for the Hypothesis Ledger anti-hallucination gates.

These tests pin down the four FIX gates introduced in v0.8.1
(commit b59125b) so any future refactor catches a loosened gate
immediately rather than at delivery time.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

# Discoverable both via `python3 -m unittest discover -s tests/python` and
# direct `python3 tests/python/test_hypothesis.py`.
_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from hypothesis import HypothesisLedger, ToolCallLog  # noqa: E402


def _make_ledger(tmpdir: Path) -> tuple[HypothesisLedger, list[int]]:
    """Build a fresh ledger with a counter we can bump from the test."""
    counter = [0]
    log = ToolCallLog(tmpdir)
    ledger = HypothesisLedger(
        artifacts_dir=tmpdir,
        get_tool_call_count=lambda: counter[0],
        tool_call_log=log,
    )
    return ledger, counter


def _record_tool_call(log: ToolCallLog, counter: list[int],
                      tool: str, result_text: str) -> int:
    """Simulate a tool call: bump the counter, store its result."""
    counter[0] += 1
    cid = counter[0]
    log.record(cid, tool, {}, {"status": "ok", "stdout": result_text})
    return cid


class TestEvidenceExcerptVerification(unittest.TestCase):
    """FIX #1 — every evidence item must cite an excerpt that the server
    can locate verbatim inside the stored tool result."""

    def test_missing_excerpt_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid = _record_tool_call(ledger.tool_log, counter,
                                    "trace_search", '{"hits":42}')
            out = ledger.add(
                statement="MD5 init constants present",
                confidence="low",
                falsification_plan="trace_callgraph --to md5 must show calls",
                supporting=[{"tool_call_id": cid}],   # no excerpt
            )
            self.assertEqual(out["status"], "error")
            self.assertIn("excerpt is required", out["error"])

    def test_short_excerpt_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid = _record_tool_call(ledger.tool_log, counter,
                                    "trace_search", '{"hits":42,"md5":true}')
            out = ledger.add(
                statement="MD5 init constants present",
                confidence="low",
                falsification_plan="trace_callgraph --to md5 must show calls",
                supporting=[{"tool_call_id": cid, "excerpt": "tiny"}],
            )
            self.assertEqual(out["status"], "error")
            self.assertIn("too short", out["error"])

    def test_excerpt_not_in_result_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid = _record_tool_call(ledger.tool_log, counter,
                                    "trace_search", '{"hits":42}')
            out = ledger.add(
                statement="MD5 init constants present",
                confidence="low",
                falsification_plan="trace_callgraph --to md5 must show calls",
                supporting=[{"tool_call_id": cid,
                             "excerpt": "this string is nowhere in result"}],
            )
            self.assertEqual(out["status"], "error")
            self.assertIn("NOT found in tool_call_id", out["error"])

    def test_excerpt_substring_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid = _record_tool_call(
                ledger.tool_log, counter, "trace_constscan",
                '{"fingerprint":"MD5.A","magic":"0x67452301"}',
            )
            out = ledger.add(
                statement="MD5 init constants present in trace",
                confidence="low",
                falsification_plan="trace_callgraph --to md5 must show calls",
                supporting=[{"tool_call_id": cid,
                             "excerpt": "0x67452301"}],
            )
            self.assertEqual(out["status"], "ok", out)
            # FIX #3 anchor: tool_name is derived server-side, not trusted.
            h = out["hypothesis"]
            self.assertEqual(h["supporting"][0]["tool_name"], "trace_constscan")

    def test_excerpt_with_quotes_accepted_via_escape_fallback(self):
        """Regression: agent copies excerpts from the un-escaped stdout
        it sees, but tool_log stores the JSON-serialised payload where
        `"` became `\\"`. A substring containing `"` must still pass via
        the JSON-escape fallback in excerpt_in_result()."""
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            # The tool_log records the JSON-serialized form, so the stored
            # text will contain \"type\":\"constscan\" rather than literal "
            cid = _record_tool_call(
                ledger.tool_log, counter, "trace_constscan",
                '{"type":"constscan","fingerprint":"SHA512.h0"}',
            )
            # Agent copies an excerpt that contains literal quotes from the
            # rendered stdout it saw.
            out = ledger.add(
                statement="SHA-512 init constants present in trace",
                confidence="low",
                falsification_plan="trace_callgraph --to sha512 returns no hits",
                supporting=[{"tool_call_id": cid,
                             "excerpt": '"type":"constscan"'}],
            )
            self.assertEqual(out["status"], "ok", out)

    def test_tool_call_id_out_of_range_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            _record_tool_call(ledger.tool_log, counter,
                              "trace_search", "ok body")
            out = ledger.add(
                statement="ID 999 should not be accepted",
                confidence="low",
                falsification_plan="trace_lint reports any inconsistency",
                supporting=[{"tool_call_id": 999, "excerpt": "ok body"}],
            )
            self.assertEqual(out["status"], "error")
            self.assertIn("outside the actual", out["error"])


class TestContradictionPressure(unittest.TestCase):
    """FIX #2 — contradicting > supporting hard-caps confidence at low."""

    def _build_with_evidence(self, ledger, counter,
                             n_supporting: int, n_contradicting: int) -> str:
        sup = [{"tool_call_id":
                _record_tool_call(ledger.tool_log, counter,
                                  f"tool_s{i}", f"support evidence {i}"),
                "excerpt": f"support evidence {i}"}
               for i in range(n_supporting)]
        contra = [{"tool_call_id":
                   _record_tool_call(ledger.tool_log, counter,
                                     f"tool_c{i}", f"counter evidence {i}"),
                   "excerpt": f"counter evidence {i}"}
                  for i in range(n_contradicting)]
        out = ledger.add(
            statement="H under test for contradiction pressure",
            confidence="low",
            falsification_plan="counter-experiment described elsewhere",
            supporting=sup,
            contradicting=contra,
        )
        self.assertEqual(out["status"], "ok", out)
        return out["hypothesis"]["id"]

    def test_contradicting_exceeds_supporting_caps_at_low(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            hid = self._build_with_evidence(ledger, counter,
                                            n_supporting=2,
                                            n_contradicting=3)
            ledger.update(hid, falsification_attempted=True)
            out = ledger.conclude(hid, "trying medium anyway",
                                  final_confidence="medium")
            self.assertEqual(out["status"], "error")
            self.assertIn("contradiction pressure", out["error"])

    def test_medium_requires_supporting_greater_than_contradicting(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            hid = self._build_with_evidence(ledger, counter,
                                            n_supporting=2,
                                            n_contradicting=2)
            out = ledger.conclude(hid, "tie should not pass medium",
                                  final_confidence="medium")
            self.assertEqual(out["status"], "error")
            self.assertIn("supporting > contradicting", out["error"])

    def test_high_requires_supporting_at_least_2x_contradicting(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            hid = self._build_with_evidence(ledger, counter,
                                            n_supporting=3,
                                            n_contradicting=2)
            ledger.update(hid, falsification_attempted=True)
            out = ledger.conclude(hid, "3 vs 2 should fail 2x rule",
                                  final_confidence="high")
            self.assertEqual(out["status"], "error")
            self.assertIn("2 × contradicting", out["error"])


class TestSourceDiversity(unittest.TestCase):
    """FIX #3 — conclude(high) requires supporting from ≥2 distinct tools."""

    def test_three_hits_from_same_tool_blocked_at_high(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid1 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_constscan", "MD5.A magic hit 1")
            cid2 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_constscan", "MD5.A magic hit 2")
            cid3 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_constscan", "MD5.A magic hit 3")
            out = ledger.add(
                statement="Binary computes MD5",
                confidence="low",
                falsification_plan="callgraph shows no md5 call symbol",
                supporting=[
                    {"tool_call_id": cid1, "excerpt": "MD5.A magic hit 1"},
                    {"tool_call_id": cid2, "excerpt": "MD5.A magic hit 2"},
                    {"tool_call_id": cid3, "excerpt": "MD5.A magic hit 3"},
                ],
            )
            self.assertEqual(out["status"], "ok", out)
            hid = out["hypothesis"]["id"]
            # Satisfy FIX#5 + FIX#6 so the diversity gate is what trips
            cid_falsify = _record_tool_call(ledger.tool_log, counter,
                                            "trace_callgraph", "callgraph found no md5_*")
            ledger.update(hid, falsification_evidence={
                "tool_call_id": cid_falsify,
                "excerpt": "callgraph found no md5_*"})
            ledger.mark_reviewed(hid, "confirm",
                                 "reviewer audited even though diversity is 1")
            res = ledger.conclude(hid, "MD5 confirmed from constscan",
                                  final_confidence="high")
            self.assertEqual(res["status"], "error")
            self.assertIn("source diversity", res["error"])

    def test_two_distinct_tools_satisfies_diversity(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid1 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_constscan", "MD5.A magic hit")
            cid2 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_callgraph", "call func: md5_update")
            cid3 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_hexblock", "hexdump bytes_hex 6745")
            out = ledger.add(
                statement="Binary computes MD5",
                confidence="low",
                falsification_plan="trace_lint reports inconsistency",
                supporting=[
                    {"tool_call_id": cid1, "excerpt": "MD5.A magic hit"},
                    {"tool_call_id": cid2, "excerpt": "call func: md5_update"},
                    {"tool_call_id": cid3, "excerpt": "hexdump bytes_hex 6745"},
                ],
            )
            self.assertEqual(out["status"], "ok", out)
            hid = out["hypothesis"]["id"]
            # FIX #5: real falsification experiment after hypothesis creation
            cid_falsify = _record_tool_call(ledger.tool_log, counter,
                                            "trace_lint", "lint says no inconsistency")
            ledger.update(hid, falsification_evidence={
                "tool_call_id": cid_falsify,
                "excerpt": "lint says no inconsistency"})
            # FIX #6: reviewer hard gate
            ledger.mark_reviewed(hid, "confirm",
                                 "reviewer audited 3-tool diversity and falsification")
            res = ledger.conclude(hid, "MD5 confirmed via 3 tools",
                                  final_confidence="high")
            self.assertEqual(res["status"], "ok", res)
            self.assertEqual(res["hypothesis"]["confidence"], "high")


class TestConflictGraph(unittest.TestCase):
    """FIX #4 — conclude(≥medium) blocked if a conflicting hypothesis is
    already concluded ≥medium."""

    def _add(self, ledger, counter, statement, n_sup=2, conflicts_with=None):
        # Tool-name pool: FIX #8 (v0.9.7) requires algorithm-named hypotheses
        # (e.g. "Binary uses MD5") to carry trace_cryptoinstr / trace_constscan
        # supporting before they can conclude at medium/high. The pool rotates
        # trace_constscan first so even n_sup=1 cases satisfy the gate.
        tool_pool = ["trace_constscan", "trace_cryptoinstr",
                     "trace_callgraph", "trace_search"]
        sup = [{"tool_call_id":
                _record_tool_call(ledger.tool_log, counter,
                                  tool_pool[i % len(tool_pool)],
                                  f"evidence chunk {i}"),
                "excerpt": f"evidence chunk {i}"}
               for i in range(n_sup)]
        out = ledger.add(
            statement=statement,
            confidence="low",
            falsification_plan="alternative tools would disagree",
            supporting=sup,
            conflicts_with=conflicts_with,
        )
        self.assertEqual(out["status"], "ok", out)
        return out["hypothesis"]["id"]

    def test_conflict_blocks_second_conclude_medium(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            h1 = self._add(ledger, counter, "Binary uses MD5")
            # H2 declares it conflicts with H1
            h2 = self._add(ledger, counter, "Binary uses SHA-256",
                           conflicts_with=[h1])
            r1 = ledger.conclude(h1, "MD5 confirmed",
                                 final_confidence="medium")
            self.assertEqual(r1["status"], "ok", r1)
            r2 = ledger.conclude(h2, "SHA-256 confirmed",
                                 final_confidence="medium")
            self.assertEqual(r2["status"], "error")
            self.assertIn("conflict", r2["error"])

    def test_conflict_allows_low_confidence_conclude(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            h1 = self._add(ledger, counter, "Binary uses MD5", n_sup=2)
            h2 = self._add(ledger, counter, "Binary uses SHA-256",
                           n_sup=2, conflicts_with=[h1])
            ledger.conclude(h1, "MD5 confirmed", final_confidence="medium")
            r2 = ledger.conclude(h2, "SHA-256 at low confidence",
                                 final_confidence="low")
            self.assertEqual(r2["status"], "ok", r2)


class TestArtifactReferenceValidation(unittest.TestCase):
    """validate_artifact_references — writes that cite an unfinished or
    weak hypothesis must be rejected."""

    def test_rejects_reference_to_active_hypothesis(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid = _record_tool_call(ledger.tool_log, counter,
                                    "trace_constscan", "MD5.A magic hit")
            r = ledger.add(
                statement="MD5 hypothesis",
                confidence="low",
                falsification_plan="callgraph would disagree",
                supporting=[{"tool_call_id": cid,
                             "excerpt": "MD5.A magic hit"}],
            )
            hid = r["hypothesis"]["id"]
            # FIX A-8: bracketed citation form is the only one matched
            check = ledger.validate_artifact_references(
                f"Algorithm is MD5, see [{hid}].")
            self.assertFalse(check["ok"])
            self.assertTrue(any("not 'concluded'" in e
                                for e in check["errors"]))

    def test_accepts_reference_to_concluded_medium(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid1 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_constscan", "MD5.A magic hit")
            cid2 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_callgraph", "call func: md5_update")
            r = ledger.add(
                statement="MD5 hypothesis",
                confidence="low",
                falsification_plan="callgraph would disagree",
                supporting=[
                    {"tool_call_id": cid1, "excerpt": "MD5.A magic hit"},
                    {"tool_call_id": cid2, "excerpt": "call func: md5_update"},
                ],
            )
            hid = r["hypothesis"]["id"]
            ledger.conclude(hid, "MD5 confirmed", final_confidence="medium")
            # FIX A-8: bracketed citation form is the only one matched
            check = ledger.validate_artifact_references(
                f"Algorithm is MD5, see [{hid}].")
            self.assertTrue(check["ok"], check)
            self.assertIn(hid, check["referenced_ids"])


class TestFalsificationEvidence(unittest.TestCase):
    """FIX #5 (v0.9.1) — conclude(high) requires verifiable
    falsification_evidence; boolean self-report no longer suffices.
    """

    def _build_for_high(self, td, n_supporting_distinct=3):
        ledger, counter = _make_ledger(Path(td))
        sup = []
        # Distinct tool names → satisfies FIX #3 diversity
        for i in range(n_supporting_distinct):
            cid = _record_tool_call(ledger.tool_log, counter,
                                    f"distinct_tool_{i}", f"piece evidence {i} content")
            sup.append({"tool_call_id": cid, "excerpt": f"piece evidence {i} content"})
        r = ledger.add(
            statement="Binary computes XX algorithm",
            confidence="low",
            falsification_plan="run a counter-experiment via trace_callgraph",
            supporting=sup,
        )
        return ledger, counter, r["hypothesis"]["id"]

    def test_boolean_only_rejected_at_high(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._build_for_high(td)
            ledger.update(hid, falsification_attempted=True)
            # FIX #6 needs reviewer too; satisfy that to isolate FIX #5
            ledger.mark_reviewed(hid, "confirm", "reviewer audit passed for test")
            out = ledger.conclude(hid, "concluded", final_confidence="high")
            self.assertEqual(out["status"], "error")
            self.assertIn("falsification_evidence", out["error"])

    def test_evidence_before_hypothesis_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._build_for_high(td)
            # Falsification "evidence" pointing at an OLD tool_call_id
            # (one we already used for supporting). tool_call_id must be
            # strictly greater than created_at_tool_call.
            old_cid = 1
            out = ledger.update(hid, falsification_evidence={
                "tool_call_id": old_cid, "excerpt": "piece evidence 0 content"})
            self.assertEqual(out["status"], "error")
            self.assertIn("must be GREATER", out["error"])

    def test_valid_evidence_promotes_to_high(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._build_for_high(td)
            # Run the falsification experiment AFTER hypothesis was created
            cid_falsify = _record_tool_call(
                ledger.tool_log, counter, "trace_callgraph",
                "call func: md5_compress 0 hits — falsification result")
            out = ledger.update(hid, falsification_evidence={
                "tool_call_id": cid_falsify,
                "excerpt": "call func: md5_compress 0 hits"})
            self.assertEqual(out["status"], "ok", out)
            ledger.mark_reviewed(hid, "confirm",
                                 "reviewer audited evidence and falsification result")
            res = ledger.conclude(hid, "validated", final_confidence="high")
            self.assertEqual(res["status"], "ok", res)


class TestReviewerHardGate(unittest.TestCase):
    """FIX #6 (v0.9.1) — conclude(high) requires hypothesis-reviewer
    verdict='confirm' within REVIEWER_STALENESS_LIMIT calls."""

    def _make_high_ready(self, td):
        ledger, counter = _make_ledger(Path(td))
        sup = []
        for i, tool in enumerate(("trace_constscan", "trace_callgraph",
                                  "trace_hexblock")):
            cid = _record_tool_call(ledger.tool_log, counter,
                                    tool, f"evidence body {i} verbatim")
            sup.append({"tool_call_id": cid, "excerpt": f"evidence body {i} verbatim"})
        r = ledger.add(
            statement="Algorithm is XYZ",
            confidence="low",
            falsification_plan="cross-check with other indicators",
            supporting=sup,
        )
        hid = r["hypothesis"]["id"]
        cid_falsify = _record_tool_call(ledger.tool_log, counter,
                                        "trace_lint", "lint says no XYZ pattern present")
        ledger.update(hid, falsification_evidence={
            "tool_call_id": cid_falsify,
            "excerpt": "lint says no XYZ pattern"})
        return ledger, counter, hid

    def test_high_without_reviewer_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._make_high_ready(td)
            out = ledger.conclude(hid, "trying to conclude",
                                  final_confidence="high")
            self.assertEqual(out["status"], "error")
            self.assertIn("reviewer", out["error"].lower())

    def test_high_with_refute_verdict_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._make_high_ready(td)
            ledger.mark_reviewed(hid, "refute",
                                 "evidence #2 was weak by reviewer audit")
            out = ledger.conclude(hid, "trying anyway",
                                  final_confidence="high")
            self.assertEqual(out["status"], "error")
            self.assertIn("confirm", out["error"])

    def test_high_with_confirm_verdict_accepted(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._make_high_ready(td)
            ledger.mark_reviewed(hid, "confirm",
                                 "evidence checks out; all gates satisfied")
            out = ledger.conclude(hid, "validated", final_confidence="high")
            self.assertEqual(out["status"], "ok", out)
            self.assertEqual(out["hypothesis"]["confidence"], "high")

    def test_stale_review_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._make_high_ready(td)
            ledger.mark_reviewed(hid, "confirm", "early review will go stale")
            # Burn 31 more tool calls — REVIEWER_STALENESS_LIMIT is 30
            for _ in range(31):
                _record_tool_call(ledger.tool_log, counter,
                                  "trace_search", "later activity")
            out = ledger.conclude(hid, "trying late",
                                  final_confidence="high")
            self.assertEqual(out["status"], "error")
            self.assertIn("stale", out["error"].lower())


class TestArchiveState(unittest.TestCase):
    """FIX #7 (v0.9.1) — concluded hypotheses can be archived so they
    no longer count as 'must be referenced' in the deliverable."""

    def _build_concluded(self, td):
        ledger, counter = _make_ledger(Path(td))
        sup = []
        for i, tool in enumerate(("t_a", "t_b")):
            cid = _record_tool_call(ledger.tool_log, counter,
                                    tool, f"evidence chunk {i}")
            sup.append({"tool_call_id": cid, "excerpt": f"evidence chunk {i}"})
        r = ledger.add(statement="Sub-hypothesis", confidence="low",
                       falsification_plan="some experiment",
                       supporting=sup)
        hid = r["hypothesis"]["id"]
        ledger.conclude(hid, "confirmed at medium", final_confidence="medium")
        return ledger, counter, hid

    def test_archive_succeeds_for_concluded(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._build_concluded(td)
            out = ledger.archive(hid, "not load-bearing for final report")
            self.assertEqual(out["status"], "ok", out)
            self.assertEqual(out["hypothesis"]["state"], "archived")

    def test_archive_blocks_abandoned(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid = _record_tool_call(ledger.tool_log, counter,
                                    "t", "evidence verbatim block")
            r = ledger.add(statement="To abandon", confidence="low",
                           falsification_plan="any falsifier",
                           supporting=[{"tool_call_id": cid,
                                        "excerpt": "evidence verbatim block"}])
            hid = r["hypothesis"]["id"]
            ledger.abandon(hid, "no longer applies")
            out = ledger.archive(hid, "trying to archive abandoned")
            self.assertEqual(out["status"], "error")

    def test_archive_short_reason_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._build_concluded(td)
            out = ledger.archive(hid, "x")
            self.assertEqual(out["status"], "error")
            self.assertIn(">=6", out["error"])

    def test_archived_not_required_in_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter, hid = self._build_concluded(td)
            ledger.archive(hid, "exclusion analysis; not in final report")
            # Artifact with NO references but ledger has only an archived
            # hypothesis (no concluded ones) — should not trigger the
            # "bypass" bypass-error.
            concluded = [h for h in ledger.list(state="concluded")["hypotheses"]
                         if h["state"] == "concluded"]
            self.assertEqual(concluded, [])  # archived no longer counts


class TestArtifactBracketCitation(unittest.TestCase):
    """FIX A-8 (v0.9.1) — citation regex is bracket-only; bare H1/H2 in
    Python source no longer false-match."""

    def _make_concluded(self, td):
        ledger, counter = _make_ledger(Path(td))
        sup = []
        for i, tool in enumerate(("trace_constscan", "trace_callgraph")):
            cid = _record_tool_call(ledger.tool_log, counter,
                                    tool, f"evidence content {i}")
            sup.append({"tool_call_id": cid, "excerpt": f"evidence content {i}"})
        r = ledger.add(statement="X is true", confidence="low",
                       falsification_plan="some falsification approach",
                       supporting=sup)
        hid = r["hypothesis"]["id"]
        ledger.conclude(hid, "validated", final_confidence="medium")
        return ledger, hid

    def test_bare_H_not_matched_as_citation(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, hid = self._make_concluded(td)
            # Bare H<n> in narrative — no brackets. Should NOT be picked up.
            check = ledger.validate_artifact_references(
                f"As we discussed, {hid} shows the pattern.")
            self.assertEqual(check["referenced_ids"], [])

    def test_bracketed_H_matched_as_citation(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, hid = self._make_concluded(td)
            check = ledger.validate_artifact_references(
                f"Algorithm is X (see [{hid}]).")
            self.assertTrue(check["ok"], check)
            self.assertIn(hid, check["referenced_ids"])

    def test_python_variable_name_not_false_matched(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, hid = self._make_concluded(td)
            # Python source with H1 as a magnetic-field variable name — must
            # NOT trip the validator since the SOURCE doesn't bracket-cite hid.
            artifact = "def field(t):\n    H1 = 5.0\n    return H1 * t\n"
            check = ledger.validate_artifact_references(artifact)
            self.assertEqual(check["referenced_ids"], [])
            self.assertTrue(check["ok"])


class TestHighConfidenceTierGate(unittest.TestCase):
    """FIX gap 1 (v0.9.3) — '高置信推断' / 'high-confidence inference' tier
    marker detection in artifact content. Closes the bypass surfaced by the
    real TikTok trace audit (trace_1009_main.log) where the agent shipped 7+
    high-confidence claims with zero [H<n>] backing."""

    def _make_ledger(self, td: str):
        return _make_ledger(Path(td))

    def test_no_marker_returns_empty_list(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, _ = self._make_ledger(td)
            check = ledger.validate_artifact_references(
                "# Findings\n\nObservation: line 8872 contains 4192-byte hexdump.")
            self.assertEqual(check["high_confidence_markers_found"], [])

    def test_chinese_marker_detected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, _ = self._make_ledger(td)
            check = ledger.validate_artifact_references(
                "## 6. 关键发现\n\n**高置信推断**: SM3 是本 SO 的核心 hash 原语。")
            self.assertIn("高置信推断", check["high_confidence_markers_found"])

    def test_english_marker_detected_case_insensitive(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, _ = self._make_ledger(td)
            check = ledger.validate_artifact_references(
                "## Findings\n\n**High-Confidence Inference**: binary computes MD5.")
            self.assertIn("high-confidence inference",
                          check["high_confidence_markers_found"])

    def test_both_zh_and_en_markers_detected(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, _ = self._make_ledger(td)
            check = ledger.validate_artifact_references(
                "高置信推断: SM3. high-confidence inference: AES T-table.")
            self.assertGreaterEqual(len(check["high_confidence_markers_found"]), 2)

    def test_artifact_with_marker_and_citation_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = self._make_ledger(td)
            cid1 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_constscan", "SM3 T_j magic hit")
            cid2 = _record_tool_call(ledger.tool_log, counter,
                                     "trace_callgraph", "call func: sm3_compress")
            r = ledger.add(statement="binary computes SM3",
                           confidence="low",
                           falsification_plan="cryptoinstr would show sha256h",
                           supporting=[
                               {"tool_call_id": cid1, "excerpt": "SM3 T_j magic hit"},
                               {"tool_call_id": cid2, "excerpt": "call func: sm3_compress"},
                           ])
            hid = r["hypothesis"]["id"]
            ledger.conclude(hid, "SM3 confirmed", final_confidence="medium")
            # Artifact uses tier marker AND cites [H<n>] — passes validation
            check = ledger.validate_artifact_references(
                f"**高置信推断**: binary 用 SM3 (见 [{hid}])。")
            self.assertTrue(check["ok"], check)
            self.assertIn(hid, check["referenced_ids"])
            # 高置信推断 contains 高置信 as a prefix; both markers register.
            # That's intentional — variations like '高置信判断' also trip.
            self.assertIn("高置信推断", check["high_confidence_markers_found"])


class TestWriteArtifactHighConfGate(unittest.TestCase):
    """End-to-end gate test through the handler layer (without JSON-RPC).

    This is the test that nails the real TikTok-trace audit case: ledger is
    empty (agent never called hypothesis_add), but the artifact contains
    '高置信推断' tier claims. Pre-v0.9.3 this would silently write the file.
    v0.9.3 must reject.
    """

    def setUp(self):
        from state import STATE
        from artifacts import ArtifactStore  # noqa: F401
        self.td = tempfile.TemporaryDirectory()
        STATE.trace_file = Path("/dev/null")
        STATE.trace_basename = "test"
        STATE.mode = "general"
        STATE.tool_call_count = 0
        STATE.artifacts_dir = Path(self.td.name)
        from hypothesis import HypothesisLedger, ToolCallLog
        STATE.tool_log = ToolCallLog(STATE.artifacts_dir)
        STATE.ledger = HypothesisLedger(
            artifacts_dir=STATE.artifacts_dir,
            get_tool_call_count=lambda: STATE.tool_call_count,
            tool_call_log=STATE.tool_log,
        )
        self.state = STATE

    def tearDown(self):
        from state import STATE
        STATE.trace_file = None
        STATE.daemon = None
        STATE.ledger = None
        STATE.tool_log = None
        STATE.artifacts_dir = None
        STATE.tool_call_count = 0
        self.td.cleanup()

    def test_high_conf_marker_no_citation_rejected(self):
        from tools.handlers import tool_write_artifact
        body = (
            "# 完整分析报告\n\n"
            + "## 6. 关键发现\n\n"
            + "**高置信推断**: binary 在做 SM3 主压缩循环.\n\n"
            + "(详细 hexdump 略)" * 20
        )
        result = tool_write_artifact({"path": "report.md", "content": body})
        self.assertEqual(result["status"], "error")
        self.assertIn("high-confidence", result["error"])
        self.assertIn("高置信推断", result["high_confidence_markers_found"])
        self.assertIn("instruction", result)

    def test_no_marker_passes_even_empty_ledger(self):
        from tools.handlers import tool_write_artifact
        body = (
            "# 体检报告\n\n"
            + "**已确认**: trace 长度 7,145,157 行.\n\n"
            + "(纯观察叙事 padding)" * 30
        )
        result = tool_write_artifact({"path": "obs.md", "content": body})
        self.assertEqual(result["status"], "ok", result)
        self.assertTrue(Path(result["path"]).exists())

    def test_high_conf_marker_with_citation_passes(self):
        from tools.handlers import tool_write_artifact
        ledger = self.state.ledger
        counter = [0]

        def record(tool: str, payload: str) -> int:
            counter[0] += 1
            self.state.tool_call_count = counter[0]
            ledger.tool_log.record(counter[0], tool, {},
                                    {"status": "ok", "stdout": payload})
            return counter[0]
        c1 = record("trace_constscan", "SM3 T_j magic hit 1")
        c2 = record("trace_callgraph", "call func: sm3_compress symbol")
        r = ledger.add(statement="binary computes SM3 hash",
                       confidence="low",
                       falsification_plan="cryptoinstr would show sha256h instead",
                       supporting=[
                           {"tool_call_id": c1, "excerpt": "SM3 T_j magic hit 1"},
                           {"tool_call_id": c2, "excerpt": "call func: sm3_compress symbol"},
                       ])
        hid = r["hypothesis"]["id"]
        ledger.conclude(hid, "SM3 confirmed via multi-tool",
                        final_confidence="medium")
        body = (
            "# 完整分析\n\n"
            + f"**高置信推断**: binary 在做 SM3 (见 [{hid}]).\n\n"
            + "(详细 hexdump 略)" * 20
        )
        result = tool_write_artifact({"path": "report-cited.md", "content": body})
        self.assertEqual(result["status"], "ok", result)


class TestAbandonCascade(unittest.TestCase):
    """abandon() must surface active hypotheses that depended on the
    abandoned one so the agent re-evaluates them."""

    def test_abandon_surfaces_dependent_hypotheses(self):
        with tempfile.TemporaryDirectory() as td:
            ledger, counter = _make_ledger(Path(td))
            cid = _record_tool_call(ledger.tool_log, counter,
                                    "trace_constscan", "MD5.A magic hit")
            r1 = ledger.add(
                statement="H1 — root signal",
                confidence="low",
                falsification_plan="any of 3 tools disagree",
                supporting=[{"tool_call_id": cid,
                             "excerpt": "MD5.A magic hit"}],
            )
            h1 = r1["hypothesis"]["id"]
            r2 = ledger.add(
                statement="H2 — depends on H1",
                confidence="low",
                falsification_plan="downstream of H1",
                depends_on=[h1],
            )
            h2 = r2["hypothesis"]["id"]
            abandoned = ledger.abandon(h1, reason="refuted by new evidence")
            self.assertEqual(abandoned["status"], "ok", abandoned)
            self.assertIn(h2, abandoned["downstream_active_hypotheses"])
            self.assertIn(h1, abandoned["warning"])


if __name__ == "__main__":
    unittest.main()
