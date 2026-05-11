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
            ledger.update(hid, falsification_attempted=True)
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
            ledger.update(hid, falsification_attempted=True)
            res = ledger.conclude(hid, "MD5 confirmed via 3 tools",
                                  final_confidence="high")
            self.assertEqual(res["status"], "ok", res)
            self.assertEqual(res["hypothesis"]["confidence"], "high")


class TestConflictGraph(unittest.TestCase):
    """FIX #4 — conclude(≥medium) blocked if a conflicting hypothesis is
    already concluded ≥medium."""

    def _add(self, ledger, counter, statement, n_sup=2, conflicts_with=None):
        sup = [{"tool_call_id":
                _record_tool_call(ledger.tool_log, counter,
                                  f"t{i}", f"evidence chunk {i}"),
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
            check = ledger.validate_artifact_references(
                f"Algorithm is MD5, see {hid}.")
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
            check = ledger.validate_artifact_references(
                f"Algorithm is MD5, see {hid}.")
            self.assertTrue(check["ok"], check)
            self.assertIn(hid, check["referenced_ids"])


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
