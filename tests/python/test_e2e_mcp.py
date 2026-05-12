"""End-to-end integration tests for the algokiller MCP server.

Spawns `python3 server/algokiller_mcp.py` as a real subprocess, sends
JSON-RPC 2.0 frames over its stdin, and parses the JSON-RPC responses
on stdout — exactly how Claude Desktop drives the plugin.

Covers two test surfaces the unit tests cannot reach:

  L1 plumbing — bind_trace → trace_lint → trace_constscan →
                trace_callgraph → trace_hexblock → write_artifact
                runs against a real `ak_search` binary on a synthetic
                fixture, verifying the full pipeline does not crash and
                that discipline-reminders are attached.

  L3 ledger   — drives the Hypothesis Ledger anti-hallucination scaffold
                end to end: hypothesis_add → conclude(high) reject →
                update(falsification_attempted) → conclude(high) ok →
                write_artifact with H<id> → write_artifact without H<id>
                rejected as "bypass ledger". Verifies FIX #1–#4 are
                enforced in the production JSON-RPC path, not just the
                in-process unit-test path.

Fixtures used:
  tools/search/tests/fixtures/sprint34.trace  (MD5 init + memcpy block)
  tools/search/tests/fixtures/sprint5-constscan.trace  (SHA-256 init)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
SERVER = REPO_ROOT / "server" / "algokiller_mcp.py"
AK_SEARCH = REPO_ROOT / "server" / "bin" / "ak_search"
FIXTURES = REPO_ROOT / "tools" / "search" / "tests" / "fixtures"


def _ensure_binary() -> bool:
    """If ak_search isn't built (CI before make), skip these tests cleanly."""
    if not AK_SEARCH.exists():
        return False
    # quick run: --help-equivalent. Any exit code means it executes.
    try:
        subprocess.run([str(AK_SEARCH)], capture_output=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


@unittest.skipUnless(_ensure_binary(),
                     f"ak_search binary not available at {AK_SEARCH}; build via `cd tools/search && make`")
class MCPClient:
    """Thin JSON-RPC 2.0 client driving algokiller_mcp.py over stdio."""

    def __init__(self) -> None:
        env = os.environ.copy()
        env["ALGOKILLER_PLUGIN_ROOT"] = str(REPO_ROOT)
        env["PYTHONUNBUFFERED"] = "1"
        self.proc = subprocess.Popen(
            [sys.executable, "-u", str(SERVER)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
        )
        self._next_id = 1
        # Initialize handshake.
        self.request("initialize",
                     {"protocolVersion": "2024-11-05", "capabilities": {}})
        self.notify("notifications/initialized")

    def request(self, method: str, params: dict | None = None) -> dict:
        req_id = self._next_id
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        return self._read_response(req_id)

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def call_tool(self, name: str, arguments: dict) -> dict:
        """Convenience: tools/call + unwrap the text content as JSON."""
        resp = self.request("tools/call",
                            {"name": name, "arguments": arguments})
        if "error" in resp:
            raise RuntimeError(f"JSON-RPC error: {resp['error']}")
        content = resp["result"]["content"]
        assert len(content) == 1 and content[0]["type"] == "text"
        return json.loads(content[0]["text"])

    def _read_response(self, req_id: int) -> dict:
        assert self.proc.stdout is not None
        while True:
            line = self.proc.stdout.readline()
            if not line:
                stderr = ""
                if self.proc.stderr is not None:
                    try:
                        stderr = self.proc.stderr.read() or ""
                    except Exception:
                        pass
                raise RuntimeError(
                    f"MCP server closed stdin before responding to id={req_id}; "
                    f"stderr tail: {stderr[-500:]!r}")
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == req_id:
                return msg

    def close(self) -> None:
        try:
            if self.proc.stdin is not None:
                self.proc.stdin.close()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()


class TestL1Plumbing(unittest.TestCase):
    """L1: full pipeline runs against a real ak_search + synthetic trace."""

    @classmethod
    def setUpClass(cls):
        if not _ensure_binary():
            raise unittest.SkipTest(f"ak_search not built at {AK_SEARCH}")
        cls.client = MCPClient()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "client"):
            cls.client.close()

    def test_01_tools_list_returns_26(self):
        resp = self.client.request("tools/list")
        tools = resp["result"]["tools"]
        self.assertEqual(len(tools), 26)
        names = {t["name"] for t in tools}
        # Sanity-check a few across categories.
        for required in ("bind_trace", "pick_output_dir",
                         "trace_lint", "trace_constscan",
                         "trace_callgraph", "trace_hexblock",
                         "hypothesis_add", "write_artifact",
                         "mark_hypothesis_reviewed", "hypothesis_archive"):
            self.assertIn(required, names)

    def test_02_bind_and_lint(self):
        trace = FIXTURES / "sprint34.trace"
        r = self.client.call_tool("bind_trace",
                                  {"path": str(trace), "mode": "general"})
        self.assertEqual(r["status"], "ok", r)
        self.assertIn("artifacts_dir", r)
        # Discipline reminder injected from second tool call onward.
        r = self.client.call_tool("trace_lint", {})
        self.assertEqual(r["status"], "ok", r)
        self.assertIn("discipline_reminder", r)
        self.assertIn("_tool_call_id", r)

    def test_03_constscan_detects_md5_init(self):
        r = self.client.call_tool("trace_constscan", {})
        self.assertEqual(r["status"], "ok", r)
        # sprint34.trace embeds the MD5 init quartet — at least one hit.
        self.assertIn("MD5", r["stdout"], r["stdout"][:500])

    def test_04_callgraph_top_returns_memcpy(self):
        r = self.client.call_tool("trace_callgraph", {"top": 5})
        self.assertEqual(r["status"], "ok", r)
        # sprint34.trace has __memcpy_aarch64_simd, objc_retain, objc_msgSend.
        self.assertTrue(
            "memcpy" in r["stdout"] or "objc_msgSend" in r["stdout"],
            f"unexpected callgraph output: {r['stdout'][:400]}")

    def test_05_hexblock_parses_memcpy(self):
        # The memcpy call is on line 12 of sprint34.trace (1-based).
        r = self.client.call_tool("trace_hexblock", {"line": 12})
        self.assertEqual(r["status"], "ok", r)
        # Expect the ASCII payload "ABCDEFGHIJKLMNOP" → hex 41 42 43... in bytes_hex
        self.assertIn("4142434445", r["stdout"].lower().replace(" ", ""))

    def test_06_unknown_tool_returns_self_correction(self):
        # The dispatcher returns a normal tool result with instruction
        # rather than a JSON-RPC error so the agent doesn't stall.
        r = self.client.call_tool("nonexistent_tool", {})
        self.assertEqual(r["status"], "error")
        self.assertIn("does not exist", r["instruction"])
        self.assertIn("available_tools", r)


class TestF16ArcBookkeepingHexblock(unittest.TestCase):
    """FIX F-16 (v0.9.6): trace_hexblock tags ARC bookkeeping calls so
    agents stop reading consecutive same-buffer hexdumps from
    objc_retainAutoreleasedReturnValue / objc_autoreleaseReturnValue as
    independent algorithm-input events. Real-world repro: XHS iOS
    register-di trace, where one NSData was dumped 3 times by Frida-
    stalker on retain/autorelease/retain and the analysis report (using
    earlier algokiller) misread this as a 3-way HMAC pipeline."""

    @classmethod
    def setUpClass(cls):
        if not _ensure_binary():
            raise unittest.SkipTest(f"ak_search not built at {AK_SEARCH}")
        cls.client = MCPClient()
        trace = FIXTURES / "v096-arc-and-simd.trace"
        r = cls.client.call_tool("bind_trace",
                                 {"path": str(trace), "mode": "general"})
        if r.get("status") != "ok":
            raise unittest.SkipTest(f"bind_trace failed: {r}")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "client"):
            cls.client.close()

    def _find_call_line(self, needle: str) -> int:
        """Use trace_search to resolve the line number of a `call func:` row."""
        r = self.client.call_tool("trace_search",
                                  {"query": needle, "from_line": 1, "limit": 5})
        self.assertEqual(r["status"], "ok", r)
        for raw in (r.get("stdout") or "").splitlines():
            raw = raw.strip()
            if not raw or not raw.startswith("{"):
                continue
            row = json.loads(raw)
            if row.get("type") == "match" and "call func:" in row.get("text", ""):
                return int(row["line"])
        self.fail(f"could not resolve a call_func line for {needle!r}: {r}")

    def test_01_arc_call_tagged_and_warned(self):
        """objc_retainAutoreleasedReturnValue + hexdump → arc_bookkeeping
        + arc_warning surfaced as instruction so agents see it."""
        line = self._find_call_line("objc_retainAutoreleasedReturnValue")
        r = self.client.call_tool("trace_hexblock", {"line": line})
        self.assertEqual(r["status"], "ok", r)
        body = json.loads(r["stdout"].splitlines()[0])
        self.assertEqual(body.get("call_kind"), "arc_bookkeeping",
                         f"expected arc_bookkeeping tag: {body}")
        self.assertIn("arc_warning", body,
                      "hexdump on ARC call must carry arc_warning")
        # Warning text should explain the side-effect-dump pitfall.
        self.assertIn("Frida-stalker side-effect", body["arc_warning"])
        # Engine must also lift the warning into result.instruction so it
        # rides the discipline-reminder path back to the agent.
        self.assertIn("arc_bookkeeping", r.get("instruction", ""),
                      f"arc warning must propagate to instruction: {r.get('instruction')}")

    def test_02_normal_call_not_tagged_as_arc(self):
        """A non-ARC call (memcpy) must NOT be flagged arc_bookkeeping
        even though its hexdump shape is identical to ARC's."""
        line = self._find_call_line("__memcpy_aarch64_simd")
        r = self.client.call_tool("trace_hexblock", {"line": line})
        self.assertEqual(r["status"], "ok", r)
        body = json.loads(r["stdout"].splitlines()[0])
        self.assertEqual(body.get("call_kind"), "normal",
                         f"memcpy must stay normal: {body}")
        self.assertNotIn("arc_warning", body)


class TestF17ConstscanSimdAugmentation(unittest.TestCase):
    """FIX F-17 (v0.9.6): trace_constscan post-processing detects NEON
    `movi v*.16b, #0x36/0x5c` HMAC pad broadcasts that the scalar C
    engine misses, and emits a per-block hint so agents stop dividing
    MD5.T[i] / SHA256.K[i] hit counts by 4 / 16 / 64."""

    @classmethod
    def setUpClass(cls):
        if not _ensure_binary():
            raise unittest.SkipTest(f"ak_search not built at {AK_SEARCH}")
        cls.client = MCPClient()
        trace = FIXTURES / "v096-arc-and-simd.trace"
        r = cls.client.call_tool("bind_trace",
                                 {"path": str(trace), "mode": "general"})
        if r.get("status") != "ok":
            raise unittest.SkipTest(f"bind_trace failed: {r}")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "client"):
            cls.client.close()

    def _summary(self) -> dict:
        r = self.client.call_tool("trace_constscan", {})
        self.assertEqual(r["status"], "ok", r)
        body = json.loads(r["stdout"].splitlines()[0])
        self.assertEqual(body.get("type"), "constscan")
        return body

    def test_01_simd_movi_fingerprints_appended(self):
        body = self._summary()
        fps = {h.get("fingerprint"): h for h in body.get("hits", [])}
        # Fixture contains 2 `movi v0.16b, #0x36` and 2 `movi v1.16b, #0x5c`.
        ipad = fps.get("HMAC.ipad.simd_movi")
        opad = fps.get("HMAC.opad.simd_movi")
        self.assertIsNotNone(ipad, f"missing HMAC.ipad.simd_movi: keys={list(fps)}")
        self.assertIsNotNone(opad, f"missing HMAC.opad.simd_movi: keys={list(fps)}")
        self.assertEqual(ipad["total_hits"], 2, ipad)
        self.assertEqual(opad["total_hits"], 2, opad)
        self.assertEqual(ipad["verdict"], "real_simd")
        self.assertEqual(opad["verdict"], "real_simd")
        # Sample lines must be present so the agent can verify.
        self.assertGreaterEqual(len(ipad["sample_lines"]), 1)
        self.assertGreaterEqual(len(opad["sample_lines"]), 1)

    def test_02_hmac_estimate_from_simd(self):
        body = self._summary()
        est = body.get("hmac_estimate")
        self.assertIsNotNone(est, f"hmac_estimate missing: {list(body)}")
        self.assertEqual(est.get("simd_movi_ipad"), 2)
        self.assertEqual(est.get("simd_movi_opad"), 2)
        # SIMD takes precedence over scalar when present.
        self.assertEqual(est.get("estimated_hmac_calls"), 2)
        self.assertIn("simd_movi", est.get("estimate_basis", ""))

    def test_03_block_count_hints_for_md5_T(self):
        body = self._summary()
        hints = body.get("block_count_hints") or []
        by_fp = {h.get("fingerprint"): h for h in hints}
        # Fixture has 1 MD5.T[1..4] ldr each → block_count_estimate=1.
        for k in ("MD5.T[1]", "MD5.T[2]", "MD5.T[3]", "MD5.T[4]"):
            h = by_fp.get(k)
            self.assertIsNotNone(h, f"missing block_count_hint for {k}: keys={list(by_fp)}")
            self.assertEqual(h["block_count_estimate"], 1, h)
            self.assertEqual(h["primitive"], "MD5")
            # Note must explicitly warn against the /4 /16 /64 mistake.
            self.assertIn("Do NOT divide", h["note"])

    def test_04_augmentation_note_present(self):
        body = self._summary()
        self.assertIn("FIX F-17", body.get("augmentation_note", ""))


class TestL3LedgerEndToEnd(unittest.TestCase):
    """L3: anti-hallucination scaffold runs end-to-end in the real JSON-RPC
    path. Validates that FIX #1–#4 are not just unit-test artefacts."""

    @classmethod
    def setUpClass(cls):
        if not _ensure_binary():
            raise unittest.SkipTest(f"ak_search not built at {AK_SEARCH}")
        cls.client = MCPClient()
        trace = FIXTURES / "sprint5-constscan.trace"
        r = cls.client.call_tool("bind_trace",
                                 {"path": str(trace), "mode": "ciphertext"})
        if r.get("status") != "ok":
            raise unittest.SkipTest(f"bind_trace failed: {r}")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "client"):
            cls.client.close()

    def _gather_evidence(self):
        """Run two distinct trace tools and capture verbatim excerpts."""
        constscan = self.client.call_tool("trace_constscan", {})
        self.assertEqual(constscan["status"], "ok", constscan)
        cid1 = constscan["_tool_call_id"]
        # Pick something verbatim from the output (>=8 chars).
        excerpt1 = constscan["stdout"][:80]
        self.assertGreater(len(excerpt1), 8)

        callgraph = self.client.call_tool("trace_callgraph", {"top": 5})
        self.assertEqual(callgraph["status"], "ok", callgraph)
        cid2 = callgraph["_tool_call_id"]
        excerpt2 = callgraph["stdout"][:80] or '"type":"callgraph"'
        return cid1, excerpt1, cid2, excerpt2

    def test_anti_hallucination_full_path(self):
        cid1, excerpt1, cid2, excerpt2 = self._gather_evidence()

        # ---- Step 1: hypothesis_add with real evidence (FIX #1 path) ----
        r = self.client.call_tool("hypothesis_add", {
            "statement": "Trace performs a SHA-256-family computation",
            "confidence": "low",
            "falsification_plan": (
                "trace_callgraph --top must show no hash-related symbol "
                "and trace_constscan must report no SHA hits."),
            "supporting": [
                {"tool_call_id": cid1, "excerpt": excerpt1},
                {"tool_call_id": cid2, "excerpt": excerpt2},
            ],
        })
        self.assertEqual(r["status"], "ok", r)
        hid = r["hypothesis"]["id"]
        # FIX #3 anchor: tool_name derived server-side.
        names = {ev["tool_name"] for ev in r["hypothesis"]["supporting"]}
        self.assertEqual(names, {"trace_constscan", "trace_callgraph"})

        # ---- Step 2: try conclude(high) — must reject (FIX gates) ----
        r = self.client.call_tool("hypothesis_conclude", {
            "id": hid,
            "final_statement": "SHA-256 confirmed (premature)",
            "final_confidence": "high",
        })
        self.assertEqual(r["status"], "error", r)
        # supporting-count gate triggers first (only 2 supporting)
        err = r["error"]
        self.assertIn(">=3 supporting", err)

        # ---- Step 3: add a 3rd supporting from yet another tool ----
        lint = self.client.call_tool("trace_lint", {})
        self.assertEqual(lint["status"], "ok", lint)
        excerpt3 = lint["stdout"][:80]
        r = self.client.call_tool("hypothesis_update", {
            "id": hid,
            "add_supporting": [
                {"tool_call_id": lint["_tool_call_id"], "excerpt": excerpt3},
            ],
        })
        self.assertEqual(r["status"], "ok", r)

        # ---- Step 4: count passes but FIX #5 falsification_evidence missing ----
        r = self.client.call_tool("hypothesis_conclude", {
            "id": hid,
            "final_statement": "SHA-256 family computation present",
            "final_confidence": "high",
        })
        self.assertEqual(r["status"], "error", r)
        self.assertIn("falsification_evidence", r["error"])

        # ---- Step 5a: FIX #5 boolean-only NOT sufficient anymore ----
        r = self.client.call_tool("hypothesis_update", {
            "id": hid,
            "falsification_attempted": True,
        })
        self.assertEqual(r["status"], "ok", r)
        # FIX #5 warning should surface
        self.assertIn("warning", r)
        r = self.client.call_tool("hypothesis_conclude", {
            "id": hid,
            "final_statement": "SHA-256 family computation present",
            "final_confidence": "high",
        })
        self.assertEqual(r["status"], "error", r)
        self.assertIn("falsification_evidence", r["error"])

        # ---- Step 5b: run a real falsification experiment + cite it ----
        falsify_lint = self.client.call_tool("trace_lint", {})
        self.assertEqual(falsify_lint["status"], "ok", falsify_lint)
        falsify_excerpt = falsify_lint["stdout"][:80]
        r = self.client.call_tool("hypothesis_update", {
            "id": hid,
            "falsification_evidence": {
                "tool_call_id": falsify_lint["_tool_call_id"],
                "excerpt": falsify_excerpt,
            },
        })
        self.assertEqual(r["status"], "ok", r)

        # ---- Step 5c: FIX #6 reviewer gate ----
        r = self.client.call_tool("hypothesis_conclude", {
            "id": hid,
            "final_statement": "SHA-256 family computation present",
            "final_confidence": "high",
        })
        self.assertEqual(r["status"], "error", r)
        self.assertIn("reviewer", r["error"].lower())

        # Now spawn the reviewer verdict (in real usage this is the
        # hypothesis-reviewer sub-agent; in the test we call directly).
        r = self.client.call_tool("mark_hypothesis_reviewed", {
            "id": hid,
            "verdict": "confirm",
            "reason": "all gates audited; evidence excerpts verified",
        })
        self.assertEqual(r["status"], "ok", r)

        # ---- Step 6: conclude(high) finally succeeds ----
        r = self.client.call_tool("hypothesis_conclude", {
            "id": hid,
            "final_statement": "SHA-256 family computation present in trace",
            "final_confidence": "high",
        })
        self.assertEqual(r["status"], "ok", r)
        self.assertEqual(r["hypothesis"]["confidence"], "high")

        # ---- Step 7: write_artifact citing [H<id>] (FIX A-8 bracket form) → ok ----
        artifact_body = (
            f"# Findings\n\nSHA-256 family computation found in trace; see [{hid}].\n"
        )
        r = self.client.call_tool("write_artifact", {
            "path": "findings.md", "content": artifact_body,
        })
        self.assertEqual(r["status"], "ok", r)
        self.assertTrue(Path(r["path"]).exists())

        # ---- Step 8: write_artifact bypassing ledger → reject ----
        bypass_body = (
            "# Long report\n\n"
            + ("Lorem ipsum dolor sit amet, consectetur adipiscing elit. " * 20)
        )
        r = self.client.call_tool("write_artifact", {
            "path": "bypass.md", "content": bypass_body,
        })
        self.assertEqual(r["status"], "error", r)
        self.assertIn("bypasses hypothesis ledger", r["error"])

        # ---- Step 9 (FIX #7): hypothesis_archive lets the agent exempt
        # non-load-bearing concluded hypotheses from the bypass gate. ----
        r = self.client.call_tool("hypothesis_archive", {
            "id": hid,
            "reason": "exclusion analysis; not load-bearing for final report",
        })
        self.assertEqual(r["status"], "ok", r)
        self.assertEqual(r["hypothesis"]["state"], "archived")
        # Now the bypass body should NOT be rejected (no remaining concluded).
        r = self.client.call_tool("write_artifact", {
            "path": "no-citation.md", "content": bypass_body,
        })
        self.assertEqual(r["status"], "ok", r)

    def test_invalid_excerpt_rejected_in_e2e_path(self):
        """FIX #1 must reject fabricated evidence over JSON-RPC, not just
        from in-process unit calls."""
        r = self.client.call_tool("hypothesis_add", {
            "statement": "Trace performs MD5 computation",
            "confidence": "low",
            "falsification_plan": "trace_callgraph would show no md5",
            "supporting": [
                {"tool_call_id": 1,
                 "excerpt": "this string was never in any tool output"},
            ],
        })
        self.assertEqual(r["status"], "error", r)
        self.assertIn("NOT found in tool_call_id", r["error"])


if __name__ == "__main__":
    unittest.main()
