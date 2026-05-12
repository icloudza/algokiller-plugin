"""Unit tests for the hook scripts shipped in ``hooks/``.

We don't drive the actual Claude Code hook protocol from CI — that
requires a live Desktop session. Instead we exercise the helpers the
shell wrappers delegate to (``dump-session-state.py``,
``write-session-summary.py``, ``pre-write-artifact.py``,
``lock-check.py``, ``validate-reviewer.py``) directly in-process by
exec'ing them into a private namespace and probing the public
functions.

This catches the high-frequency breakages: imports drift, schema
changes in the ledger file, hyphenated-filename pitfalls.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_REPO = Path(__file__).resolve().parent.parent.parent
_HOOKS = _REPO / "hooks"
_SERVER = _REPO / "server"
for p in (_SERVER, _HOOKS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))


def _load_hook(filename: str) -> dict:
    """Exec a hooks/*.py file into a private namespace; return the
    namespace so individual helper functions are addressable."""
    path = _HOOKS / filename
    if not path.is_file():
        raise FileNotFoundError(path)
    ns: dict = {"__file__": str(path)}
    exec(path.read_text(encoding="utf-8"), ns)  # noqa: S102
    return ns


def _make_session(tmpdir: Path, ledger: dict, *, artifacts: list[str] = (),
                  tool_calls: list[dict] = ()) -> Path:
    """Build a fake session directory that ``_find_latest_session``
    will discover via the Documents fallback path.

    ``tool_calls`` lets a test seed the ``tool_call_log/`` subdir with
    fake records so ``_read_tool_call_log`` returns the expected
    recent-call summary in the snapshot."""
    documents = tmpdir / "Documents"
    base = documents / "AlgoKiller-Reports" / "trace42" / "20990101_120000"
    base.mkdir(parents=True)
    (base / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
    for name in artifacts:
        (base / name).write_text("x", encoding="utf-8")
    if tool_calls:
        log_dir = base / "tool_call_log"
        log_dir.mkdir()
        for rec in tool_calls:
            cid = int(rec["id"])
            (log_dir / f"{cid:06d}.json").write_text(
                json.dumps(rec), encoding="utf-8")
    return base


class TestDumpSessionState(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_summarise_only_concluded_hypotheses(self):
        ns = _load_hook("dump-session-state.py")
        session = _make_session(self.root, ledger={
            "hypotheses": [
                {"id": "H1", "state": "concluded",
                 "final_confidence": "high",
                 "final_statement": "AES-128 ECB confirmed"},
                {"id": "H2", "state": "active",
                 "statement": "GCM mode candidate"},
                {"id": "H3", "state": "abandoned",
                 "statement": "RC4 hypothesis"},
            ]
        }, artifacts=["recovered.py", "report.md"])
        ledger = ns["_read_ledger"](session)
        payload = ns["_summarise"](session, ledger)
        self.assertEqual(len(payload["concluded_hypotheses"]), 1)
        self.assertEqual(payload["concluded_hypotheses"][0]["id"], "H1")
        self.assertEqual(set(payload["artifacts_written"]),
                         {"recovered.py", "report.md"})

    def test_find_latest_session_in_documents(self):
        ns = _load_hook("dump-session-state.py")
        session = _make_session(self.root, ledger={"hypotheses": []})
        with mock.patch("pathlib.Path.home", return_value=self.root):
            found = ns["_find_latest_session"]()
        self.assertIsNotNone(found)
        self.assertEqual(Path(found).resolve(), session.resolve())

    def test_summarise_includes_active_and_rejected(self):
        """B1 — the snapshot must expose ``active_hypotheses`` and
        ``rejected_hypotheses`` (abandoned + archived). Pre-B1 the
        snapshot only carried concluded hypotheses, which is what made
        post-compact rehydration miss the "mid-verification" state and
        the "do not walk back" list."""
        ns = _load_hook("dump-session-state.py")
        session = _make_session(self.root, ledger={
            "hypotheses": [
                {"id": "H1", "state": "concluded",
                 "final_confidence": "high",
                 "final_statement": "AES-128 ECB confirmed"},
                {"id": "H2", "state": "active",
                 "confidence": "medium",
                 "statement": "Maybe SM3 main compression",
                 "supporting": [
                     {"tool_call_id": 7, "excerpt": "movi v0.16b, #0x36"},
                 ]},
                {"id": "H3", "state": "abandoned",
                 "statement": "RC4 hypothesis",
                 "abandon_reason": "no S-box init found"},
                {"id": "H4", "state": "archived",
                 "statement": "ChaCha20 hypothesis",
                 "archive_reason": "not load-bearing"},
            ]
        })
        ledger = ns["_read_ledger"](session)
        payload = ns["_summarise"](session, ledger)
        self.assertEqual(payload["schema"], 2)
        # Concluded still present (existing contract).
        self.assertEqual(len(payload["concluded_hypotheses"]), 1)
        self.assertEqual(payload["concluded_hypotheses"][0]["id"], "H1")
        # Active hypothesis with latest_evidence anchor.
        self.assertEqual(len(payload["active_hypotheses"]), 1)
        active = payload["active_hypotheses"][0]
        self.assertEqual(active["id"], "H2")
        self.assertEqual(active["supporting_count"], 1)
        self.assertIn("tc#7", active["latest_evidence"])
        self.assertIn("movi", active["latest_evidence"])
        # Both abandoned + archived go into the same rejected bucket so
        # the model has a single "do not walk back" list.
        rejected_ids = {h["id"] for h in payload["rejected_hypotheses"]}
        self.assertEqual(rejected_ids, {"H3", "H4"})

    def test_summarise_reads_recent_tool_calls(self):
        """B1 — recent_tool_calls comes from ``tool_call_log/`` and
        carries ``{id, tool, args, hits}``. The hits field is a cheap
        substring-extracted signal from the cached result_text; it
        gives the model a "did I already run this and get 0 hits?"
        answer without re-running the tool."""
        ns = _load_hook("dump-session-state.py")
        session = _make_session(
            self.root,
            ledger={"hypotheses": []},
            tool_calls=[
                {"id": 1, "tool_name": "trace_lint", "args": {},
                 "result_text": '{"format_ok": true, "warnings": []}'},
                {"id": 2, "tool_name": "trace_constscan",
                 "args": {"limit": 50},
                 "result_text": '{"total_hits": 42, "fingerprints": []}'},
                {"id": 3, "tool_name": "trace_search",
                 "args": {"query": "0xdeadbeef", "limit": 10},
                 "result_text": '{"hits": 0, "results": []}'},
            ])
        ledger = ns["_read_ledger"](session)
        payload = ns["_summarise"](session, ledger)
        calls = payload["recent_tool_calls"]
        self.assertEqual(len(calls), 3)
        # Chronological order (oldest first) — easier to read.
        self.assertEqual([c["id"] for c in calls], [1, 2, 3])
        # Hit counts extracted from the cached JSON.
        self.assertEqual(calls[1]["hits"], 42)
        self.assertEqual(calls[2]["hits"], 0)
        # Args are short-stringified.
        self.assertIn("0xdeadbeef", calls[2]["args"])

    def test_main_writes_both_json_and_md(self):
        """B1 — ``main()`` produces both ``_compact_state.json`` and
        ``_compact_state.md``. The md form is what gets cat-injected
        post-compact; the json form is for ``verify_hypothesis`` /
        ``ak:status`` tooling to read programmatically."""
        ns = _load_hook("dump-session-state.py")
        session = _make_session(self.root, ledger={
            "hypotheses": [
                {"id": "H1", "state": "concluded",
                 "final_confidence": "medium",
                 "final_statement": "SHA-256 confirmed"},
                {"id": "H2", "state": "active",
                 "confidence": "low",
                 "statement": "HMAC variant TBD",
                 "supporting": []},
            ]
        }, tool_calls=[
            {"id": 1, "tool_name": "trace_constscan",
             "args": {"limit": 100},
             "result_text": '{"total_hits": 7}'},
        ])
        with mock.patch("pathlib.Path.home", return_value=self.root):
            rc = ns["main"]()
        self.assertEqual(rc, 0)
        json_path = session / "_compact_state.json"
        md_path = session / "_compact_state.md"
        self.assertTrue(json_path.is_file())
        self.assertTrue(md_path.is_file())
        md = md_path.read_text(encoding="utf-8")
        # All four required sections present in the rendered md.
        self.assertIn("### Active Hypotheses", md)
        self.assertIn("### Concluded Hypotheses", md)
        self.assertIn("### Rejected Paths", md)
        self.assertIn("### Tool Call Ledger", md)
        # C1 discipline reminder embedded so it survives compact even
        # if the static post-compact-rules.md cat got dropped.
        self.assertIn("hypothesis_list", md)


class TestPreWriteArtifact(unittest.TestCase):
    """The hook should warn (NOT block) when [H<n>] citations in the
    draft don't cover the ledger's concluded set."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, payload: dict, ledger: dict) -> tuple[int, str]:
        session = _make_session(self.root, ledger=ledger)
        ns = _load_hook("pre-write-artifact.py")
        with mock.patch("pathlib.Path.home", return_value=self.root), \
             mock.patch.object(sys, "stdin",
                               mock.Mock(read=lambda: json.dumps(payload))):
            buf = []
            with mock.patch.object(sys, "stderr",
                                   mock.Mock(write=lambda s: buf.append(s))):
                rc = ns["main"]()
            return rc, "".join(buf)

    def test_missing_citations_emits_warning(self):
        rc, stderr = self._run(
            payload={
                "tool_name": "mcp__plugin_ak_ak__write_artifact",
                "tool_input": {"content": "Report cites [H1] only.\n"},
            },
            ledger={"hypotheses": [
                {"id": "H1", "state": "concluded"},
                {"id": "H2", "state": "concluded"},
            ]},
        )
        self.assertEqual(rc, 0, "hook must NEVER block; only warn")
        self.assertIn("missing citations", stderr)
        self.assertIn("H2", stderr)

    def test_complete_citations_no_warning(self):
        rc, stderr = self._run(
            payload={
                "tool_name": "mcp__plugin_ak_ak__write_artifact",
                "tool_input": {"content": "Cites [H1] and [H2].\n"},
            },
            ledger={"hypotheses": [
                {"id": "H1", "state": "concluded"},
                {"id": "H2", "state": "concluded"},
            ]},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(stderr, "")

    def test_non_write_artifact_call_ignored(self):
        """The hook fires on ALL PreToolUse — must no-op on non-target tools."""
        rc, stderr = self._run(
            payload={
                "tool_name": "mcp__plugin_ak_ak__trace_search",
                "tool_input": {"query": "0xdeadbeef"},
            },
            ledger={"hypotheses": [{"id": "H1", "state": "concluded"}]},
        )
        self.assertEqual(rc, 0)
        self.assertEqual(stderr, "")


class TestValidateReviewer(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, payload: dict, ledger: dict) -> str:
        _make_session(self.root, ledger=ledger)
        ns = _load_hook("validate-reviewer.py")
        with mock.patch("pathlib.Path.home", return_value=self.root), \
             mock.patch.object(sys, "stdin",
                               mock.Mock(read=lambda: json.dumps(payload))):
            buf = []
            with mock.patch.object(sys, "stderr",
                                   mock.Mock(write=lambda s: buf.append(s))):
                ns["main"]()
            return "".join(buf)

    def test_reviewer_returned_without_marking_warns(self):
        stderr = self._run(
            payload={"subagent": "hypothesis-reviewer"},
            ledger={"hypotheses": [{"id": "H1", "state": "active"}]},
        )
        self.assertIn("without calling mark_hypothesis_reviewed", stderr)

    def test_reviewer_with_mark_silent(self):
        stderr = self._run(
            payload={"subagent": "hypothesis-reviewer"},
            ledger={"hypotheses": [
                {"id": "H1", "state": "concluded",
                 "reviewed_at_tool_call": 42},
            ]},
        )
        self.assertEqual(stderr, "")

    def test_non_reviewer_subagent_ignored(self):
        stderr = self._run(
            payload={"subagent": "trace-hexdump-extractor"},
            ledger={"hypotheses": [{"id": "H1", "state": "active"}]},
        )
        self.assertEqual(stderr, "")


class TestHooksJsonRegistration(unittest.TestCase):
    """Make sure every hook entry in hooks.json points at a script
    that actually exists. Catches typos when adding new hooks."""

    def test_every_command_references_existing_script(self):
        cfg = json.loads((_REPO / "hooks" / "hooks.json").read_text())
        missing = []
        for hook_type, entries in cfg["hooks"].items():
            for entry in entries:
                for h in entry["hooks"]:
                    cmd = h["command"]
                    # Extract the path from `bash "...${CLAUDE_PLUGIN_ROOT}/X/Y/Z.sh"`
                    # by stripping the env-var prefix.
                    if "${CLAUDE_PLUGIN_ROOT}/" not in cmd:
                        continue
                    rel = cmd.split("${CLAUDE_PLUGIN_ROOT}/", 1)[1].rstrip('"')
                    script = _REPO / rel
                    if not script.is_file():
                        missing.append((hook_type, str(script)))
        self.assertEqual(missing, [],
                         f"hooks.json references missing files: {missing}")


if __name__ == "__main__":
    unittest.main()
