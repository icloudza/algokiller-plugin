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


def _make_session(tmpdir: Path, ledger: dict, *, artifacts: list[str] = ()) -> Path:
    """Build a fake session directory that ``_find_latest_session``
    will discover via the Documents fallback path."""
    documents = tmpdir / "Documents"
    base = documents / "AlgoKiller-Reports" / "trace42" / "20990101_120000"
    base.mkdir(parents=True)
    (base / "ledger.json").write_text(json.dumps(ledger), encoding="utf-8")
    for name in artifacts:
        (base / name).write_text("x", encoding="utf-8")
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
