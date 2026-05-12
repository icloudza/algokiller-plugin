"""Unit tests for server.output_dir.resolve_output_dir — the 5-priority
chain that decides where a session's analysis artifacts get written.

All 5 priorities are exercised on a temp filesystem so the tests run
hermetically regardless of where the developer's real HOME / Documents
point. The picker module is tested separately (test_picker.py).
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from output_dir import resolve_output_dir, _find_project_root, PROJECT_MARKERS  # noqa: E402


_FIXED_STAMP = "20990101_000000"


def _stamp() -> str:
    return _FIXED_STAMP


class TestResolveOutputDir(unittest.TestCase):
    """Cover every branch of the 5-priority chain."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()
        # Trace lives in a non-project tmp subdir by default; individual
        # tests opt in to project structure when they need it.
        self.trace_dir = self.root / "captures"
        self.trace_dir.mkdir()
        self.trace = self.trace_dir / "login.log"
        self.trace.write_text("synthetic")

    def tearDown(self):
        self.tmp.cleanup()

    # ─── priority 1: explicit argument ────────────────────────────────

    def test_priority_1_explicit_wins(self):
        explicit = self.root / "custom_reports"
        r = resolve_output_dir(self.trace, explicit=str(explicit),
                               env={}, now_stamp_fn=_stamp)
        self.assertEqual(r.source, "explicit")
        self.assertEqual(r.path, explicit / "login" / _FIXED_STAMP)

    def test_priority_1_relative_explicit_rejected(self):
        with self.assertRaises(ValueError) as cm:
            resolve_output_dir(self.trace, explicit="relative/path",
                               env={}, now_stamp_fn=_stamp)
        self.assertIn("must be an absolute path", str(cm.exception))

    def test_priority_1_unwritable_rejected(self):
        # /nonexistent_root_for_test/... has an unwritable root.
        with self.assertRaises(ValueError) as cm:
            resolve_output_dir(self.trace,
                               explicit="/nonexistent_root_for_test/foo",
                               env={}, now_stamp_fn=_stamp)
        self.assertIn("not writable", str(cm.exception))

    # ─── priority 2: $ALGOKILLER_OUTPUT_DIR ────────────────────────────

    def test_priority_2_env_var(self):
        env_dir = self.root / "env_reports"
        r = resolve_output_dir(self.trace, explicit=None,
                               env={"ALGOKILLER_OUTPUT_DIR": str(env_dir)},
                               now_stamp_fn=_stamp)
        self.assertEqual(r.source, "env")
        self.assertEqual(r.path, env_dir / "login" / _FIXED_STAMP)

    def test_priority_2_explicit_overrides_env(self):
        env_dir = self.root / "env_reports"
        explicit = self.root / "explicit_reports"
        r = resolve_output_dir(self.trace, explicit=str(explicit),
                               env={"ALGOKILLER_OUTPUT_DIR": str(env_dir)},
                               now_stamp_fn=_stamp)
        self.assertEqual(r.source, "explicit")
        self.assertNotIn("env_reports", str(r.path))

    # ─── priority 3: .algokiller.toml ──────────────────────────────────

    def test_priority_3_algokiller_toml(self):
        project = self.root / "myproj"
        project.mkdir()
        (project / ".git").mkdir()  # makes it a valid project root
        config_out = project / "build" / "reports"
        (project / ".algokiller.toml").write_text(
            f'[output]\ndir = "{config_out}"\n', encoding="utf-8")
        trace = project / "captures" / "tok.log"
        trace.parent.mkdir()
        trace.write_text("synthetic")

        r = resolve_output_dir(trace, explicit=None, env={},
                               now_stamp_fn=_stamp)
        self.assertEqual(r.source, "project_config")
        self.assertEqual(r.path, config_out / "tok" / _FIXED_STAMP)
        self.assertEqual(r.project_root, project)

    def test_priority_3_relative_config_dir(self):
        """Relative paths in .algokiller.toml resolve against project root."""
        project = self.root / "myproj2"
        project.mkdir()
        (project / ".git").mkdir()
        (project / ".algokiller.toml").write_text(
            '[output]\ndir = "_reports"\n', encoding="utf-8")
        trace = project / "tok.log"
        trace.write_text("synthetic")

        r = resolve_output_dir(trace, explicit=None, env={},
                               now_stamp_fn=_stamp)
        self.assertEqual(r.source, "project_config")
        self.assertEqual(r.path,
                         (project / "_reports" / "tok" / _FIXED_STAMP).resolve())

    def test_priority_3_malformed_toml_falls_through_to_marker(self):
        """A broken .algokiller.toml shouldn't crash the resolver; the
        project_marker default should still apply."""
        project = self.root / "myproj3"
        project.mkdir()
        (project / ".git").mkdir()
        (project / ".algokiller.toml").write_text("this is not valid TOML !!",
                                                  encoding="utf-8")
        trace = project / "tok.log"
        trace.write_text("synthetic")
        r = resolve_output_dir(trace, explicit=None, env={},
                               now_stamp_fn=_stamp)
        self.assertEqual(r.source, "project_marker")
        self.assertEqual(r.path,
                         project / ".algokiller" / "tok" / _FIXED_STAMP)

    # ─── priority 4: project-marker walk-up ────────────────────────────

    def test_priority_4_git_marker(self):
        project = self.root / "git_project"
        project.mkdir()
        (project / ".git").mkdir()
        deep = project / "a" / "b" / "captures"
        deep.mkdir(parents=True)
        trace = deep / "x.log"
        trace.write_text("synthetic")

        r = resolve_output_dir(trace, explicit=None, env={},
                               now_stamp_fn=_stamp)
        self.assertEqual(r.source, "project_marker")
        self.assertEqual(r.project_root, project)
        self.assertEqual(r.path,
                         project / ".algokiller" / "x" / _FIXED_STAMP)

    def test_priority_4_walk_limit_respected(self):
        """A project marker 5+ levels above the trace's parent should NOT
        be picked up — too deep, prevents accidental writes into a
        far-up grand-parent project."""
        project = self.root / "deep_project"
        project.mkdir()
        (project / "pyproject.toml").write_text("[tool]\n")
        # parent / a / b / c / d / e / trace.log — 6 levels below project root
        deep = project / "a" / "b" / "c" / "d" / "e" / "f"
        deep.mkdir(parents=True)
        trace = deep / "x.log"
        trace.write_text("synthetic")

        r = resolve_output_dir(trace, explicit=None, env={},
                               now_stamp_fn=_stamp)
        # walk limit is 4; we fall through to Documents — that's the
        # whole point of the limit, to prevent spurious far-up matches.
        self.assertEqual(r.source, "documents")

    def test_priority_4_pyproject_marker(self):
        project = self.root / "py_proj"
        project.mkdir()
        (project / "pyproject.toml").write_text("[tool]\n")
        trace = project / "captures" / "x.log"
        trace.parent.mkdir()
        trace.write_text("synthetic")

        r = resolve_output_dir(trace, explicit=None, env={},
                               now_stamp_fn=_stamp)
        self.assertEqual(r.source, "project_marker")

    # ─── priority 5: Documents fallback ────────────────────────────────

    def test_priority_5_documents_fallback(self):
        """Trace with no project root in its ancestry → Documents."""
        # Synthesize a fake home so Documents lookup is hermetic.
        fake_home = self.root / "home"
        fake_documents = fake_home / "Documents"
        fake_documents.mkdir(parents=True)
        trace = self.root / "anywhere" / "x.log"
        trace.parent.mkdir()
        trace.write_text("synthetic")

        with mock.patch("output_dir.Path.home", return_value=fake_home):
            r = resolve_output_dir(trace, explicit=None, env={},
                                   now_stamp_fn=_stamp)
        self.assertEqual(r.source, "documents")
        self.assertEqual(r.path,
                         fake_documents / "AlgoKiller-Reports" /
                         "x" / _FIXED_STAMP)

    def test_priority_5_no_documents_falls_to_home(self):
        """Documents directory doesn't exist — drop one level lower to
        plain $HOME so reports are still discoverable."""
        fake_home = self.root / "rough_home"
        fake_home.mkdir()
        trace = self.root / "x.log"
        trace.write_text("synthetic")

        with mock.patch("output_dir.Path.home", return_value=fake_home):
            r = resolve_output_dir(trace, explicit=None, env={},
                                   now_stamp_fn=_stamp)
        self.assertEqual(r.source, "documents")
        self.assertEqual(r.path,
                         fake_home / "AlgoKiller-Reports" / "x" / _FIXED_STAMP)


class TestProjectMarkerCoverage(unittest.TestCase):
    """Spot-check that the marker list covers the major ecosystems —
    if someone removes one we want a loud failure rather than a silent
    coverage drop."""

    REQUIRED = {".git", "pyproject.toml", "package.json", "Cargo.toml",
                "go.mod", "Makefile", ".algokiller.toml"}

    def test_required_markers_present(self):
        missing = self.REQUIRED - set(PROJECT_MARKERS)
        self.assertFalse(missing, f"PROJECT_MARKERS is missing: {missing}")

    def test_find_project_root_handles_filesystem_root(self):
        """Walking up past the filesystem root must not loop or crash."""
        # /tmp/random_subdir/x — likely no project markers above it
        with tempfile.TemporaryDirectory() as td:
            sub = Path(td) / "deeply" / "nested"
            sub.mkdir(parents=True)
            result = _find_project_root(sub)
            # Either None (no marker), or something that exists; can't
            # be a path that doesn't exist.
            if result is not None:
                self.assertTrue(result.exists())


if __name__ == "__main__":
    unittest.main()
