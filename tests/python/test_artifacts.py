"""Regression tests for ArtifactStore — path-escape guards + per-write
timestamping + notes sidecar."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

from artifacts import ArtifactStore  # noqa: E402


class TestArtifactStorePathSafety(unittest.TestCase):

    def test_absolute_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), mode="ciphertext")
            r = store.write("/etc/passwd_replacement", "hi")
            self.assertEqual(r["status"], "error")
            self.assertIn("must be relative", r["error"])

    def test_directory_escape_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td) / "session", mode="general")
            # parent of session/ exists, so a ../ would resolve to td
            r = store.write("../escape.py", "hi")
            self.assertEqual(r["status"], "error")
            self.assertIn("escapes artifacts directory", r["error"])

    def test_empty_path_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), mode="ciphertext")
            r = store.write("", "hi")
            self.assertEqual(r["status"], "error")
            self.assertIn("must not be empty", r["error"])


class TestArtifactStoreWrite(unittest.TestCase):

    def test_write_stamps_mode_and_timestamp(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), mode="ciphertext")
            r = store.write("recovered.py", "print('hi')\n")
            self.assertEqual(r["status"], "ok", r)
            out = Path(r["path"])
            self.assertTrue(out.exists())
            self.assertTrue(out.name.startswith("recovered_CIPHERTEXT_"))
            self.assertTrue(out.name.endswith(".py"))

    def test_notes_writes_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), mode="general")
            r = store.write("report.md", "# Findings\n",
                            notes="evidence: H1, H2, H3")
            self.assertEqual(r["status"], "ok", r)
            self.assertIsNotNone(r["notes_path"])
            notes = Path(r["notes_path"]).read_text(encoding="utf-8")
            self.assertEqual(notes, "evidence: H1, H2, H3")

    def test_repeated_write_deduplicates(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), mode="ciphertext")
            r1 = store.write("dup.py", "v1")
            r2 = store.write("dup.py", "v2")
            self.assertEqual(r1["status"], "ok", r1)
            self.assertEqual(r2["status"], "ok", r2)
            self.assertNotEqual(r1["path"], r2["path"])
            self.assertTrue(Path(r1["path"]).exists())
            self.assertTrue(Path(r2["path"]).exists())

    def test_mode_normalisation(self):
        with tempfile.TemporaryDirectory() as td:
            # weird chars get sanitised into _
            store = ArtifactStore(Path(td), mode="ci/pher;text")
            r = store.write("a.py", "x")
            self.assertEqual(r["status"], "ok", r)
            self.assertIn("CI_PHER_TEXT", Path(r["path"]).name)


class TestArtifactStoreList(unittest.TestCase):

    def test_list_returns_size_and_mtime(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), mode="ciphertext")
            store.write("one.py", "x")
            store.write("two.md", "y", notes="note")
            items = store.list_all()
            self.assertGreaterEqual(len(items), 2)
            for it in items:
                self.assertIn("path", it)
                self.assertIn("size", it)
                self.assertIn("mtime", it)


class TestArtifactStoreRead(unittest.TestCase):

    def test_read_inside_base_dir(self):
        with tempfile.TemporaryDirectory() as td:
            store = ArtifactStore(Path(td), mode="ciphertext")
            r = store.write("hello.py", "print('hi')\n")
            text = store.read(r["path"])
            self.assertEqual(text, "print('hi')\n")

    def test_read_outside_base_dir_rejected(self):
        with tempfile.TemporaryDirectory() as td_a, \
             tempfile.TemporaryDirectory() as td_b:
            store = ArtifactStore(Path(td_a), mode="ciphertext")
            other = Path(td_b) / "x.py"
            other.write_text("not yours")
            with self.assertRaises(ValueError):
                store.read(str(other))


if __name__ == "__main__":
    unittest.main()
