"""Unit tests for ``server.locks`` — the kernel-flock-backed scan
lock that gates ``PreCompact``.

The kernel-level semantics make most failure modes impossible by
construction; what we CAN test in-process is:

* acquire/release lifecycle is idempotent and reference-counted
* probe from the same process matches the expected state
* metadata file carries valid PID + acquired_at + platform after acquire
* the ``in_progress`` probe correctly reports False after release

Tests touch ``~/.algokiller/active-scans.lock``. We monkey-patch
``LOCK_DIR`` / ``LOCK_FILE`` to a temp directory so the dev's real
lock isn't disturbed.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

import locks  # noqa: E402


class TestScanLock(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        # Redirect the module-level constants to our temp dir so we
        # don't fight with any real lock in the dev's $HOME.
        self._orig_lock_dir = locks.LOCK_DIR
        self._orig_lock_file = locks.LOCK_FILE
        locks.LOCK_DIR = self.root
        locks.LOCK_FILE = self.root / "active-scans.lock"

    def tearDown(self):
        # Always release any lock we acquired so subsequent tests start
        # clean even on assertion failure.
        try:
            locks.SCAN_LOCK.release()
        except Exception:
            pass
        locks.LOCK_DIR = self._orig_lock_dir
        locks.LOCK_FILE = self._orig_lock_file
        self.tmp.cleanup()

    def test_initial_state_not_in_progress(self):
        state = locks.is_scan_in_progress()
        self.assertFalse(state["in_progress"], state)

    def test_acquire_release_lifecycle(self):
        # Use a fresh lock object so we're not sharing state with the
        # singleton (other tests may have touched it).
        lock = locks.ScanLock()
        self.assertFalse(lock.held)
        ok = lock.acquire()
        self.assertTrue(ok)
        self.assertTrue(lock.held)
        lock.release()
        self.assertFalse(lock.held)

    def test_acquire_writes_metadata(self):
        lock = locks.ScanLock()
        lock.acquire()
        try:
            data = locks.LOCK_FILE.read_text(encoding="utf-8")
            meta = json.loads(data)
            self.assertEqual(meta["pid"], os.getpid())
            self.assertIn("acquired_at", meta)
            self.assertIn("platform", meta)
        finally:
            lock.release()

    def test_reentrant_acquire(self):
        """Calling acquire twice on the same instance bumps the ref
        count, NOT a double-lock. Release must be balanced."""
        lock = locks.ScanLock()
        self.assertTrue(lock.acquire())
        self.assertTrue(lock.acquire())  # re-entrant
        self.assertTrue(lock.held)
        lock.release()
        self.assertTrue(lock.held, "first release should NOT free the lock")
        lock.release()
        self.assertFalse(lock.held)

    def test_release_without_acquire_is_safe(self):
        """Defensive: release on a never-held lock is a no-op."""
        lock = locks.ScanLock()
        lock.release()  # should not raise
        self.assertFalse(lock.held)

    def test_probe_reports_in_progress_while_held(self):
        lock = locks.ScanLock()
        lock.acquire()
        try:
            # Probe from the SAME process: another ScanLock-like
            # check should see the lock as held. Cross-process probe
            # semantics are tested via subprocess in a separate test.
            # Within-process, the kernel typically grants the lock
            # because flock is process-scoped on POSIX. So we rely on
            # the metadata file as the indicator instead.
            self.assertTrue(locks.LOCK_FILE.exists())
            raw = locks.LOCK_FILE.read_text(encoding="utf-8")
            self.assertIn(f'"pid": {os.getpid()}', raw)
        finally:
            lock.release()

    @unittest.skipIf(sys.platform == "win32",
                     "subprocess flock interaction not tested on Windows here")
    def test_cross_process_probe_sees_lock(self):
        """When a different process holds the kernel lock, our probe
        reports in_progress=True. Spawn a Python subprocess that
        acquires + sleeps, then probe from this process."""
        import subprocess, time, textwrap
        lock_dir = str(self.root)
        helper = textwrap.dedent(f"""
            import sys, time, json
            sys.path.insert(0, {str(_SERVER)!r})
            import locks
            from pathlib import Path
            locks.LOCK_DIR = Path({lock_dir!r})
            locks.LOCK_FILE = Path({lock_dir!r}) / "active-scans.lock"
            lk = locks.ScanLock()
            lk.acquire()
            print("ACQUIRED", flush=True)
            time.sleep(2.0)
            lk.release()
        """).strip()
        proc = subprocess.Popen(
            [sys.executable, "-c", helper],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # Wait until child confirms acquisition
            line = proc.stdout.readline().strip()
            self.assertEqual(line, "ACQUIRED")
            state = locks.is_scan_in_progress()
            self.assertTrue(state["in_progress"], state)
            self.assertEqual(state.get("holder_pid"), proc.pid)
        finally:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        # After child exits, lock must report free again.
        state = locks.is_scan_in_progress()
        self.assertFalse(state["in_progress"],
                         "kernel should auto-release lock on child exit")


if __name__ == "__main__":
    unittest.main()
