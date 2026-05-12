"""Unit tests for server.picker.

We only exercise the platform-dispatch logic and the unsupported-fallback
path. The actual native dialog flow (osascript / PowerShell / zenity)
would require a GUI session and a human at the keyboard — those run
manually, not in CI.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

_SERVER = Path(__file__).resolve().parent.parent.parent / "server"
if str(_SERVER) not in sys.path:
    sys.path.insert(0, str(_SERVER))

import picker  # noqa: E402


class TestPickerDispatch(unittest.TestCase):

    def test_unknown_platform_unsupported(self):
        with mock.patch.object(picker.sys, "platform", "haiku"):
            r = picker.pick_directory()
        self.assertEqual(r["status"], "unsupported")
        self.assertIn("haiku", r["reason"])

    def test_linux_no_pickers_installed(self):
        """Linux with neither zenity nor kdialog on PATH → unsupported."""
        with mock.patch.object(picker.sys, "platform", "linux"), \
             mock.patch("picker.shutil.which", return_value=None):
            r = picker.pick_directory()
        self.assertEqual(r["status"], "unsupported")
        self.assertIn("zenity / kdialog", r["reason"])

    def test_macos_dispatches_to_osascript(self):
        """The macOS branch should attempt to invoke osascript."""
        called = {}

        def fake_run(cmd, *args, **kwargs):
            called["cmd0"] = cmd[0] if isinstance(cmd, list) else cmd
            from types import SimpleNamespace
            return SimpleNamespace(returncode=0, stdout="/tmp/chosen\n", stderr="")

        with mock.patch.object(picker.sys, "platform", "darwin"), \
             mock.patch("picker.subprocess.run", side_effect=fake_run):
            r = picker.pick_directory()
        self.assertEqual(called.get("cmd0"), "osascript")
        self.assertEqual(r["status"], "ok")
        self.assertEqual(r["path"], "/tmp/chosen")

    def test_macos_user_cancel(self):
        from types import SimpleNamespace

        def fake_run(*a, **kw):
            return SimpleNamespace(returncode=1, stdout="",
                                   stderr="execution error: User canceled. (-128)")

        with mock.patch.object(picker.sys, "platform", "darwin"), \
             mock.patch("picker.subprocess.run", side_effect=fake_run):
            r = picker.pick_directory()
        self.assertEqual(r["status"], "cancelled")

    def test_windows_dispatch(self):
        called = {}

        def fake_run(cmd, *a, **kw):
            called["cmd0"] = cmd[0]
            from types import SimpleNamespace
            return SimpleNamespace(returncode=0, stdout="C:\\Users\\me\\reports\r\n",
                                   stderr="")

        with mock.patch.object(picker.sys, "platform", "win32"), \
             mock.patch("picker.subprocess.run", side_effect=fake_run):
            r = picker.pick_directory()
        self.assertEqual(called.get("cmd0"), "powershell")
        self.assertEqual(r["status"], "ok")


if __name__ == "__main__":
    unittest.main()
