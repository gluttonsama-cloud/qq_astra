"""Platform dispatch contracts on Linux; these do not validate Windows ACLs."""

import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from . import state


class PlatformStateTests(unittest.TestCase):
    def setUp(self):
        self.windows_error = type("WindowsStateError", (RuntimeError,), {})
        self.windows_locked = type("WindowsStateLocked", (self.windows_error,), {})
        self.backend = types.SimpleNamespace(WindowsStateError=self.windows_error,
            WindowsStateLocked=self.windows_locked, read_secret_file=MagicMock(return_value="synthetic"),
            read_public_key_file=MagicMock(return_value=b'{"keys":[]}'),
            default_state_directory=MagicMock(return_value=Path("synthetic-default")),
            WindowsPrivateDirectory=MagicMock())
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules, {"bridge_service.windows_state": self.backend}).start()
        patch.object(state, "_WINDOWS", True).start()

    def test_windows_reads_use_checked_backend_and_never_posix_fallback(self):
        self.assertEqual(state.default_state_directory(), Path("synthetic-default"))
        self.assertEqual(state.read_secret_file("synthetic", 100), "synthetic")
        self.assertEqual(state.read_public_key_file("synthetic", 100), b'{"keys":[]}')
        self.backend.read_secret_file.assert_called_once_with("synthetic", max_bytes=100)
        self.backend.read_public_key_file.assert_called_once_with("synthetic", max_bytes=100)
        for reader, mock in ((state.read_secret_file, self.backend.read_secret_file),
                             (state.read_public_key_file, self.backend.read_public_key_file)):
            mock.side_effect = self.windows_error("synthetic rejection")
            with self.assertRaises(state.StateError):
                reader("synthetic")

    def test_windows_lock_and_acl_failures_close_without_creating_database(self):
        with tempfile.TemporaryDirectory() as root:
            for error, expected in ((self.windows_locked, state.StateLocked), (self.windows_error, state.StateError)):
                directory = MagicMock()
                directory.acquire_lock.side_effect = error("synthetic rejection")
                self.backend.WindowsPrivateDirectory.return_value = directory
                with self.assertRaises(expected):
                    with state.StateDirectory(Path(root) / "state"):
                        pass
                directory.open.assert_called_once()
                directory.close.assert_called_once()
                directory.create_file.assert_not_called()
                self.assertFalse((Path(root) / "state" / "bridge.sqlite3").exists())


if __name__ == "__main__":
    unittest.main()
