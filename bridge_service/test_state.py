"""Synthetic private-state tests; no real credentials, home files or network."""

import base64
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from .state import StateCipher, StateDirectory, StateError, StateLocked, default_state_directory, read_secret_file


class StateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "private"

    def test_private_permissions_and_fail_closed_paths(self):
        with patch.dict(os.environ, {"XDG_STATE_HOME": str(self.root)}):
            self.assertEqual(default_state_directory(), self.root / "qq-astra")
        with StateDirectory(self.path) as state:
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(state.db_path.stat().st_mode), 0o600)
        os.chmod(self.path, 0o755)
        with self.assertRaises(StateError):
            with StateDirectory(self.path):
                pass
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o755)
        os.chmod(self.path, 0o700)
        link = self.root / "linked"
        link.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(StateError):
            with StateDirectory(link):
                pass
        secret = self.root / "fixture-secret"
        secret.write_text("synthetic only\n")
        os.chmod(secret, 0o600)
        self.assertEqual(read_secret_file(secret), "synthetic only")
        os.chmod(secret, 0o400)
        self.assertEqual(read_secret_file(secret), "synthetic only")
        with patch("bridge_service.state.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaises(StateError):
                read_secret_file(secret)
        with self.assertRaises(StateError):
            read_secret_file(secret, max_bytes=4)
        link.unlink()
        link.symlink_to(secret)
        with self.assertRaises(StateError):
            read_secret_file(link)
        link.unlink()
        os.link(secret, link)
        with self.assertRaises(StateError):
            read_secret_file(link)
        link.unlink()
        os.chmod(secret, 0o644)
        with self.assertRaises(StateError):
            read_secret_file(secret)
        db_path = self.path / StateDirectory.DB_NAME
        os.chmod(db_path, 0o644)
        with self.assertRaises(StateError):
            with StateDirectory(self.path):
                pass
        self.assertEqual(stat.S_IMODE(db_path.stat().st_mode), 0o644)
        db_path.unlink()
        db_path.symlink_to(secret)
        with self.assertRaises(StateError):
            with StateDirectory(self.path):
                pass

    def test_exclusive_lock_across_processes_and_safe_release(self):
        code = """
import sys
from bridge_service.state import StateDirectory, StateLocked
try:
    with StateDirectory(sys.argv[1]):
        pass
except StateLocked:
    sys.exit(23)
"""
        with StateDirectory(self.path):
            lock = self.path / StateDirectory.LOCK_NAME
            inode = lock.stat().st_ino
            with self.assertRaises(StateLocked):
                with StateDirectory(self.path):
                    pass
            child = subprocess.run([sys.executable, "-c", code, str(self.path)],
                                   cwd=Path(__file__).resolve().parent.parent,
                                   capture_output=True, timeout=10)
            self.assertEqual(child.returncode, 23, child.stderr.decode())
        self.assertTrue(lock.exists())
        with StateDirectory(self.path):
            self.assertEqual(lock.stat().st_ino, inode)

    def test_wal_backup_reopen_and_corruption_is_preserved(self):
        with StateDirectory(self.path) as state:
            with sqlite3.connect(state.db_path) as db:
                self.assertEqual(db.execute("PRAGMA journal_mode").fetchone()[0], "wal")
                db.execute("CREATE TABLE fixture(value TEXT)")
                db.execute("INSERT INTO fixture VALUES('synthetic message')")
                db.commit()
                backup = state.backup()
                self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o600)
                with sqlite3.connect(backup) as saved:
                    self.assertEqual(saved.execute("SELECT value FROM fixture").fetchone()[0], "synthetic message")
                    self.assertEqual(saved.execute("PRAGMA integrity_check").fetchone()[0], "ok")
                self.assertEqual(state.backup(), backup)
            db.close()
        with StateDirectory(self.path) as state:
            with sqlite3.connect(state.db_path) as db:
                self.assertEqual(db.execute("SELECT count(*) FROM fixture").fetchone()[0], 1)
            db.close()
        damaged = self.path / StateDirectory.DB_NAME
        damaged.write_bytes(b"synthetic corrupted database")
        with self.assertRaisesRegex(StateError, "preserve state"):
            with StateDirectory(self.path):
                pass
        self.assertEqual(damaged.read_bytes(), b"synthetic corrupted database")
        self.assertTrue(backup.exists())
        damaged.unlink()
        orphan = self.path / (StateDirectory.DB_NAME + "-wal")
        orphan.write_bytes(b"synthetic orphaned WAL")
        os.chmod(orphan, 0o600)
        with self.assertRaisesRegex(StateError, "orphaned"):
            with StateDirectory(self.path):
                pass
        self.assertFalse(damaged.exists())
        self.assertEqual(orphan.read_bytes(), b"synthetic orphaned WAL")

    def test_cipher_roundtrip_wrong_key_and_plaintext_rejected(self):
        cipher = StateCipher(base64.urlsafe_b64encode(b"a" * 32))
        wrong = StateCipher(base64.urlsafe_b64encode(b"b" * 32))
        plaintext = "Synthetic text only: hello 你好"
        sealed = cipher.seal(plaintext)
        self.assertNotIn(plaintext, sealed)
        self.assertEqual(cipher.open(sealed), plaintext)
        self.assertNotEqual(cipher.seal(plaintext), sealed)
        for value, decryptor in ((sealed, wrong), (plaintext, cipher), (sealed[:-2] + "xx", cipher)):
            with self.assertRaises(StateError):
                decryptor.open(value)
        with self.assertRaises(StateError):
            StateCipher("synthetic-invalid-key")


if __name__ == "__main__":
    unittest.main()
