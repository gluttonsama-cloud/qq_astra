"""Run Windows ACL/lock/backup checks in a new, disposable project directory.

No account, network connection, production key, existing ACL or system setting
is touched. A non-Windows run explicitly reports NOT TESTED and exits nonzero.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import uuid


def main():
    argparse.ArgumentParser(description=__doc__).parse_args()
    report = {"platform": sys.platform, "status": "not_tested", "checks": [], "not_tested": []}
    if sys.platform != "win32":
        report["not_tested"] = ["Windows host is required; Linux simulation is not ACL verification"]
        print(json.dumps(report))
        return 2
    root, owned = None, False
    try:
        import pywintypes
        import win32api
        import win32con
        import win32file
        import win32security

        from .state import StateDirectory, StateError, StateLocked, read_secret_file
        from .windows_state import DACL_PROTECTED, WindowsPrivateDirectory, default_state_directory

        root = default_state_directory().with_name("QQAstra-selfcheck-" + uuid.uuid4().hex)
        if root.exists():
            raise RuntimeError("selfcheck path already exists")
        with WindowsPrivateDirectory(root) as directory:
            owned = True
            fixture = directory.create_file("synthetic.txt")
            fixture.write_text("synthetic non-secret fixture", encoding="utf-8")
            assert read_secret_file(fixture) == "synthetic non-secret fixture"
            # Ordinary files created beneath this protected private directory
            # inherit the same strict trustee set and must remain usable.
            inherited = root / "inherited.txt"
            inherited.write_text("synthetic inherited fixture", encoding="utf-8")
            assert read_secret_file(inherited) == "synthetic inherited fixture"
            report["checks"].append("private/protected and private/inherited file ACL reads")

            token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
            try:
                sid = win32security.ConvertSidToStringSid(win32security.GetTokenInformation(token, win32security.TokenUser)[0])
            finally:
                token.Close()
            wide = win32security.ConvertStringSecurityDescriptorToSecurityDescriptor(
                "D:P(A;;FA;;;" + sid + ")(A;;FR;;;WD)", win32security.SDDL_REVISION_1)
            null = win32security.SECURITY_DESCRIPTOR()
            null.SetSecurityDescriptorDacl(True, None, False)
            # An unprotected NULL DACL can inherit the safe parent DACL, which
            # would not exercise the rejection this fixture is meant to test.
            null.SetSecurityDescriptorControl(DACL_PROTECTED, DACL_PROTECTED)
            for name, descriptor in (("wide.txt", wide), ("null.txt", null)):
                attributes = pywintypes.SECURITY_ATTRIBUTES()
                attributes.SECURITY_DESCRIPTOR = descriptor
                attributes.bInheritHandle = False
                handle = win32file.CreateFile(str(root / name), win32con.GENERIC_WRITE | win32con.READ_CONTROL, 0,
                    attributes, win32con.CREATE_NEW, win32con.FILE_ATTRIBUTE_NORMAL, None)
                try:
                    if name == "null.txt":
                        actual = win32security.GetSecurityInfo(handle, win32security.SE_FILE_OBJECT,
                                                               win32security.DACL_SECURITY_INFORMATION)
                        assert actual.GetSecurityDescriptorDacl() is None, "NULL DACL fixture was not created"
                    win32file.WriteFile(handle, b"synthetic non-secret fixture")
                finally:
                    handle.Close()
                try:
                    read_secret_file(root / name)
                except StateError:
                    pass
                else:
                    raise AssertionError("unsafe fixture ACL was accepted")
            report["checks"].append("broad and NULL DACL rejected without repairing existing ACL")

            alias = root / "hardlink.txt"
            os.link(fixture, alias)
            try:
                try:
                    read_secret_file(fixture)
                except StateError:
                    pass
                else:
                    raise AssertionError("hard-linked secret was accepted")
            finally:
                alias.unlink()
            report["checks"].append("hard link rejected")

        original, renamed = root / "pincheck", root / "pincheck-renamed"
        with WindowsPrivateDirectory(original):
            try:
                win32file.MoveFileEx(str(original), str(renamed), 0)
            except pywintypes.error as exc:
                assert exc.winerror == 32, "directory pin did not report sharing violation"
            else:
                raise AssertionError("pinned directory was renamed")
            try:
                handle = win32file.CreateFile(str(original), win32con.GENERIC_WRITE,
                    win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE,
                    None, win32con.OPEN_EXISTING,
                    win32con.FILE_FLAG_BACKUP_SEMANTICS | win32file.FILE_FLAG_OPEN_REPARSE_POINT, None)
            except pywintypes.error as exc:
                assert exc.winerror == 32, "directory write pin did not report sharing violation"
            else:
                handle.Close()
                raise AssertionError("pinned directory allowed a write handle")
        win32file.MoveFileEx(str(original), str(renamed), 0)
        report["checks"].append("directory pin blocks write/rename until its handles close")

        state_path = root / "state"
        with StateDirectory(state_path) as state:
            code = """import sys
from bridge_service.state import StateDirectory, StateLocked
try:
    with StateDirectory(sys.argv[1]):
        pass
except StateLocked:
    sys.exit(23)
"""
            child = subprocess.run([sys.executable, "-c", code, str(state_path)],
                cwd=Path(__file__).resolve().parent.parent, capture_output=True, timeout=15)
            assert child.returncode == 23, "second process did not observe the state lock"
            report["checks"].append("second process rejected by exclusive state lock")
            with sqlite3.connect(state.db_path) as db:
                db.execute("CREATE TABLE fixture(value TEXT)")
                db.execute("INSERT INTO fixture VALUES('synthetic fixture')")
                db.commit()
                backup = state.backup()
                with sqlite3.connect(backup) as saved:
                    assert saved.execute("SELECT value FROM fixture").fetchone()[0] == "synthetic fixture"
                saved.close()
            db.close()
        with StateDirectory(state_path):
            pass
        report["checks"].append("WAL backup and lock release/reopen")

        reparse = root / "reparse"
        try:
            os.symlink(state_path, reparse, target_is_directory=True)
        except OSError:
            report["not_tested"].append("reparse fixture creation unavailable; no privilege/settings changed")
        else:
            try:
                try:
                    with StateDirectory(reparse):
                        pass
                except StateError:
                    pass
                else:
                    raise AssertionError("reparse path was accepted")
            finally:
                reparse.unlink()
            report["checks"].append("reparse directory rejected")
        report["status"] = "partial" if report["not_tested"] else "passed"
    except Exception as exc:
        report["status"] = "failed"
        # Do not echo paths, descriptors, SIDs or arbitrary exception strings.
        report["failure_type"] = type(exc).__name__
    finally:
        if owned:
            try:
                shutil.rmtree(root)
            except OSError:
                report["status"] = "failed"
                report["not_tested"].append("temporary selfcheck directory cleanup failed")
    print(json.dumps(report))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    sys.exit(main())
