"""Portable policy/Win32-call contracts; actual Windows validation is windows_selfcheck."""

from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from . import windows_state as ws

SID = "S-1-5-21-111-222-333-1001"
PRIVATE = ws.DACL_PRESENT | ws.DACL_PROTECTED
ACES = [(0, 0, ws.FILE_ALL_ACCESS, SID), (0, 0, ws.FILE_ALL_ACCESS, ws.SYSTEM_SID),
        (0, 0, ws.FILE_ALL_ACCESS, ws.ADMINISTRATORS_SID)]


class Handle:
    def __init__(self, path="fixture"):
        self.path, self.closed = path, False

    def Close(self):
        self.closed = True


def fake_api():
    constants = SimpleNamespace(FILE_ATTRIBUTE_DIRECTORY=0x10, FILE_ATTRIBUTE_REPARSE_POINT=0x400,
                                FILE_ATTRIBUTE_OFFLINE=0x1000, FILE_SHARE_READ=1, FILE_SHARE_WRITE=2,
                                FILE_SHARE_DELETE=4, READ_CONTROL=0x20000,
                                GENERIC_READ=0x80000000, GENERIC_WRITE=0x40000000,
                                CREATE_NEW=1, OPEN_EXISTING=3, FILE_ATTRIBUTE_NORMAL=0x80,
                                FILE_FLAG_BACKUP_SEMANTICS=0x02000000, DRIVE_FIXED=3)
    files = SimpleNamespace(FILE_TYPE_DISK=1, FILE_FLAG_OPEN_REPARSE_POINT=0x200000, GetFileType=Mock(return_value=1),
                            GetFinalPathNameByHandle=Mock(side_effect=lambda h, flags: "\\\\?\\" + h.path),
                            CreateFile=Mock(side_effect=lambda path, *args: Handle(path)),
                            QueryDosDevice=Mock(return_value="\\Device\\HarddiskVolume3\x00\x00"),
                            GetDriveType=Mock(return_value=3))
    class WinError(Exception):
        def __init__(self, code):
            self.winerror = code
    return SimpleNamespace(con=constants, file=files, types=SimpleNamespace(error=WinError), sid=SID,
                           api=SimpleNamespace(GetVolumeInformation=Mock(return_value=("", 17, 255, 8, "NTFS"))))


class WindowsPolicyTests(unittest.TestCase):
    def test_getace_signed_windows_long_is_normalized_at_api_boundary(self):
        acl = SimpleNamespace(GetAceCount=lambda: 1,
                              GetAce=lambda index: ((0, 0), -2147483648, SID))
        descriptor = SimpleNamespace(GetSecurityDescriptorOwner=lambda: SID,
            GetSecurityDescriptorControl=lambda: (PRIVATE, 1), GetSecurityDescriptorDacl=lambda: acl)
        api = fake_api()
        api.security = SimpleNamespace(SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1,
            DACL_SECURITY_INFORMATION=4, GetSecurityInfo=Mock(return_value=descriptor),
            ConvertSidToStringSid=lambda sid: sid)
        owner, control, records = ws._acl_records(api, Handle())
        self.assertEqual(records, [(0, 0, ws.GENERIC_READ, SID)])
        ws.validate_private_acl(owner, SID, control, records)
        for invalid in (-2147483649, 0x100000000, True):
            acl.GetAce = lambda index, mask=invalid: ((0, 0), mask, SID)
            with self.subTest(mask=invalid), self.assertRaises(ws.WindowsStateError):
                ws._acl_records(api, Handle())

    def test_local_path_policy_rejects_unc_devices_streams_and_aliases(self):
        self.assertEqual(ws.validate_local_path("C:/Users/fixture/qq-astra"), r"C:\Users\fixture\qq-astra")
        invalid = [r"\\server\share\state", r"\\?\C:\state", r"\\.\C:\state", r"C:relative", "relative",
                   r"C:\private\key:stream", r"C:\private\..\key", r"C:\private\.\key", r"C:\NUL.txt",
                   "C:\\private\\key ", "C:\\private\\key.", r"C:\COM¹.log", "C:\\" + "a" * 250]
        for path in invalid:
            with self.subTest(path=path), self.assertRaises(ws.WindowsStateError):
                ws.validate_local_path(path)

    def test_acl_policy_rejects_null_unprotected_wide_and_complex_aces(self):
        ws.validate_private_acl(SID, SID, PRIVATE, ACES)
        ws.validate_private_acl(SID, SID, PRIVATE, [(0, 0, ws.GENERIC_READ, SID)])
        invalid = [(SID, PRIVATE, None), (SID, 0, ACES), (SID, ws.DACL_PRESENT, ACES),
                   (ws.ADMINISTRATORS_SID, PRIVATE, ACES), (SID, PRIVATE, []),
                   (SID, PRIVATE, ACES + [(0, 0, ws.FILE_READ_ACCESS, "S-1-1-0")]),
                   (SID, PRIVATE, [(5, 0, ws.FILE_ALL_ACCESS, SID)]),
                   (SID, PRIVATE, [(1, 0, ws.FILE_ALL_ACCESS, SID)]),
                   (SID, PRIVATE, [(0, 0x80, ws.FILE_ALL_ACCESS, SID)]),
                   (SID, PRIVATE, [(0, ws.INHERIT_ONLY, ws.FILE_ALL_ACCESS, SID)])]
        for owner, control, aces in invalid:
            with self.subTest(owner=owner, control=control, aces=aces), self.assertRaises(ws.WindowsStateError):
                ws.validate_private_acl(owner, SID, control, aces)
        ws.validate_private_acl(SID, SID, ws.DACL_PRESENT, [(0, 0x10, ws.FILE_ALL_ACCESS, SID)], inherited_ok=True)

    def test_handle_policy_rejects_reparse_hardlink_directory_and_changed_path(self):
        api = fake_api()
        handle = Handle(r"C:\private\fixture")
        info = [0x80, None, None, None, 17, 0, 10, 1, 0, 1]
        api.file.GetFileInformationByHandle = Mock(return_value=info)
        ws._validate_handle(api, handle, handle.path, directory=False, volume=17)
        for index, value in ((0, 0x400), (0, 0x10), (0, 0x1000), (4, 18), (7, 2)):
            altered = info.copy()
            altered[index] = value
            api.file.GetFileInformationByHandle.return_value = altered
            with self.assertRaises(ws.WindowsStateError):
                ws._validate_handle(api, handle, handle.path, directory=False, volume=17)
        api.file.GetFileInformationByHandle.return_value = info
        with self.assertRaises(ws.WindowsStateError):
            ws._validate_handle(api, handle, r"C:\private\different", directory=False, volume=17)

    def test_ancestor_integrity_allows_windows_root_read_create_but_not_replacement(self):
        users, creator = "S-1-5-32-545", "S-1-3-0"
        root_aces = [(0, 3, ws.FILE_ALL_ACCESS, ws.SYSTEM_SID),
                     (0, 3, ws.FILE_ALL_ACCESS, ws.ADMINISTRATORS_SID),
                     (0, 3, 0x1200A9, users), (0, 2, 4, users),
                     (0, 10, 2, users), (0, 11, ws.GENERIC_ALL, creator)]
        ws.validate_ancestor_acl(ws.TRUSTED_INSTALLER_SID, SID, ws.DACL_PRESENT, root_aces)
        for right in (0x40, 0x10000, 0x40000, 0x80000, 0x10, 0x100, 0x40000000, ws.GENERIC_ALL):
            with self.subTest(right=right), self.assertRaises(ws.WindowsStateError):
                ws.validate_ancestor_acl(ws.SYSTEM_SID, SID, ws.DACL_PRESENT, root_aces + [(0, 0, right, users)])
        with self.assertRaises(ws.WindowsStateError):
            ws.validate_ancestor_acl(users, SID, ws.DACL_PRESENT, root_aces)
        with self.assertRaises(ws.WindowsStateError):
            ws.validate_ancestor_acl(ws.SYSTEM_SID, SID, ws.DACL_PRESENT, None)
        with self.assertRaises(ws.WindowsStateError):
            ws.validate_ancestor_acl(ws.SYSTEM_SID, SID, ws.DACL_PRESENT, [(5, 0, 1, users)])
        with self.assertRaises(ws.WindowsStateError):
            ws.validate_private_acl(ws.TRUSTED_INSTALLER_SID, SID, PRIVATE, ACES)

    def test_inherited_acl_requires_verified_private_parent(self):
        api = fake_api()
        chain = SimpleNamespace(api=api, text=r"C:\private", private_parent=False, volume=17)
        with patch.object(ws, "_validate_handle"), patch.object(ws, "_private_acl") as acl:
            handle = ws._file_handle(chain, "fixture", inherited_ok=True)
            acl.assert_called_once_with(api, handle, inherited_ok=False)
            handle.Close()
            chain.private_parent = True
            handle = ws._file_handle(chain, "fixture", inherited_ok=True)
            self.assertTrue(acl.call_args.kwargs["inherited_ok"])
            handle.Close()

    def test_secret_read_uses_validated_handle_and_denies_write_delete_sharing(self):
        api = fake_api()
        info = [0x80, None, None, None, 17, 0, 14, 1, 0, 1]
        api.file.GetFileInformationByHandle = Mock(return_value=info)
        api.file.ReadFile = Mock(return_value=(0, b"synthetic only\n"))
        chain = SimpleNamespace(api=api, text=r"C:\private", private_parent=True, volume=17, close=Mock())
        with patch.object(ws, "_PinnedDirectories", return_value=chain), patch.object(ws, "_private_acl") as acl:
            self.assertEqual(ws.read_secret_file(r"C:\private\fixture"), "synthetic only")
            verified_handle = acl.call_args.args[1]
            self.assertIs(api.file.ReadFile.call_args.args[0], verified_handle)
            self.assertTrue(verified_handle.closed)
            self.assertEqual(api.file.CreateFile.call_args.args[2], api.con.FILE_SHARE_READ)
            self.assertTrue(api.file.CreateFile.call_args.args[5] & api.file.FILE_FLAG_OPEN_REPARSE_POINT)
            chain.close.assert_called_once()
        with patch.object(ws, "_PinnedDirectories", return_value=chain), patch.object(ws, "_private_acl"):
            with self.assertRaises(ws.WindowsStateError):
                ws.read_secret_file(r"C:\private\fixture", max_bytes=3)

    def test_directory_pinning_does_not_require_private_drive_root(self):
        api = fake_api()
        api.file.GetFileInformationByHandle = Mock(return_value=[0x10, None, None, None, 17, 0, 0, 1, 0, 1])
        with patch.object(ws, "_windows", return_value=api), patch.object(ws, "_private_acl") as acl, \
                patch.object(ws, "_ancestor_acl") as ancestor:
            chain = ws._PinnedDirectories(r"C:\Users\fixture\private", private=True)
            self.assertEqual(len(chain.handles), 4)
            self.assertEqual(ancestor.call_count, 4)
            acl.assert_called_once_with(api, chain.handles[-1])
            for call in api.file.CreateFile.call_args_list:
                self.assertTrue(call.args[1] & ws.FILE_LIST_DIRECTORY)
                self.assertTrue(call.args[1] & ws.SYNCHRONIZE)
                self.assertEqual(call.args[2], api.con.FILE_SHARE_READ)
                self.assertTrue(call.args[5] & api.file.FILE_FLAG_OPEN_REPARSE_POINT)
            handles = chain.handles.copy()
            self.assertTrue(all(not handle.closed for handle in handles))
            chain.close()
            self.assertTrue(all(handle.closed for handle in handles))

    def test_lock_contract_is_nonblocking_handle_owned_and_never_unlinked(self):
        api = fake_api()
        api.con.LOCKFILE_EXCLUSIVE_LOCK = 2
        api.con.LOCKFILE_FAIL_IMMEDIATELY = 1
        api.types.OVERLAPPED = Mock(return_value=object())
        api.file.LockFileEx = Mock()
        chain = SimpleNamespace(api=api, close=Mock())
        directory = ws.WindowsPrivateDirectory(r"C:\private")
        directory._chain = chain
        handle = Handle()
        with patch.object(directory, "create_file") as create, patch.object(ws, "_file_handle", return_value=handle):
            directory.acquire_lock()
            create.assert_called_once_with("bridge.lock")
            api.file.LockFileEx.assert_called_once_with(handle, 3, 1, 0, directory._overlapped)
            self.assertFalse(handle.closed)
            directory.close()
            self.assertTrue(handle.closed)
            chain.close.assert_called_once()
        directory._chain = chain
        handle = Handle()
        api.file.LockFileEx.side_effect = api.types.error(33)
        with patch.object(directory, "create_file"), patch.object(ws, "_file_handle", return_value=handle):
            with self.assertRaises(ws.WindowsStateLocked):
                directory.acquire_lock()
        self.assertTrue(handle.closed)
        directory.close()

    def test_backup_publish_flushes_closes_and_atomically_replaces_only_backup(self):
        api = fake_api()
        api.file.MOVEFILE_REPLACE_EXISTING = 1
        api.file.MOVEFILE_WRITE_THROUGH = 8
        api.file.FlushFileBuffers = Mock()
        api.file.MoveFileEx = Mock()
        directory = ws.WindowsPrivateDirectory(r"C:\private")
        directory._chain = SimpleNamespace(api=api, text=r"C:\private", close=Mock())
        directory._temporary_names.add(".backup-fixture.sqlite3")
        handle = Handle()
        api.file.MoveFileEx.side_effect = lambda *args: self.assertTrue(handle.closed)
        with patch.object(ws, "_file_handle", return_value=handle), patch.object(directory, "check_file", return_value=True):
            directory.replace_file(".backup-fixture.sqlite3", "bridge.backup.sqlite3")
            api.file.FlushFileBuffers.assert_called_once_with(handle)
            api.file.MoveFileEx.assert_called_once_with(
                r"C:\private\.backup-fixture.sqlite3", r"C:\private\bridge.backup.sqlite3", 9)
            with self.assertRaises(ws.WindowsStateError):
                directory.replace_file(".backup-fixture.sqlite3", "bridge.sqlite3")
            with self.assertRaises(ws.WindowsStateError):
                directory.unlink_file("bridge.lock")
        directory.close()


if __name__ == "__main__":
    unittest.main()
