"""Fail-closed Windows/NTFS private-file backend (pywin32, Windows only).

No ACL is repaired: creation security descriptors apply only to new objects.
Ancestors have a separate integrity-only ACL policy and are pinned against
rename/write/reparse while in use. The final state directory trusts the current SID,
SYSTEM and Administrators. Same-user/admin compromise is outside this boundary.
SQLite orchestration and Fernet remain in state.py; no credentials are generated.

Native ACL/locking behavior must be verified by windows_selfcheck. Passing
the portable policy tests is not evidence of a successful Windows runtime test.

API references: https://mhammond.github.io/pywin32/win32file__CreateFile_meth.html
https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/8c0e3f4f-0729-49f4-a14d-7f7add593819
https://learn.microsoft.com/en-us/archive/msdn-magazine/2008/november/access-control-understanding-windows-file-and-registry-permissions
"""

import ntpath
import os
from pathlib import Path
import re
from types import SimpleNamespace
import uuid


class WindowsStateError(RuntimeError):
    pass


class WindowsStateLocked(WindowsStateError):
    pass


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
# Microsoft's Windows Resource Protection service SID; ancestors only.
TRUSTED_INSTALLER_SID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
DACL_PRESENT = 0x0004
DACL_PROTECTED = 0x1000
FILE_ALL_ACCESS = 0x001F01FF
FILE_READ_ACCESS = 0x00120089
GENERIC_ALL = 0x10000000
GENERIC_READ = 0x80000000
GENERIC_EXECUTE = 0x20000000
# WinNT FILE_READ_ATTRIBUTES: not exported by win32con/ win32file.
FILE_READ_ATTRIBUTES = 0x80
FILE_LIST_DIRECTORY = 0x01
SYNCHRONIZE = 0x00100000
INHERIT_ONLY = 0x08
ALLOWED_ACE_FLAGS = 0x1F


def validate_private_acl(owner_sid, current_sid, control, aces, *, inherited_ok=False):
    """Pure policy over (type, flags, mask, SID) ACE records; unknown = reject."""
    if (owner_sid != current_sid or not control & DACL_PRESENT or aces is None
            or (not inherited_ok and not control & DACL_PROTECTED)):
        raise WindowsStateError("private object needs a user-owned protected non-NULL DACL")
    allowed = {current_sid, SYSTEM_SID, ADMINISTRATORS_SID}
    current_access = 0
    for ace in aces:
        if not isinstance(ace, (tuple, list)) or len(ace) != 4:
            raise WindowsStateError("unsupported private DACL entry")
        kind, flags, mask, sid = ace
        if (type(kind) is not int or kind != 0 or type(flags) is not int or flags < 0 or flags & ~ALLOWED_ACE_FLAGS
                or type(mask) is not int or not 0 <= mask <= 0xFFFFFFFF or sid not in allowed):
            raise WindowsStateError("private DACL grants an untrusted SID or has unsupported ACEs")
        if sid == current_sid and not flags & INHERIT_ONLY:
            current_access |= mask
            if mask & GENERIC_ALL:
                current_access |= FILE_ALL_ACCESS
            if mask & GENERIC_READ:
                current_access |= FILE_READ_ACCESS
    if current_access & FILE_READ_ACCESS != FILE_READ_ACCESS:
        raise WindowsStateError("private DACL must grant this user effective read access")


def validate_ancestor_acl(owner_sid, current_sid, control, aces):
    """Allow ordinary read/create grants, never untrusted replacement/control."""
    trusted = {current_sid, SYSTEM_SID, ADMINISTRATORS_SID, TRUSTED_INSTALLER_SID}
    if owner_sid not in trusted or not control & DACL_PRESENT or aces is None:
        raise WindowsStateError("path ancestor needs a trusted owner and non-NULL DACL")
    safe = FILE_READ_ACCESS | 0x20 | 0x02 | 0x04  # Traverse/list/read plus add file/subdirectory.
    for ace in aces:
        if not isinstance(ace, (tuple, list)) or len(ace) != 4:
            raise WindowsStateError("unsupported ancestor DACL entry")
        kind, flags, mask, sid = ace
        if (type(kind) is not int or kind not in (0, 1) or type(flags) is not int
                or flags < 0 or flags & ~ALLOWED_ACE_FLAGS
                or type(mask) is not int or not 0 <= mask <= 0xFFFFFFFF):
            raise WindowsStateError("complex or unknown ancestor DACL entries are not supported")
        if kind == 1 or flags & INHERIT_ONLY or sid in trusted:
            continue  # Denies only restrict; inherited-only entries cannot act on this object.
        mapped = mask & ~(GENERIC_READ | GENERIC_EXECUTE)
        if mask & GENERIC_READ:
            mapped |= FILE_READ_ACCESS
        if mask & GENERIC_EXECUTE:
            mapped |= 0x001200A0
        if mapped & ~safe:
            raise WindowsStateError("path ancestor allows an untrusted SID to replace or control existing objects")


def _component(name):
    if (not isinstance(name, str) or not name or name in (".", "..")
            or name[-1] in " ." or re.search(r'[<>:"/\\|?*\x00-\x1f]', name)
            or re.fullmatch(r"(?i:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])", name.split(".")[0])):
        raise WindowsStateError("a plain Windows filesystem name is required")
    return name


def validate_local_path(path):
    """Only ordinary absolute DOS paths; no UNC, device, ADS or aliases."""
    value = os.fspath(path)
    if not isinstance(value, str):
        raise WindowsStateError("a Windows path string is required")
    value = value.replace("/", "\\")
    drive, tail = ntpath.splitdrive(value)
    if (not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith("\\")
            or len(value) >= 248 or "\\\\" in tail):
        raise WindowsStateError("use a short absolute path on a local fixed NTFS drive")
    for part in tail.rstrip("\\").split("\\")[1:]:
        _component(part)
    return ntpath.normpath(value)


def default_state_directory():
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise WindowsStateError("LOCALAPPDATA is unavailable; supply an explicit private state path")
    return Path(validate_local_path(ntpath.join(base, "qq-astra")))


def _windows():
    if os.name != "nt":
        raise WindowsStateError("the Windows private-file backend requires Windows and pywin32")
    try:
        import pywintypes
        import win32api
        import win32con
        import win32file
        import win32security
    except ImportError:
        raise WindowsStateError("install the declared Windows pywin32 dependency first") from None
    try:
        token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
        try:
            sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
            sid_text = win32security.ConvertSidToStringSid(sid)
        finally:
            token.Close()
    except pywintypes.error:
        raise WindowsStateError("the current Windows user identity could not be verified") from None
    return SimpleNamespace(types=pywintypes, api=win32api, con=win32con,
                           file=win32file, security=win32security, sid=sid_text)


def _attributes(api, *, directory):
    inheritance = "OICI" if directory else ""
    sddl = "O:" + api.sid + "D:P" + "".join(
        f"(A;{inheritance};FA;;;{sid})" for sid in (api.sid, SYSTEM_SID, ADMINISTRATORS_SID))
    attributes = api.types.SECURITY_ATTRIBUTES()
    attributes.SECURITY_DESCRIPTOR = api.security.ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, 1)
    attributes.bInheritHandle = False
    return attributes


def _acl_records(api, handle):
    security = api.security
    descriptor = security.GetSecurityInfo(handle, security.SE_FILE_OBJECT,
                                         security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION)
    owner = descriptor.GetSecurityDescriptorOwner()
    owner_text = security.ConvertSidToStringSid(owner) if owner is not None else None
    control = descriptor.GetSecurityDescriptorControl()[0]
    dacl = descriptor.GetSecurityDescriptorDacl()
    aces = None if dacl is None else []
    if dacl is not None:
        for index in range(dacl.GetAceCount()):
            ace = dacl.GetAce(index)
            if len(ace) != 3 or len(ace[0]) != 2 or ace[0][0] not in (0, 1):
                raise WindowsStateError("complex or unknown DACL entries are not supported")
            # PyACL.GetAce exposes ACCESS_MASK via a signed Windows C long.
            # Normalize only an actual 32-bit integer at this API boundary;
            # policy functions deliberately accept unsigned masks only.
            mask = ace[1]
            if type(mask) is not int or not -(1 << 31) <= mask <= 0xFFFFFFFF:
                raise WindowsStateError("invalid Windows access mask")
            aces.append((ace[0][0], ace[0][1], mask & 0xFFFFFFFF,
                         security.ConvertSidToStringSid(ace[2])))
    return owner_text, control, aces


def _private_acl(api, handle, *, inherited_ok=False):
    owner_text, control, aces = _acl_records(api, handle)
    validate_private_acl(owner_text, api.sid, control, aces, inherited_ok=inherited_ok)


def _ancestor_acl(api, handle):
    owner_text, control, aces = _acl_records(api, handle)
    validate_ancestor_acl(owner_text, api.sid, control, aces)


def _validate_handle(api, handle, path, *, directory, volume=None):
    info = api.file.GetFileInformationByHandle(handle)
    attrs = info[0]
    if (api.file.GetFileType(handle) != api.file.FILE_TYPE_DISK
            or attrs & (api.con.FILE_ATTRIBUTE_REPARSE_POINT | api.con.FILE_ATTRIBUTE_OFFLINE)
            or bool(attrs & api.con.FILE_ATTRIBUTE_DIRECTORY) != directory
            or (not directory and info[7] != 1) or (volume is not None and info[4] != volume)):
        raise WindowsStateError("only ordinary local files/directories without reparse points or hardlinks are allowed")
    final = api.file.GetFinalPathNameByHandle(handle, 0)
    if final.startswith("\\\\?\\"):
        final = final[4:]
    if ntpath.normcase(ntpath.normpath(final)) != ntpath.normcase(path):
        raise WindowsStateError("the opened path differs from the requested local path")
    return info


class _PinnedDirectories:
    def __init__(self, path, *, create=False, private=False):
        self.text = validate_local_path(path)
        self.api = _windows()
        self.handles = []
        self.volume = None
        self.private_parent = False
        try:
            api = self.api
            drive = ntpath.splitdrive(self.text)[0]
            root = drive + "\\"
            device = api.file.QueryDosDevice(drive).split("\x00")[0]
            volume_info = api.api.GetVolumeInformation(root)
            if (api.file.GetDriveType(root) != api.con.DRIVE_FIXED
                    or not re.fullmatch(r"\\Device\\HarddiskVolume[0-9]+", device)
                    or volume_info[4].upper() != "NTFS" or not volume_info[3] & 0x00000008):
                raise WindowsStateError("private state requires a local fixed NTFS volume with persistent ACLs")
            paths = [root]
            for part in self.text[len(root):].split("\\"):
                if part:
                    paths.append(ntpath.join(paths[-1], part))
            for index, current in enumerate(paths):
                created = False
                if create and index:
                    try:
                        api.file.CreateDirectory(current, _attributes(api, directory=True))
                        created = True
                    except api.types.error as exc:
                        if exc.winerror != 183:  # ERROR_ALREADY_EXISTS; never repair its ACL.
                            raise
                handle = api.file.CreateFile(
                    # Include a real read-access category: metadata-only access
                    # does not reliably participate in Windows sharing checks.
                    current, api.con.READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY | SYNCHRONIZE,
                    api.con.FILE_SHARE_READ, None, api.con.OPEN_EXISTING,
                    api.con.FILE_FLAG_BACKUP_SEMANTICS | api.file.FILE_FLAG_OPEN_REPARSE_POINT, None)
                self.handles.append(handle)
                info = _validate_handle(api, handle, current, directory=True, volume=self.volume)
                if self.volume is None:
                    self.volume = info[4]
                _ancestor_acl(api, handle)
                if created:
                    _private_acl(api, handle)
            try:
                _private_acl(api, self.handles[-1])
                self.private_parent = True
            except WindowsStateError:
                if private:
                    raise
        except BaseException as exc:
            self.close()
            if isinstance(exc, self.api.types.error):
                raise WindowsStateError("Windows directory could not be safely opened; check path, ACL and sharing") from None
            raise

    def close(self):
        for handle in reversed(self.handles):
            handle.Close()
        self.handles.clear()


def _file_handle(chain, name, *, create=False, read=False, writable=False, inherited_ok=False):
    api = chain.api
    path = ntpath.join(chain.text, _component(name))
    access = api.con.READ_CONTROL | FILE_READ_ATTRIBUTES
    if read or writable:
        access |= api.con.GENERIC_READ
    if writable:
        access |= api.con.GENERIC_WRITE
    sharing = api.con.FILE_SHARE_READ | (0 if read else api.con.FILE_SHARE_WRITE)
    try:
        handle = api.file.CreateFile(path, access, sharing, _attributes(api, directory=False) if create else None,
                                     api.con.CREATE_NEW if create else api.con.OPEN_EXISTING,
                                     api.con.FILE_ATTRIBUTE_NORMAL | api.file.FILE_FLAG_OPEN_REPARSE_POINT, None)
    except api.types.error as exc:
        if exc.winerror in (2, 3):
            raise FileNotFoundError("private file does not exist") from None
        if create and exc.winerror in (80, 183):
            raise FileExistsError("private file already exists") from None
        raise WindowsStateError("private file could not be safely opened; check ACL, links and sharing") from None
    try:
        _validate_handle(api, handle, path, directory=False, volume=chain.volume)
        _private_acl(api, handle, inherited_ok=inherited_ok and chain.private_parent)
        return handle
    except BaseException as exc:
        handle.Close()
        if isinstance(exc, api.types.error):
            raise WindowsStateError("private file security could not be verified") from None
        raise


class WindowsPrivateDirectory:
    """Small filesystem backend; caller retains common SQLite/Fernet logic."""

    def __init__(self, path=None):
        self.path = Path(validate_local_path(path if path is not None else default_state_directory()))
        self._chain = None
        self._lock = None
        self._overlapped = None
        self._temporary_names = set()

    def open(self):
        if self._chain is not None:
            raise WindowsStateError("private directory is already open")
        self._chain = _PinnedDirectories(self.path, create=True, private=True)
        return self

    __enter__ = open

    def _require_open(self):
        if self._chain is None:
            raise WindowsStateError("an open private directory is required")
        return self._chain

    def create_file(self, name):
        chain = self._require_open()
        try:
            handle = _file_handle(chain, name, create=True, writable=True)
        except FileExistsError:
            handle = _file_handle(chain, name, writable=True)
        handle.Close()
        return self.path / name

    def check_file(self, name, *, missing_ok=False, inherited_ok=False):
        chain = self._require_open()
        try:
            handle = _file_handle(chain, name, inherited_ok=inherited_ok)
        except FileNotFoundError:
            if missing_ok:
                return False
            raise
        handle.Close()
        return True

    def acquire_lock(self, name="bridge.lock"):
        chain = self._require_open()
        if self._lock is not None:
            raise WindowsStateError("the instance lock is already held")
        self.create_file(name)
        handle = _file_handle(chain, name, writable=True)
        try:
            overlapped = chain.api.types.OVERLAPPED()
            chain.api.file.LockFileEx(handle, chain.api.con.LOCKFILE_EXCLUSIVE_LOCK |
                                     chain.api.con.LOCKFILE_FAIL_IMMEDIATELY, 1, 0, overlapped)
        except BaseException as exc:
            handle.Close()
            if isinstance(exc, chain.api.types.error) and exc.winerror in (32, 33):
                raise WindowsStateLocked("another bridge process owns this state directory") from None
            if isinstance(exc, chain.api.types.error):
                raise WindowsStateError("the Windows instance lock could not be acquired") from None
            raise
        self._lock, self._overlapped = handle, overlapped

    def new_file(self, prefix=".backup-", suffix=".sqlite3"):
        chain = self._require_open()
        for _ in range(10):
            name = _component(prefix + uuid.uuid4().hex + suffix)
            try:
                handle = _file_handle(chain, name, create=True, writable=True)
            except FileExistsError:
                continue
            handle.Close()
            self._temporary_names.add(name)
            return self.path / name
        raise WindowsStateError("could not allocate a private temporary backup")

    def replace_file(self, source_name, destination_name):
        chain = self._require_open()
        _component(source_name)
        _component(destination_name)
        if source_name not in self._temporary_names or destination_name != "bridge.backup.sqlite3":
            raise WindowsStateError("only this instance's temporary backup may replace its backup file")
        handle = _file_handle(chain, source_name, writable=True)
        try:
            chain.api.file.FlushFileBuffers(handle)
        finally:
            handle.Close()
        self.check_file(destination_name, missing_ok=True)
        try:
            chain.api.file.MoveFileEx(ntpath.join(chain.text, source_name), ntpath.join(chain.text, destination_name),
                                     chain.api.file.MOVEFILE_REPLACE_EXISTING | chain.api.file.MOVEFILE_WRITE_THROUGH)
        except chain.api.types.error:
            raise WindowsStateError("atomic private backup publication failed") from None
        self.check_file(destination_name)
        return self.path / destination_name

    def unlink_file(self, name):
        chain = self._require_open()
        _component(name)
        if not any(name == base + suffix for base in self._temporary_names
                   for suffix in ("", "-wal", "-shm", "-journal")):
            raise WindowsStateError("only temporary files created by this backup operation can be removed")
        if not self.check_file(name, missing_ok=True, inherited_ok=True):
            return
        try:
            chain.api.file.DeleteFile(ntpath.join(chain.text, name))
        except chain.api.types.error:
            raise WindowsStateError("temporary private backup could not be removed") from None

    def close(self):
        # Never delete the persistent lock file; the handle owns its byte lock.
        if self._lock is not None:
            self._lock.Close()
            self._lock = self._overlapped = None
        if self._chain is not None:
            self._chain.close()
            self._chain = None
        self._temporary_names.clear()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def read_public_key_file(path, max_bytes=262144):
    """Handle-bound bounded read; public-key integrity uses the same strict ACL."""
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    value = validate_local_path(path)
    chain = _PinnedDirectories(ntpath.dirname(value))
    try:
        handle = _file_handle(chain, ntpath.basename(value), read=True, inherited_ok=chain.private_parent)
        try:
            info = chain.api.file.GetFileInformationByHandle(handle)
            if (info[5] << 32) + info[6] > max_bytes:
                raise WindowsStateError("private file exceeds its configured size limit")
            status, data = chain.api.file.ReadFile(handle, max_bytes + 1)
            if status != 0:
                raise WindowsStateError("private file read did not complete synchronously")
            if len(data) > max_bytes:
                raise WindowsStateError("private file exceeds its configured size limit")
            return data
        except chain.api.types.error:
            raise WindowsStateError("private file could not be read") from None
        finally:
            handle.Close()
    finally:
        chain.close()


def read_secret_file(path, max_bytes=16384):
    data = read_public_key_file(path, max_bytes)
    try:
        value = data.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise WindowsStateError("secret file must contain UTF-8 text") from None
    if not value:
        raise WindowsStateError("secret file is empty")
    return value


read_private_text = read_secret_file
read_public_key_bytes = read_public_key_file
