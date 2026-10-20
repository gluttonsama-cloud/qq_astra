"""Private platform state, single-process ownership, and authenticated encryption.

The state directory must live on a supported local filesystem with working
platform locks and SQLite. Existing insecure paths are rejected, never repaired. Keys
are supplied by the operator; this module never creates credentials.
"""

import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from contextlib import closing

from cryptography.fernet import Fernet, InvalidToken

_WINDOWS = os.name == "nt"

if os.name == "posix":
    import fcntl


class StateError(RuntimeError):
    """State cannot safely be opened; exception text contains no secrets."""


class StateLocked(StateError):
    pass


def default_state_directory():
    if _WINDOWS:
        from .windows_state import default_state_directory as windows_default
        return windows_default()
    base = os.environ.get("XDG_STATE_HOME")
    if not base or not Path(base).is_absolute():
        base = Path.home() / ".local" / "state"
    return Path(base) / "qq-astra"


def _check_directory(fd, *, private=False):
    info = os.fstat(fd)
    mode = stat.S_IMODE(info.st_mode)
    if private:
        if info.st_uid != os.geteuid() or mode & 0o077:
            raise StateError("state directory must be owned by this user with no group/other access")
    elif info.st_uid not in (0, os.geteuid()) or (mode & 0o022 and not mode & stat.S_ISVTX):
        # SQLite opens by pathname: an untrusted parent must not be able to swap
        # the checked directory. A trusted-owner sticky /tmp is safe to traverse.
        raise StateError("state/secret paths must not have untrusted writable parent directories")


def _directory_fd(path, *, create=False, private=False):
    """Walk without following symlinks, including intermediate components."""
    path = Path(os.path.abspath(os.path.expanduser(path)))
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            _check_directory(fd)
            created = False
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    created = True
                except FileExistsError:
                    pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
            if created:
                os.fchmod(fd, 0o700)
        _check_directory(fd, private=private)
        return fd
    except Exception:
        os.close(fd)
        raise


def _check_file(fd, *, writable=False):
    info = os.fstat(fd)
    modes = (0o600,) if writable else (0o400, 0o600)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) not in modes or info.st_nlink != 1):
        raise StateError("state/secret files must be private, user-owned regular files without links")


def _file_fd(directory, name, *, create=False, writable=False):
    flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    fd = None
    try:
        if create:
            try:
                fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
                os.fchmod(fd, 0o600)  # Only the file this call exclusively created.
            except FileExistsError:
                pass
        if fd is None:
            fd = os.open(name, flags, dir_fd=directory)
        _check_file(fd, writable=writable)
        return fd
    except Exception:
        if fd is not None:
            os.close(fd)
        raise


def read_secret_file(path, max_bytes=16384):
    """Read a bounded private UTF-8 secret; never echo its contents in errors."""
    if _WINDOWS:
        from .windows_state import read_secret_file as windows_read, WindowsStateError
        try:
            return windows_read(path, max_bytes=max_bytes)
        except WindowsStateError:
            raise StateError("secret file failed Windows private ACL/path validation") from None
    if type(max_bytes) is not int or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")
    path = Path(os.path.abspath(os.path.expanduser(path)))
    directory = None
    try:
        directory = _directory_fd(path.parent)
        fd = _file_fd(directory, path.name)
        with os.fdopen(fd, "rb") as stream:
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise StateError("secret file exceeds the configured size limit")
        try:
            result = data.decode("utf-8").strip()
        except UnicodeDecodeError:
            raise StateError("secret file must contain UTF-8 text") from None
        if not result:
            raise StateError("secret file is empty")
        return result
    except OSError:
        raise StateError("secret file cannot be safely opened; check ownership, mode and symlinks") from None
    finally:
        if directory is not None:
            os.close(directory)


def read_public_key_file(path, max_bytes=1_048_576):
    """Read a trusted public file with platform-specific path/permission checks."""
    if _WINDOWS:
        from .windows_state import read_public_key_file as windows_read, WindowsStateError
        try:
            return windows_read(path, max_bytes=max_bytes)
        except WindowsStateError:
            raise StateError("public key file failed Windows ACL/path validation") from None
    directory = None
    try:
        path = Path(os.path.abspath(os.path.expanduser(path)))
        directory = _directory_fd(path.parent)
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        with os.fdopen(os.open(path.name, flags, dir_fd=directory), "rb") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid not in (0, os.geteuid())
                    or info.st_mode & 0o022 or info.st_size > max_bytes):
                raise StateError("public key file must not be writable by other users")
            raw = source.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise StateError("public key file exceeds size limit")
        return raw
    except OSError:
        raise StateError("public key file cannot be safely opened") from None
    finally:
        if directory is not None:
            os.close(directory)


class StateCipher:
    PREFIX = "fernet:v1:"

    def __init__(self, key):
        try:
            self._fernet = Fernet(key)
        except (TypeError, ValueError):
            raise StateError("a valid existing Fernet state key is required") from None

    def seal(self, value):
        if not isinstance(value, str):
            raise TypeError("state plaintext must be a string")
        return self.PREFIX + self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def open(self, value):
        try:
            if not isinstance(value, str) or not value.startswith(self.PREFIX):
                raise ValueError
            return self._fernet.decrypt(value[len(self.PREFIX):].encode("ascii")).decode("utf-8")
        except (InvalidToken, ValueError, UnicodeError):
            raise StateError("encrypted state cannot be opened; check the configured state key") from None


class StateDirectory:
    DB_NAME = "bridge.sqlite3"
    BACKUP_NAME = "bridge.backup.sqlite3"
    LOCK_NAME = "bridge.lock"

    def __init__(self, path=None):
        self.path = Path(os.path.abspath(os.path.expanduser(path if path is not None else default_state_directory())))
        self.db_path = self.path / self.DB_NAME
        self._directory = self._lock = None
        self._windows = None

    def _validate_database_files(self):
        for name in (self.DB_NAME, self.DB_NAME + "-wal", self.DB_NAME + "-shm", self.DB_NAME + "-journal"):
            if self._windows is not None:
                self._windows.check_file(name, missing_ok=name != self.DB_NAME, inherited_ok=name != self.DB_NAME)
                continue
            try:
                fd = _file_fd(self._directory, name, writable=True)
            except FileNotFoundError:
                if name == self.DB_NAME:
                    raise
                continue
            os.close(fd)

    @staticmethod
    def _integrity(db):
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise StateError("database integrity check failed; preserve state and explicitly restore a verified backup")

    def __enter__(self):
        if self._directory is not None or self._windows is not None:
            raise StateError("state directory context is already open")
        if _WINDOWS:
            return self._enter_windows()
        try:
            self._directory = _directory_fd(self.path, create=True, private=True)
            self._lock = _file_fd(self._directory, self.LOCK_NAME, create=True, writable=True)
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise StateLocked("another bridge process owns this state directory") from None
            try:
                os.stat(self.DB_NAME, dir_fd=self._directory, follow_symlinks=False)
            except FileNotFoundError:
                for suffix in ("-wal", "-shm", "-journal"):
                    try:
                        os.stat(self.DB_NAME + suffix, dir_fd=self._directory, follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    raise StateError("orphaned database sidecars found; preserve state for explicit recovery")
            fd = _file_fd(self._directory, self.DB_NAME, create=True, writable=True)
            os.close(fd)
            self._validate_database_files()
            self._open_database()
            return self
        except Exception as exc:
            self.close()
            if isinstance(exc, sqlite3.DatabaseError):
                raise StateError("database cannot be opened or recovered; preserve state and explicitly restore a verified backup") from None
            if isinstance(exc, OSError):
                raise StateError("state paths cannot be safely opened; check ownership, modes and symlinks") from None
            raise

    def _open_database(self):
        with closing(sqlite3.connect(self.db_path.as_uri() + "?mode=rw", uri=True)) as db:
            self._integrity(db)
            if db.execute("PRAGMA journal_mode=WAL").fetchone()[0] != "wal":
                raise StateError("database does not support WAL mode")

    def _enter_windows(self):
        from .windows_state import WindowsPrivateDirectory, WindowsStateError, WindowsStateLocked
        try:
            self._windows = WindowsPrivateDirectory(self.path)
            self._windows.open()
            self._windows.acquire_lock(self.LOCK_NAME)
            if not self._windows.check_file(self.DB_NAME, missing_ok=True):
                for suffix in ("-wal", "-shm", "-journal"):
                    if self._windows.check_file(self.DB_NAME + suffix, missing_ok=True, inherited_ok=True):
                        raise StateError("orphaned database sidecars found; preserve state for explicit recovery")
            self._windows.create_file(self.DB_NAME)
            self._validate_database_files()
            self._open_database()
            return self
        except Exception as exc:
            self.close()
            if isinstance(exc, WindowsStateLocked):
                raise StateLocked("another bridge process owns this state directory") from None
            if isinstance(exc, WindowsStateError):
                raise StateError("Windows state ACL/path validation failed") from None
            if isinstance(exc, sqlite3.DatabaseError):
                raise StateError("database cannot be opened or recovered; preserve state and explicitly restore a verified backup") from None
            raise

    def _copy_backup(self, temporary):
        with closing(sqlite3.connect(self.db_path.as_uri() + "?mode=ro", uri=True)) as source:
            self._integrity(source)
            with closing(sqlite3.connect(temporary)) as target:
                source.backup(target)
                target.execute("PRAGMA journal_mode=DELETE")
                self._integrity(target)

    def backup(self):
        """Atomically replace a verified backup, including committed WAL data.

        The source is never replaced. Restore is deliberately an operator step
        with the service stopped, after preserving the original DB and sidecars.
        """
        if self._windows is not None:
            return self._backup_windows()
        if self._directory is None or self._lock is None:
            raise StateError("backup requires an open, locked state directory")
        temporary = None
        try:
            self._validate_database_files()
            try:
                fd = _file_fd(self._directory, self.BACKUP_NAME, writable=True)
            except FileNotFoundError:
                pass
            else:
                os.close(fd)
            fd, temporary = tempfile.mkstemp(prefix=".backup-", suffix=".sqlite3", dir=self.path)
            try:
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            self._copy_backup(temporary)
            fd = _file_fd(self._directory, Path(temporary).name, writable=True)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            os.replace(Path(temporary).name, self.BACKUP_NAME,
                       src_dir_fd=self._directory, dst_dir_fd=self._directory)
            temporary = None
            os.fsync(self._directory)
            return self.path / self.BACKUP_NAME
        except (OSError, sqlite3.DatabaseError):
            raise StateError("state backup failed; the source database was not replaced") from None
        finally:
            if temporary is not None:
                for suffix in ("", "-wal", "-shm", "-journal"):
                    try:
                        os.unlink(Path(temporary).name + suffix, dir_fd=self._directory)
                    except FileNotFoundError:
                        pass

    def _backup_windows(self):
        from .windows_state import WindowsStateError
        temporary = None
        try:
            self._validate_database_files()
            self._windows.check_file(self.BACKUP_NAME, missing_ok=True)
            temporary = self._windows.new_file()
            self._copy_backup(temporary)
            result = self._windows.replace_file(temporary.name, self.BACKUP_NAME)
            temporary = None
            return result
        except (OSError, sqlite3.DatabaseError, WindowsStateError) as exc:
            error = StateError("Windows state backup failed; source database was not replaced")
            if isinstance(exc, WindowsStateError):
                error.windows_details = exc.safe_details()
            elif isinstance(exc, OSError):
                error.windows_details = {"code": "native_backup_error", "errno": exc.errno,
                                         "winerror": getattr(exc, "winerror", None)}
            else:
                error.windows_details = {"code": "sqlite_backup_error",
                                         "sqlite_errorcode": getattr(exc, "sqlite_errorcode", None)}
            raise error from None
        finally:
            if temporary is not None:
                for suffix in ("", "-wal", "-shm", "-journal"):
                    self._windows.unlink_file(temporary.name + suffix)

    def close(self):
        # Never unlink the lock: unlinking permits two owners of different inodes.
        if self._windows is not None:
            self._windows.close()
            self._windows = None
        if self._lock is not None:
            os.close(self._lock)
            self._lock = None
        if self._directory is not None:
            os.close(self._directory)
            self._directory = None

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
