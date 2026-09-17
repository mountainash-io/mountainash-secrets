"""Private YAML records beneath an application-provisioned, pinned POSIX root.

Startup links are trusted application configuration; internal links are refused.
Transactions are cooperative flock coordination on local filesystems, not NFS/CIFS.
Identity checks detect substitutions at inspection, not hostile later mutations.
"""

from __future__ import annotations

import errno
import fcntl
import os
import secrets
import stat
import threading
import typing as t
from contextlib import ExitStack, contextmanager
from pathlib import Path

import yaml

from ..core.errors import SecretStoreUnavailableError
from ..core.keys import validate_segment as _validate_segment

if t.TYPE_CHECKING:
    from collections.abc import Iterator
    from types import TracebackType

    from ..core.protocols import SecretRecord

__all__ = ["FilesystemSecretStore"]


class _Failure(Exception):
    """Internal value-free outcome; never expose this exception to callers."""

    def __init__(self, reason: str) -> None:
        self.reason = reason


def _raise_safe(error: Exception) -> t.NoReturn:
    # Bare re-raise also removes a caller's already-active exception context.
    try:
        raise error
    except Exception as safe:
        safe.__cause__ = None
        safe.__context__ = None
        raise


@contextmanager
def _backend() -> Iterator[None]:
    """Translate only backend work, after its owned resources have been closed."""
    reason = ""
    kind = ""
    try:
        yield
    except _Failure as failure:
        reason = failure.reason
    except PermissionError:
        kind = "permission"
    except OSError as error:
        kind = "permission" if error.errno in (errno.ELOOP, errno.ENOTDIR, errno.EISDIR) else ""
        reason = "unavailable"
    except (ValueError, TypeError, OverflowError, RecursionError, yaml.YAMLError):
        reason = "unavailable"
    if kind == "permission":
        _raise_safe(PermissionError("Unsafe secret store entry"))
    if reason == "invalid_input":
        _raise_safe(ValueError("Invalid secret key or record"))
    if reason:
        _raise_safe(SecretStoreUnavailableError("Secret store operation failed", reason=reason))


def _layout(key: str) -> tuple[str | None, str]:
    parts = key.split(".")
    try:
        for part in parts:
            _validate_segment(part)
    except ValueError:
        raise _Failure("invalid_input") from None
    if len(parts) == 1:
        return None, parts[0]
    return parts[0], "-".join(parts[1:])


def _private(fd: int) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_nlink != 1:
        raise PermissionError
    return info


def _same_entry(directory: int, name: str, fd: int | None) -> None:
    """Check absence or retained private-inode identity without following links."""
    try:
        entry = os.stat(name, dir_fd=directory, follow_symlinks=False)
    except FileNotFoundError:
        if fd is None:
            return
        raise PermissionError from None
    if fd is None:
        raise PermissionError
    opened = _private(fd)
    if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
        raise PermissionError


def _file(
    resources: ExitStack,
    directory: int,
    name: str,
    *,
    create: bool = False,
    writable: bool = False,
) -> int | None:
    flags = (os.O_RDWR if writable else os.O_RDONLY) | os.O_NOFOLLOW | os.O_NONBLOCK
    if create:
        try:
            fd = os.open(name, flags | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=directory)
        except FileExistsError:
            fd = os.open(name, flags, dir_fd=directory)
    else:
        try:
            fd = os.open(name, flags, dir_fd=directory)
        except FileNotFoundError:
            return None
    resources.callback(os.close, fd)
    _private(fd)
    return fd


class FilesystemSecretStore:
    """Own a pinned root until close; applications own directory access policy.

    Use as a context manager. Changing ``base_dir`` never retargets operations.
    Close is terminal and nonwaiting; admitted operations retain their own handles.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self._mutex = threading.Lock()
        self._root: int | None = None
        with _backend(), ExitStack() as resources:
            required = (os.open, os.mkdir, os.stat, os.unlink, os.rename)
            if (
                not all(fn in os.supports_dir_fd for fn in required)
                or os.stat not in os.supports_follow_symlinks
                or not all(
                    hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK")
                )
                or not hasattr(fcntl, "flock")
            ):
                raise _Failure("unsupported_filesystem")
            try:
                fd = os.open(self.base_dir, os.O_RDONLY | os.O_DIRECTORY)
            except OSError:
                raise _Failure("unavailable") from None
            resources.callback(os.close, fd)
            if not stat.S_ISDIR(os.fstat(fd).st_mode):
                raise _Failure("unavailable")
            self._root = fd
            resources.pop_all()

    def close(self) -> None:
        with self._mutex:
            fd, self._root = self._root, None
        with _backend():
            if fd is not None:
                os.close(fd)

    def __enter__(self) -> FilesystemSecretStore:
        with _backend(), self._mutex:
            if self._root is None:
                raise _Failure("store_closed")
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self.close()
        else:
            try:
                self.close()
            except SecretStoreUnavailableError:
                pass  # Never replace the caller's body exception with teardown failure.

    def _directory(
        self,
        resources: ExitStack,
        key: str,
        *,
        create: bool,
    ) -> tuple[int | None, str]:
        with self._mutex:
            if self._root is None:
                raise _Failure("store_closed")
            root = os.dup(self._root)
        resources.callback(os.close, root)
        namespace, stem = _layout(key)
        if namespace is None:
            return root, stem
        if create:
            try:
                os.mkdir(namespace, 0o777, dir_fd=root)
            except FileExistsError:
                pass
        try:
            directory = os.open(
                namespace, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root
            )
        except FileNotFoundError:
            if create:
                raise
            return None, stem
        resources.callback(os.close, directory)
        if not stat.S_ISDIR(os.fstat(directory).st_mode):
            raise PermissionError
        return directory, stem

    def get(self, key: str) -> SecretRecord | None:
        with _backend(), ExitStack() as resources:
            directory, stem = self._directory(resources, key, create=False)
            if directory is None:
                return None
            fd = _file(resources, directory, f"{stem}.yaml")
            if fd is None:
                return None
            reason = ""
            with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as stream:
                try:
                    data = yaml.safe_load(stream)
                except UnicodeDecodeError:
                    reason = "decode_error"
                except (yaml.YAMLError, ValueError, TypeError, OverflowError, RecursionError):
                    reason = "malformed_yaml"
            if reason:
                raise _Failure(reason)
            if not isinstance(data, dict):
                raise _Failure("invalid_record_shape")
            return data
        return None  # _backend always raises on failure.

    def set(self, key: str, data: SecretRecord) -> None:
        with _backend(), ExitStack() as resources:
            # Validate input after admission but before any namespace work.
            if not isinstance(data, dict):
                with self._mutex:
                    if self._root is None:
                        raise _Failure("store_closed")
                raise _Failure("invalid_input")
            directory, stem = self._directory(resources, key, create=True)
            assert directory is not None
            credential, marker = f"{stem}.yaml", f".{stem}.cleared"
            previous = _file(resources, directory, credential)
            tombstone = _file(resources, directory, marker)
            temporary = f".{stem}.{secrets.token_hex(16)}.tmp"
            fd = os.open(
                temporary,
                os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory,
            )
            resources.callback(os.close, fd)
            committed = False
            try:
                _same_entry(directory, temporary, fd)
                with os.fdopen(fd, "w", encoding="utf-8", closefd=False) as stream:
                    yaml.safe_dump(data, stream)
                    stream.flush()
                _same_entry(directory, temporary, fd)
                _same_entry(directory, credential, previous)
                _same_entry(directory, marker, tombstone)
                os.replace(temporary, credential, src_dir_fd=directory, dst_dir_fd=directory)
                committed = True
                cleanup_failed = False
                try:
                    _same_entry(directory, marker, tombstone)
                    if tombstone is not None:
                        os.unlink(marker, dir_fd=directory)
                except OSError:
                    cleanup_failed = True
                if cleanup_failed:
                    raise _Failure("write_committed_cleanup_failed")
            finally:
                if not committed:
                    _same_entry(directory, temporary, fd)
                    os.unlink(temporary, dir_fd=directory)

    def delete(self, key: str) -> None:
        with _backend(), ExitStack() as resources:
            directory, stem = self._directory(resources, key, create=True)
            assert directory is not None
            credential, marker = f"{stem}.yaml", f".{stem}.cleared"
            tombstone = _file(resources, directory, marker)
            previous = _file(resources, directory, credential)
            _same_entry(directory, marker, tombstone)
            _same_entry(directory, credential, previous)
            if previous is not None:
                os.unlink(credential, dir_fd=directory)
            if tombstone is None:
                tombstone = _file(resources, directory, marker, create=True)
            _same_entry(directory, marker, tombstone)

    def is_cleared(self, key: str) -> bool:
        with _backend(), ExitStack() as resources:
            directory, stem = self._directory(resources, key, create=False)
            if directory is None:
                return False
            name = f".{stem}.cleared"
            marker = _file(resources, directory, name)
            _same_entry(directory, name, marker)
            return marker is not None
        return False

    @contextmanager
    def transaction(self, key: str) -> Iterator[None]:
        resources = ExitStack()
        acquired = False
        try:
            with _backend():
                try:
                    directory, stem = self._directory(resources, key, create=True)
                    assert directory is not None
                    name = f".{stem}.lock"
                    fd = _file(resources, directory, name, create=True, writable=True)
                    assert fd is not None
                    _same_entry(directory, name, fd)
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    acquired = True
                finally:
                    if not acquired:
                        resources.close()
            completed = False
            try:
                yield
                completed = True
            finally:
                try:
                    with _backend():
                        try:
                            fcntl.flock(fd, fcntl.LOCK_UN)
                        finally:
                            resources.close()
                except (SecretStoreUnavailableError, PermissionError):
                    if completed:
                        raise
        finally:
            # Normally empty; also covers cancellation during setup.
            resources.close()
