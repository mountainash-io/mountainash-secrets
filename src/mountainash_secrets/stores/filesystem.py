"""FilesystemStore — secure YAML credential storage on disk (full ClearableStore).

Supersedes mountainash_settings.secrets.filesystem.FilesystemBackend, hardened
against symlink attacks: every open uses O_NOFOLLOW, and get() opens-by-fd then
fstats that fd (no check-then-open TOCTOU window). Atomicity (transaction) uses
fcntl.flock — atomic across processes on a LOCAL filesystem only; NOT safe over
NFS/CIFS, and cooperative (direct get/set/delete do not take the lock).
"""
from __future__ import annotations

import errno
import fcntl
import os
import stat
import typing as t
from contextlib import contextmanager
from pathlib import Path

import yaml

from ..core.errors import SecretStoreUnavailableError
from ..core.keys import validate_segment as _validate_segment

if t.TYPE_CHECKING:
    from collections.abc import Iterator

    from ..core.protocols import SecretRecord

__all__ = ["FilesystemSecretStore"]


def _key_to_paths(base_dir: Path, key: str) -> tuple[Path, Path, Path, Path]:
    """Convert a dot-separated key to (yaml, tmp, tombstone, lock) paths.

    - "simple"               -> base_dir/simple.yaml
    - "domain.leaf"          -> base_dir/domain/leaf.yaml
    - "domain.provider.user" -> base_dir/domain/provider-user.yaml
    """
    parts = key.split(".")
    for part in parts:
        _validate_segment(part)

    if len(parts) == 1:
        directory = base_dir
        stem = parts[0]
    elif len(parts) == 2:
        directory = base_dir / parts[0]
        stem = parts[1]
    else:
        directory = base_dir / parts[0]
        stem = "-".join(parts[1:])

    yaml_path = directory / f"{stem}.yaml"
    tmp_path = directory / f".{stem}.tmp"
    tombstone_path = directory / f".{stem}.cleared"
    lock_path = directory / f".{stem}.lock"
    return yaml_path, tmp_path, tombstone_path, lock_path


class FilesystemSecretStore:
    """Stores records as YAML files with secure (0o600/0o700) permissions.

    Note: any symlink at the credential path (broken or not) is rejected with
    PermissionError — O_NOFOLLOW refuses to follow the final component, so a
    file cannot be swapped for a symlink between the check and the open.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)

    def get(self, key: str) -> SecretRecord | None:
        yaml_path, _, _, _ = _key_to_paths(self.base_dir, key)
        try:
            fd = os.open(str(yaml_path), os.O_RDONLY | os.O_NOFOLLOW)
        except FileNotFoundError:
            return None
        except OSError as exc:
            if exc.errno == errno.ELOOP:
                raise PermissionError(f"Credential file is a symlink: {yaml_path}") from exc
            raise
        # Validate the OPENED descriptor before reading — there is no
        # check-then-open window, and fstat must precede fdopen (fdopen on a
        # directory fd would raise before our type check could run).
        fh = None
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode):
                raise PermissionError(f"Credential file is not a regular file: {yaml_path}")
            if st.st_mode & 0o077:
                raise PermissionError(f"Credential file has unsafe permissions: {yaml_path}")
            fh = os.fdopen(fd, "r")
            data = yaml.safe_load(fh)
        finally:
            if fh is not None:
                fh.close()  # closes the underlying fd
            else:
                os.close(fd)  # fdopen never took ownership
        if data is None:
            return None
        if not isinstance(data, dict):
            raise SecretStoreUnavailableError(
                f"Corrupt secret record (not a mapping): {yaml_path}"
            )
        return data

    def set(self, key: str, data: SecretRecord) -> None:
        if not isinstance(data, dict):
            raise ValueError(f"SecretRecord must be a mapping, got {type(data).__name__}")
        yaml_path, tmp_path, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(yaml_path.parent), 0o700)
        try:
            fd = os.open(
                str(tmp_path),
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
                0o600,
            )
            with os.fdopen(fd, "w") as fh:
                yaml.safe_dump(data, fh)
            os.replace(str(tmp_path), str(yaml_path))
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise
        if tombstone_path.exists():
            tombstone_path.unlink()

    def delete(self, key: str) -> None:
        yaml_path, _, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        if yaml_path.exists():
            yaml_path.unlink()
        tombstone_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(tombstone_path.parent), 0o700)
        fd = os.open(
            str(tombstone_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW,
            0o600,
        )
        os.close(fd)

    def is_cleared(self, key: str) -> bool:
        _, _, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        return tombstone_path.exists()

    @contextmanager
    def transaction(self, key: str) -> Iterator[None]:
        _, _, _, lock_path = _key_to_paths(self.base_dir, key)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(lock_path.parent), 0o700)
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
