"""FilesystemStore — secure YAML credential storage on disk (full ClearableStore).

Ported from mountainash_settings.secrets.filesystem.FilesystemBackend.
Atomicity (transaction) uses fcntl.flock — atomic across processes on a LOCAL
filesystem only; NOT safe over NFS/CIFS.
"""
from __future__ import annotations

import fcntl
import os
import re
import typing as t
from contextlib import contextmanager
from pathlib import Path

import yaml

from ..core.errors import StoreUnavailableError

if t.TYPE_CHECKING:
    from collections.abc import Iterator

    from ..core.protocols import SecretRecord

__all__ = ["FilesystemStore"]

_VALID_SEGMENT = re.compile(r"^[a-z0-9_]+$")


def _validate_segment(name: str) -> None:
    if not _VALID_SEGMENT.match(name):
        raise ValueError(f"Invalid key segment: {name!r} — must match [a-z0-9_]+")


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


class FilesystemStore:
    """Stores records as YAML files with secure (0o600/0o700) permissions.

    Note: a broken symlink (existing link, missing target) reads as absent
    (``get`` returns None via the ``exists()`` check); a symlink whose target
    exists is rejected with PermissionError to defeat file-swap attacks.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)

    def get(self, key: str) -> SecretRecord | None:
        yaml_path, _, _, _ = _key_to_paths(self.base_dir, key)
        if not yaml_path.exists():
            return None
        if yaml_path.is_symlink():
            raise PermissionError(f"Credential file is a symlink: {yaml_path}")
        mode = yaml_path.stat().st_mode
        if mode & 0o077:
            raise PermissionError(f"Credential file has unsafe permissions: {yaml_path}")
        with yaml_path.open("r") as fh:
            data = yaml.safe_load(fh)
        if data is None:
            return None
        if not isinstance(data, dict):
            raise StoreUnavailableError(
                f"Corrupt secret record (not a mapping): {yaml_path}"
            )
        return data

    def set(self, key: str, data: SecretRecord) -> None:
        yaml_path, tmp_path, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(yaml_path.parent), 0o700)
        try:
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
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
        fd = os.open(str(tombstone_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)

    def is_cleared(self, key: str) -> bool:
        _, _, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        return tombstone_path.exists()

    @contextmanager
    def transaction(self, key: str) -> Iterator[None]:
        _, _, _, lock_path = _key_to_paths(self.base_dir, key)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(lock_path.parent), 0o700)
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
