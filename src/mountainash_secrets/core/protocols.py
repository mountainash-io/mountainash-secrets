"""The capability-graded secret-store port.

`runtime_checkable` checks method NAMES only — not signatures or semantics.
Semantic conformance is covered by tests/test_conformance.py, not by isinstance.
"""
from __future__ import annotations

import typing as t
from contextlib import AbstractContextManager

__all__ = [
    "JSONValue",
    "SecretRecord",
    "SecretReader",
    "SecretWriter",
    "ClearableSecretStore",
    "VersionedSecretReader",
]

JSONValue = t.Union[
    str, int, float, bool, None, t.List["JSONValue"], t.Dict[str, "JSONValue"]
]
# A secret record is a mapping of JSON-native values. Stores MUST round-trip
# JSON-native values losslessly; callers encode datetimes (int/ISO str) and
# binary (base64 str) themselves.
SecretRecord = t.Dict[str, "JSONValue"]


@t.runtime_checkable
class SecretReader(t.Protocol):
    """Read a live secret record by key. The base capability."""

    def get(self, key: str) -> SecretRecord | None:
        """Return the live record, or None if no live record exists."""
        ...


@t.runtime_checkable
class SecretWriter(SecretReader, t.Protocol):
    """Read + mutate. ``transaction`` is the atomicity primitive."""

    def set(self, key: str, data: SecretRecord) -> None: ...

    def delete(self, key: str) -> None: ...

    def transaction(self, key: str) -> AbstractContextManager[None]: ...


@t.runtime_checkable
class ClearableSecretStore(SecretWriter, t.Protocol):
    """Distinguishes 'deliberately cleared' (tombstone) from 'never set'."""

    def is_cleared(self, key: str) -> bool: ...


@t.runtime_checkable
class VersionedSecretReader(SecretReader, t.Protocol):
    """Vault-style versioned read (additive; not all stores support it)."""

    def get_version(self, key: str, version: str) -> SecretRecord | None: ...

    def list_versions(self, key: str) -> list[str]: ...
