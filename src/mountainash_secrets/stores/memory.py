"""InMemoryStore — full ClearableSecretStore; the canonical single-process test double."""
from __future__ import annotations

import copy
import threading
import typing as t
from contextlib import contextmanager

if t.TYPE_CHECKING:
    from collections.abc import Iterator

    from ..core.protocols import SecretRecord

__all__ = ["InMemorySecretStore"]


class InMemorySecretStore:
    """Stores records in a dict. Single-process; transaction uses per-key locks.

    Records are deep-copied on set and get so callers cannot mutate stored state
    through a shared reference.
    """

    def __init__(self) -> None:
        self._data: dict[str, SecretRecord] = {}
        self._cleared: set[str] = set()
        self._key_locks: dict[str, threading.RLock] = {}
        self._guard = threading.Lock()

    def get(self, key: str) -> SecretRecord | None:
        value = self._data.get(key)
        return copy.deepcopy(value) if value is not None else None

    def set(self, key: str, data: SecretRecord) -> None:
        if not isinstance(data, dict):
            raise ValueError(f"SecretRecord must be a mapping, got {type(data).__name__}")
        self._data[key] = copy.deepcopy(data)
        self._cleared.discard(key)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._cleared.add(key)

    def is_cleared(self, key: str) -> bool:
        return key in self._cleared

    @contextmanager
    def transaction(self, key: str) -> Iterator[None]:
        with self._guard:
            lock = self._key_locks.setdefault(key, threading.RLock())
        with lock:
            yield
