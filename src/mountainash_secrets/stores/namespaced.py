"""NamespacedStore — a key-prefixing wrapper that isolates consumers sharing a store."""
from __future__ import annotations

import typing as t

if t.TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from ..core.protocols import ClearableStore, SecretRecord

__all__ = ["NamespacedStore"]


class NamespacedStore:
    """Prepends ``{prefix}.`` to every key and forwards to a wrapped ClearableStore.

    Lets two consumers (e.g. OAuth tokens under 'oauth', settings credentials
    under 'cred') share one underlying store without key collisions.
    """

    def __init__(self, inner: ClearableStore, prefix: str) -> None:
        self._inner = inner
        self._prefix = prefix

    def _k(self, key: str) -> str:
        return f"{self._prefix}.{key}"

    def get(self, key: str) -> SecretRecord | None:
        return self._inner.get(self._k(key))

    def set(self, key: str, data: SecretRecord) -> None:
        self._inner.set(self._k(key), data)

    def delete(self, key: str) -> None:
        self._inner.delete(self._k(key))

    def is_cleared(self, key: str) -> bool:
        return self._inner.is_cleared(self._k(key))

    def transaction(self, key: str) -> AbstractContextManager[None]:
        return self._inner.transaction(self._k(key))
