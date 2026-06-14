"""Strict-fetch helper. ``get`` returns None for a missing key; ``require`` raises."""
from __future__ import annotations

import typing as t

from .errors import SecretNotFoundError

if t.TYPE_CHECKING:
    from .protocols import SecretReader, SecretRecord

__all__ = ["require"]


def require(store: SecretReader, key: str) -> SecretRecord:
    """Return the live record for ``key`` or raise SecretNotFoundError."""
    record = store.get(key)
    if record is None:
        raise SecretNotFoundError(f"No live secret for key: {key!r}")
    return record
