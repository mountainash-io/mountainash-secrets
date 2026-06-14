"""EnvReader — read-only SecretReader backed by environment variables.

A key like "db.password" maps to env var "{prefix}DB_PASSWORD". A present
variable returns ``{"value": <string>}``; an absent one returns None.
"""
from __future__ import annotations

import os
import typing as t

if t.TYPE_CHECKING:
    from ..core.protocols import SecretRecord

__all__ = ["EnvReader"]


class EnvReader:
    def __init__(self, prefix: str = "") -> None:
        self._prefix = prefix

    def _var(self, key: str) -> str:
        return f"{self._prefix}{key.upper().replace('.', '_')}"

    def get(self, key: str) -> SecretRecord | None:
        value = os.environ.get(self._var(key))
        if value is None:
            return None
        return {"value": value}
