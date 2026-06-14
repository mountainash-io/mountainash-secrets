"""Exception hierarchy for the secret-store port.

Error messages MUST NOT include secret record values.
"""
from __future__ import annotations

__all__ = [
    "SecretStoreError",
    "ResolverError",
    "CapabilityError",
    "StoreUnavailableError",
    "SecretNotFoundError",
]


class SecretStoreError(Exception):
    """Base of every error raised by this package."""


class ResolverError(SecretStoreError):
    """Raised when a store name is unknown or already registered."""


class CapabilityError(SecretStoreError):
    """Raised when a named store lacks a requested capability rung."""


class StoreUnavailableError(SecretStoreError):
    """Raised when a backend/transport/IO operation fails."""


class SecretNotFoundError(SecretStoreError):
    """Raised by the strict ``require()`` helper when a key has no live record."""
