"""Exception hierarchy for the secret-store port.

Error messages MUST NOT include secret record values.
"""

from __future__ import annotations

__all__ = [
    "SecretStoreError",
    "SecretResolverError",
    "SecretCapabilityError",
    "SecretStoreUnavailableError",
    "SecretNotFoundError",
]


class SecretStoreError(Exception):
    """Base of every error raised by this package."""


class SecretResolverError(SecretStoreError):
    """Raised when a store name is unknown or already registered."""


class SecretCapabilityError(SecretStoreError):
    """Raised when a named store lacks a requested capability rung."""


class SecretStoreUnavailableError(SecretStoreError):
    """Backend failure with a machine-readable ``reason``.

    Ordinary positional message construction remains supported. Filesystem
    reasons distinguish unavailable/closed/unsupported state, decode/YAML/shape
    corruption, and committed writes whose marker cleanup failed. Consumers
    must not parse message text or assume a failure means no mutation occurred.
    """

    def __init__(self, *args: object, reason: str = "unavailable") -> None:
        super().__init__(*args)
        self.reason = reason


class SecretNotFoundError(SecretStoreError):
    """Raised by the strict ``require()`` helper when a key has no live record."""
