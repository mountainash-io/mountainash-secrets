"""Canonical key-segment grammar + helpers shared across stores.

``FilesystemSecretStore`` addresses records by dot-separated keys whose every
segment must match ``[a-z0-9_]+``. Consumers that build keys from arbitrary
identifiers — user ids, emails, opaque OAuth subjects — use :func:`to_key_segment`
to encode any string into a single valid segment, deterministically and
collision-resistantly, instead of hand-rolling the encoding per consumer.
"""
from __future__ import annotations

import base64
import hashlib
import re

__all__ = ["SEGMENT_PATTERN", "is_valid_segment", "validate_segment", "to_key_segment"]

SEGMENT_PATTERN = re.compile(r"^[a-z0-9_]+$")
_HASH_PREFIX = "h_"


def is_valid_segment(name: str) -> bool:
    """Return True iff ``name`` is a valid single key segment (``[a-z0-9_]+``)."""
    return bool(SEGMENT_PATTERN.match(name))


def validate_segment(name: str) -> None:
    """Raise ``ValueError`` unless ``name`` is a valid single key segment."""
    if not is_valid_segment(name):
        raise ValueError(f"Invalid key segment: {name!r} — must match [a-z0-9_]+")


def to_key_segment(raw: str) -> str:
    """Encode an arbitrary string into one valid key segment, deterministically.

    An already-valid segment passes through unchanged, so keys stay
    human-readable on disk — *unless* it begins with the reserved ``h_`` prefix,
    in which case it is encoded too. Everything else (emails, uppercase, UUIDs,
    opaque subjects, the empty string) becomes a stable ``h_<base32(sha256)>``
    segment. Encoded outputs always start with ``h_`` and pass-through outputs
    never do, so the two output spaces are disjoint and the mapping is effectively
    injective (collisions require a SHA-256 collision).
    """
    if is_valid_segment(raw) and not raw.startswith(_HASH_PREFIX):
        return raw
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return _HASH_PREFIX + base64.b32encode(digest).decode("ascii").rstrip("=").lower()
