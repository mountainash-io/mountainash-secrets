import pytest

from mountainash_secrets.core.access import require
from mountainash_secrets.core.errors import SecretNotFoundError
from mountainash_secrets.stores.memory import InMemoryStore


def test_require_returns_record_when_present():
    s = InMemoryStore()
    s.set("k", {"a": 1})
    assert require(s, "k") == {"a": 1}


def test_require_raises_when_absent():
    with pytest.raises(SecretNotFoundError):
        require(InMemoryStore(), "missing")


def test_require_raises_after_delete():
    s = InMemoryStore()
    s.set("k", {"a": 1})
    s.delete("k")
    with pytest.raises(SecretNotFoundError):
        require(s, "k")
