import pytest
from mountainash_secrets.core.access import require
from mountainash_secrets.core.errors import SecretNotFoundError
from mountainash_secrets.stores.memory import InMemorySecretStore


def test_require_returns_record_when_present():
    s = InMemorySecretStore()
    s.set("k", {"a": 1})
    assert require(s, "k") == {"a": 1}


def test_require_raises_when_absent():
    with pytest.raises(SecretNotFoundError):
        require(InMemorySecretStore(), "missing")


def test_require_raises_after_delete():
    s = InMemorySecretStore()
    s.set("k", {"a": 1})
    s.delete("k")
    with pytest.raises(SecretNotFoundError):
        require(s, "k")
