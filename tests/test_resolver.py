import pytest
from mountainash_secrets.core.errors import SecretCapabilityError, SecretResolverError
from mountainash_secrets.core.protocols import ClearableSecretStore, SecretReader
from mountainash_secrets.core.resolver import SecretRegistryResolver


class _ReaderOnly:
    def get(self, key):
        return None


class _FullStore(_ReaderOnly):
    def set(self, key, data):
        pass

    def delete(self, key):
        pass

    def transaction(self, key):
        from contextlib import nullcontext

        return nullcontext()

    def is_cleared(self, key):
        return False


def test_resolve_returns_registered_store():
    store = _ReaderOnly()
    r = SecretRegistryResolver({"local": store})
    assert r.resolve("local") is store


def test_resolve_unknown_name_raises_resolver_error():
    r = SecretRegistryResolver()
    with pytest.raises(SecretResolverError):
        r.resolve("missing")


def test_register_duplicate_without_replace_raises():
    r = SecretRegistryResolver({"local": _ReaderOnly()})
    with pytest.raises(SecretResolverError):
        r.register("local", _ReaderOnly())


def test_register_replace_overwrites():
    r = SecretRegistryResolver({"local": _ReaderOnly()})
    new = _ReaderOnly()
    r.register("local", new, replace=True)
    assert r.resolve("local") is new


def test_resolve_as_returns_store_when_capability_satisfied():
    store = _FullStore()
    r = SecretRegistryResolver({"tokens": store})
    assert r.resolve_as("tokens", ClearableSecretStore) is store


def test_resolve_as_raises_capability_error_on_shortfall():
    r = SecretRegistryResolver({"ro": _ReaderOnly()})
    with pytest.raises(SecretCapabilityError):
        r.resolve_as("ro", ClearableSecretStore)


def test_resolve_as_unknown_name_raises_resolver_error():
    r = SecretRegistryResolver()
    with pytest.raises(SecretResolverError):
        r.resolve_as("missing", SecretReader)
