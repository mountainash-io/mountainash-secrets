import pytest
from mountainash_secrets.core.errors import CapabilityError, ResolverError
from mountainash_secrets.core.protocols import ClearableStore, SecretReader
from mountainash_secrets.core.resolver import RegistryResolver


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
    r = RegistryResolver({"local": store})
    assert r.resolve("local") is store


def test_resolve_unknown_name_raises_resolver_error():
    r = RegistryResolver()
    with pytest.raises(ResolverError):
        r.resolve("missing")


def test_register_duplicate_without_replace_raises():
    r = RegistryResolver({"local": _ReaderOnly()})
    with pytest.raises(ResolverError):
        r.register("local", _ReaderOnly())


def test_register_replace_overwrites():
    r = RegistryResolver({"local": _ReaderOnly()})
    new = _ReaderOnly()
    r.register("local", new, replace=True)
    assert r.resolve("local") is new


def test_resolve_as_returns_store_when_capability_satisfied():
    store = _FullStore()
    r = RegistryResolver({"tokens": store})
    assert r.resolve_as("tokens", ClearableStore) is store


def test_resolve_as_raises_capability_error_on_shortfall():
    r = RegistryResolver({"ro": _ReaderOnly()})
    with pytest.raises(CapabilityError):
        r.resolve_as("ro", ClearableStore)


def test_resolve_as_unknown_name_raises_resolver_error():
    r = RegistryResolver()
    with pytest.raises(ResolverError):
        r.resolve_as("missing", SecretReader)
