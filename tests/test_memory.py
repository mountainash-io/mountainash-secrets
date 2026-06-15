from mountainash_secrets.core.protocols import ClearableSecretStore
from mountainash_secrets.stores.memory import InMemorySecretStore


def test_set_then_get_round_trips():
    s = InMemorySecretStore()
    s.set("k", {"a": 1, "b": ["x", {"c": True}]})
    assert s.get("k") == {"a": 1, "b": ["x", {"c": True}]}


def test_get_unknown_returns_none():
    assert InMemorySecretStore().get("missing") is None


def test_delete_makes_get_none_and_marks_cleared():
    s = InMemorySecretStore()
    s.set("k", {"a": 1})
    s.delete("k")
    assert s.get("k") is None
    assert s.is_cleared("k") is True


def test_never_set_is_not_cleared():
    assert InMemorySecretStore().is_cleared("k") is False


def test_set_after_delete_clears_tombstone():
    s = InMemorySecretStore()
    s.set("k", {"a": 1})
    s.delete("k")
    s.set("k", {"a": 2})
    assert s.is_cleared("k") is False
    assert s.get("k") == {"a": 2}


def test_get_returns_deeply_isolated_copy():
    # Mutating a NESTED structure of the returned record must not affect the
    # store — guards against a shallow copy (SecretRecord supports nesting).
    s = InMemorySecretStore()
    s.set("k", {"a": 1, "nested": {"x": [1, 2]}})
    got = s.get("k")
    got["nested"]["x"].append(999)
    assert s.get("k") == {"a": 1, "nested": {"x": [1, 2]}}


def test_set_stores_deeply_isolated_copy():
    # Mutating a NESTED structure of the input after set must not leak in.
    s = InMemorySecretStore()
    payload = {"a": 1, "nested": {"x": [1, 2]}}
    s.set("k", payload)
    payload["nested"]["x"].append(999)
    assert s.get("k") == {"a": 1, "nested": {"x": [1, 2]}}


def test_transaction_is_a_context_manager():
    s = InMemorySecretStore()
    with s.transaction("k"):
        s.set("k", {"a": 1})
    assert s.get("k") == {"a": 1}


def test_satisfies_clearable_store():
    assert isinstance(InMemorySecretStore(), ClearableSecretStore)
