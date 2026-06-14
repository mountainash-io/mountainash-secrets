from mountainash_secrets.core.protocols import ClearableStore
from mountainash_secrets.stores.memory import InMemoryStore
from mountainash_secrets.stores.namespaced import NamespacedStore


def test_prefixes_keys_on_inner_store():
    inner = InMemoryStore()
    ns = NamespacedStore(inner, "oauth")
    ns.set("garmin", {"token": "abc"})
    assert inner.get("oauth.garmin") == {"token": "abc"}


def test_get_reads_through_prefix():
    inner = InMemoryStore()
    ns = NamespacedStore(inner, "oauth")
    ns.set("garmin", {"token": "abc"})
    assert ns.get("garmin") == {"token": "abc"}


def test_two_namespaces_over_one_inner_do_not_collide():
    inner = InMemoryStore()
    oauth = NamespacedStore(inner, "oauth")
    cred = NamespacedStore(inner, "cred")
    oauth.set("github", {"token": "T"})
    cred.set("github", {"password": "P"})
    assert oauth.get("github") == {"token": "T"}
    assert cred.get("github") == {"password": "P"}


def test_delete_and_is_cleared_are_namespaced():
    inner = InMemoryStore()
    ns = NamespacedStore(inner, "oauth")
    ns.set("x", {"a": 1})
    ns.delete("x")
    assert ns.get("x") is None
    assert ns.is_cleared("x") is True
    assert inner.is_cleared("oauth.x") is True


def test_transaction_forwards_under_prefix():
    inner = InMemoryStore()
    ns = NamespacedStore(inner, "oauth")
    with ns.transaction("x"):
        ns.set("x", {"a": 1})
    assert ns.get("x") == {"a": 1}


def test_wrapper_satisfies_clearable_store():
    assert isinstance(NamespacedStore(InMemoryStore(), "oauth"), ClearableStore)
