from mountainash_secrets.core.protocols import ClearableSecretStore
from mountainash_secrets.stores.memory import InMemorySecretStore
from mountainash_secrets.stores.namespaced import NamespacedSecretStore


def test_prefixes_keys_on_inner_store():
    inner = InMemorySecretStore()
    ns = NamespacedSecretStore(inner, "oauth")
    ns.set("garmin", {"token": "abc"})
    assert inner.get("oauth.garmin") == {"token": "abc"}


def test_get_reads_through_prefix():
    inner = InMemorySecretStore()
    ns = NamespacedSecretStore(inner, "oauth")
    ns.set("garmin", {"token": "abc"})
    assert ns.get("garmin") == {"token": "abc"}


def test_two_namespaces_over_one_inner_do_not_collide():
    inner = InMemorySecretStore()
    oauth = NamespacedSecretStore(inner, "oauth")
    cred = NamespacedSecretStore(inner, "cred")
    oauth.set("github", {"token": "T"})
    cred.set("github", {"password": "P"})
    assert oauth.get("github") == {"token": "T"}
    assert cred.get("github") == {"password": "P"}


def test_delete_and_is_cleared_are_namespaced():
    inner = InMemorySecretStore()
    ns = NamespacedSecretStore(inner, "oauth")
    ns.set("x", {"a": 1})
    ns.delete("x")
    assert ns.get("x") is None
    assert ns.is_cleared("x") is True
    assert inner.is_cleared("oauth.x") is True


def test_transaction_forwards_under_prefix():
    inner = InMemorySecretStore()
    ns = NamespacedSecretStore(inner, "oauth")
    with ns.transaction("x"):
        ns.set("x", {"a": 1})
    assert ns.get("x") == {"a": 1}


def test_wrapper_satisfies_clearable_store():
    assert isinstance(NamespacedSecretStore(InMemorySecretStore(), "oauth"), ClearableSecretStore)
