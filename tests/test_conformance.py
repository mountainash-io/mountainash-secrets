"""Behavioral conformance suite — runs identical semantics over every writer store."""
import threading
import time

import pytest
from mountainash_secrets.stores.filesystem import FilesystemStore
from mountainash_secrets.stores.memory import InMemorySecretStore
from mountainash_secrets.stores.namespaced import NamespacedSecretStore


@pytest.fixture(params=["memory", "filesystem"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemorySecretStore()
    return FilesystemStore(tmp_path)


def test_set_get_round_trips_nested_json_record(store):
    record = {
        "access_token": "tok",
        "expires_at": 1718000000,          # int epoch — JSON-native convention
        "scopes": ["read", "write"],
        "meta": {"nested": True, "n": 1.5, "absent": None},
    }
    store.set("svc.acct", record)
    assert store.get("svc.acct") == record


def test_get_unknown_key_returns_none(store):
    assert store.get("never.set") is None


def test_delete_yields_none_and_tombstone(store):
    store.set("k", {"a": 1})
    store.delete("k")
    assert store.get("k") is None
    assert store.is_cleared("k") is True


def test_never_set_is_not_cleared(store):
    assert store.is_cleared("fresh") is False


def test_rewrite_after_delete_clears_tombstone(store):
    store.set("k", {"a": 1})
    store.delete("k")
    store.set("k", {"a": 2})
    assert store.is_cleared("k") is False
    assert store.get("k") == {"a": 2}


def test_transaction_round_trip(store):
    with store.transaction("k"):
        store.set("k", {"count": 1})
    assert store.get("k") == {"count": 1}


def test_transaction_serializes_concurrent_read_modify_write(store):
    # Real atomicity check: N threads each do `read; sleep; write current+1`
    # entirely inside transaction(). A no-op (nullcontext) transaction would
    # lose updates and fail; correct serialization yields the exact total.
    store.set("k", {"n": 0})
    workers, increments = 8, 5

    def worker():
        for _ in range(increments):
            with store.transaction("k"):
                current = store.get("k")["n"]
                time.sleep(0.001)  # widen the race window
                store.set("k", {"n": current + 1})

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for tr in threads:
        tr.start()
    for tr in threads:
        tr.join()

    assert store.get("k") == {"n": workers * increments}


def test_namespace_isolation_over_shared_store(store):
    oauth = NamespacedSecretStore(store, "oauth")
    cred = NamespacedSecretStore(store, "cred")
    oauth.set("github", {"token": "T"})
    cred.set("github", {"password": "P"})
    assert oauth.get("github") == {"token": "T"}
    assert cred.get("github") == {"password": "P"}


@pytest.mark.parametrize("bad", [None, ["a"], "scalar", 42])
def test_set_rejects_non_mapping(store, bad):
    # A present key must always map to a non-None record (spec §4.2/§6), so
    # set() rejects non-mapping values instead of writing a ghost/corrupt entry.
    with pytest.raises(ValueError):
        store.set("k", bad)
