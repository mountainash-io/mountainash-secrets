from contextlib import contextmanager

from mountainash_secrets.core.protocols import (
    ClearableStore,
    SecretReader,
    SecretWriter,
    VersionedReader,
)


class _ReaderOnly:
    def get(self, key):
        return None


class _FullStore:
    def get(self, key):
        return None

    def set(self, key, data):
        pass

    def delete(self, key):
        pass

    @contextmanager
    def transaction(self, key):
        yield

    def is_cleared(self, key):
        return False


def test_reader_only_is_reader_not_writer():
    obj = _ReaderOnly()
    assert isinstance(obj, SecretReader)
    assert not isinstance(obj, SecretWriter)
    assert not isinstance(obj, ClearableStore)


def test_full_store_satisfies_clearable_and_below():
    obj = _FullStore()
    assert isinstance(obj, SecretReader)
    assert isinstance(obj, SecretWriter)
    assert isinstance(obj, ClearableStore)


def test_full_store_is_not_versioned():
    # No get_version/list_versions → not a VersionedReader.
    assert not isinstance(_FullStore(), VersionedReader)


def test_plain_object_is_no_capability():
    assert not isinstance(object(), SecretReader)
