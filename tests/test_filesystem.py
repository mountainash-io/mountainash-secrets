import os

import pytest
from mountainash_secrets.core.protocols import ClearableStore
from mountainash_secrets.stores.filesystem import FilesystemStore


def test_set_then_get_round_trips(tmp_path):
    s = FilesystemStore(tmp_path)
    s.set("svc.acct", {"token": "abc", "n": 3})
    assert s.get("svc.acct") == {"token": "abc", "n": 3}


def test_get_unknown_returns_none(tmp_path):
    assert FilesystemStore(tmp_path).get("nope") is None


def test_delete_makes_get_none_and_marks_cleared(tmp_path):
    s = FilesystemStore(tmp_path)
    s.set("k", {"a": 1})
    s.delete("k")
    assert s.get("k") is None
    assert s.is_cleared("k") is True


def test_set_after_delete_removes_tombstone(tmp_path):
    s = FilesystemStore(tmp_path)
    s.set("k", {"a": 1})
    s.delete("k")
    s.set("k", {"a": 2})
    assert s.is_cleared("k") is False
    assert s.get("k") == {"a": 2}


def test_file_is_written_with_owner_only_permissions(tmp_path):
    s = FilesystemStore(tmp_path)
    s.set("k", {"a": 1})
    yaml_path = tmp_path / "k.yaml"
    assert yaml_path.exists()
    assert (yaml_path.stat().st_mode & 0o077) == 0


def test_invalid_key_segment_raises(tmp_path):
    s = FilesystemStore(tmp_path)
    with pytest.raises(ValueError):
        s.set("Bad-Key", {"a": 1})


def test_symlinked_file_is_rejected_on_get(tmp_path):
    s = FilesystemStore(tmp_path)
    s.set("k", {"a": 1})
    real = tmp_path / "k.yaml"
    link = tmp_path / "evil.yaml"
    link.symlink_to(real)
    with pytest.raises(PermissionError):
        s.get("evil")


def test_unsafe_permissions_rejected_on_get(tmp_path):
    s = FilesystemStore(tmp_path)
    s.set("k", {"a": 1})
    os.chmod(tmp_path / "k.yaml", 0o644)
    with pytest.raises(PermissionError):
        s.get("k")


def test_transaction_serializes_read_modify_write(tmp_path):
    s = FilesystemStore(tmp_path)
    with s.transaction("k"):
        s.set("k", {"count": 1})
    assert s.get("k") == {"count": 1}


def test_non_mapping_on_disk_raises(tmp_path):
    from mountainash_secrets.core.errors import StoreUnavailableError

    s = FilesystemStore(tmp_path)
    s.set("k", {"a": 1})
    path = tmp_path / "k.yaml"
    path.write_text("- a\n- b\n")  # a YAML list, not a mapping
    os.chmod(path, 0o600)
    with pytest.raises(StoreUnavailableError):
        s.get("k")


def test_set_rejects_symlinked_temp_file(tmp_path):
    # A pre-planted symlink at the temp path must NOT be followed (O_NOFOLLOW),
    # so the secret is never written through it to an attacker-chosen target.
    s = FilesystemStore(tmp_path)
    target = tmp_path / "target.txt"
    (tmp_path / ".k.tmp").symlink_to(target)
    with pytest.raises(OSError):
        s.set("k", {"token": "secret"})
    assert not target.exists()


def test_get_rejects_non_regular_file(tmp_path):
    # A directory (or other non-regular file) where a credential file is
    # expected is rejected rather than read.
    s = FilesystemStore(tmp_path)
    (tmp_path / "d.yaml").mkdir(mode=0o700)
    with pytest.raises(PermissionError):
        s.get("d")


def test_satisfies_clearable_store(tmp_path):
    assert isinstance(FilesystemStore(tmp_path), ClearableStore)
