import os

import pytest
from mountainash_secrets.core.protocols import ClearableSecretStore
from mountainash_secrets.stores.filesystem import FilesystemSecretStore
from mountainash_secrets.core.errors import SecretStoreUnavailableError


@pytest.fixture
def store(tmp_path):
    with FilesystemSecretStore(tmp_path) as instance:
        yield instance


def test_set_then_get_round_trips(tmp_path, store):
    s = store
    s.set("svc.acct", {"token": "abc", "n": 3})
    assert s.get("svc.acct") == {"token": "abc", "n": 3}


def test_get_unknown_returns_none(store):
    assert store.get("nope") is None


def test_delete_makes_get_none_and_marks_cleared(tmp_path, store):
    s = store
    s.set("k", {"a": 1})
    s.delete("k")
    assert s.get("k") is None
    assert s.is_cleared("k") is True


def test_set_after_delete_removes_tombstone(tmp_path, store):
    s = store
    s.set("k", {"a": 1})
    s.delete("k")
    s.set("k", {"a": 2})
    assert s.is_cleared("k") is False
    assert s.get("k") == {"a": 2}


def test_file_is_written_with_owner_only_permissions(tmp_path, store):
    s = store
    s.set("k", {"a": 1})
    yaml_path = tmp_path / "k.yaml"
    assert yaml_path.exists()
    assert (yaml_path.stat().st_mode & 0o077) == 0


def test_invalid_key_segment_raises(tmp_path, store):
    s = store
    with pytest.raises(ValueError):
        s.set("Bad-Key", {"a": 1})


def test_symlinked_file_is_rejected_on_get(tmp_path, store):
    s = store
    s.set("k", {"a": 1})
    real = tmp_path / "k.yaml"
    link = tmp_path / "evil.yaml"
    link.symlink_to(real)
    with pytest.raises(PermissionError):
        s.get("evil")


def test_unsafe_permissions_rejected_on_get(tmp_path, store):
    s = store
    s.set("k", {"a": 1})
    os.chmod(tmp_path / "k.yaml", 0o644)
    with pytest.raises(PermissionError):
        s.get("k")


def test_transaction_serializes_read_modify_write(tmp_path, store):
    s = store
    with s.transaction("k"):
        s.set("k", {"count": 1})
    assert s.get("k") == {"count": 1}


def test_non_mapping_on_disk_raises(tmp_path, store):
    s = store
    s.set("k", {"a": 1})
    path = tmp_path / "k.yaml"
    path.write_text("- a\n- b\n")  # a YAML list, not a mapping
    os.chmod(path, 0o600)
    with pytest.raises(SecretStoreUnavailableError):
        s.get("k")


def test_get_rejects_non_regular_file(tmp_path, store):
    # A directory (or other non-regular file) where a credential file is
    # expected is rejected rather than read.
    s = store
    (tmp_path / "d.yaml").mkdir(mode=0o700)
    with pytest.raises(PermissionError):
        s.get("d")


def test_satisfies_clearable_store(store):
    assert isinstance(store, ClearableSecretStore)


@pytest.mark.parametrize("operation", ["get", "set", "delete", "is_cleared", "transaction"])
@pytest.mark.parametrize("ambient", [False, True])
def test_invalid_key_diagnostics_are_chain_free(tmp_path, store, operation, ambient):
    import traceback

    key = "valid.DUMMY_REJECTED_KEY!"
    before = descriptor_set()

    def invoke():
        with pytest.raises(ValueError) as caught:
            if operation == "transaction":
                with store.transaction(key):
                    pytest.fail("invalid transaction entered")
            elif operation == "set":
                store.set(key, {})
            else:
                getattr(store, operation)(key)
        error = caught.value
        assert error.__cause__ is None
        assert error.__context__ is None
        diagnostic = str(error) + repr(error) + "".join(traceback.format_exception(error))
        assert key not in diagnostic
        assert "DUMMY_CALLER_CONTEXT" not in diagnostic
        assert list(tmp_path.iterdir()) == []
        assert descriptor_set() == before

    if ambient:
        try:
            raise RuntimeError("DUMMY_CALLER_CONTEXT")
        except RuntimeError:
            invoke()
    else:
        invoke()


def call_store(store, operation, key="ns.k"):
    if operation == "transaction":
        with store.transaction(key):
            return None
    if operation == "set":
        return store.set(key, {"n": 2})
    return getattr(store, operation)(key)


@pytest.mark.parametrize("selection", ["missing", "ancestor/missing", "broken", "file"])
def test_root_requires_provisioned_directory(tmp_path, selection):
    if selection == "broken":
        (tmp_path / selection).symlink_to(tmp_path / "absent")
    elif selection == "file":
        (tmp_path / selection).write_text("sentinel")
    before = {p.name: entry_snapshot(p) for p in tmp_path.iterdir()}
    root_before = entry_snapshot(tmp_path)
    with pytest.raises(SecretStoreUnavailableError) as caught:
        FilesystemSecretStore(tmp_path / selection)
    assert caught.value.reason == "unavailable"
    assert {p.name: entry_snapshot(p) for p in tmp_path.iterdir()} == before
    assert entry_snapshot(tmp_path) == root_before


@pytest.mark.parametrize("operation", ["get", "set", "delete", "is_cleared", "transaction"])
def test_internal_namespace_link_refused(tmp_path, operation):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir(mode=0o750)
    (outside / "k.yaml").write_text("n: 1\n")
    (outside / "k.yaml").chmod(0o600)
    (root / "ns").symlink_to(outside, target_is_directory=True)
    before = {p.name: p.read_bytes() for p in outside.iterdir()}
    mode = outside.stat().st_mode
    store = FilesystemSecretStore(root)
    try:
        with pytest.raises(PermissionError):
            call_store(store, operation)
        assert {p.name: p.read_bytes() for p in outside.iterdir()} == before
        assert outside.stat().st_mode == mode
    finally:
        store.close()


@pytest.mark.parametrize("selection", ["alias", "direct", "ancestor"])
def test_root_selection_is_pinned_for_all_operations(tmp_path, selection):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(a, target_is_directory=True)
    if selection == "ancestor":
        (a / "root").mkdir()
        (b / "root").mkdir()
        configured, selected, replacement = alias / "root", a / "root", b / "root"
    else:
        configured, selected, replacement = (alias if selection == "alias" else a), a, b
    replacement.chmod(0o750)
    (replacement / "sentinel").write_bytes(b"untouched")
    replacement_before = entry_snapshot(replacement)
    sentinel_before = entry_snapshot(replacement / "sentinel")
    store = FilesystemSecretStore(configured)
    try:
        store.set("ns.k", {"n": 1})
        if selection == "direct":
            moved = tmp_path / "moved"
            a.rename(moved)
            b.rename(a)
            selected, replacement = moved, a
        else:
            alias.unlink()
            alias.symlink_to(b, target_is_directory=True)
        store.base_dir = replacement
        assert store.get("ns.k") == {"n": 1}
        with store.transaction("ns.k"):
            store.delete("ns.k")
            assert store.is_cleared("ns.k")
            store.set("ns.k", {"n": 2})
        assert store.get("ns.k") == {"n": 2}
        assert not store.is_cleared("ns.k")
        assert (selected / "ns/k.yaml").exists()
        assert [p.name for p in replacement.iterdir()] == ["sentinel"]
        assert entry_snapshot(replacement) == replacement_before
        assert entry_snapshot(replacement / "sentinel") == sentinel_before
        with FilesystemSecretStore(configured) as fresh:
            assert fresh.get("ns.k") is None
    finally:
        store.close()


def test_close_is_terminal_and_does_not_close_reused_descriptor(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir(mode=0o750)
    (outside / "sentinel").write_bytes(b"untouched")
    outside_before = entry_snapshot(outside)
    sentinel_before = entry_snapshot(outside / "sentinel")
    store = FilesystemSecretStore(root)
    context = store.transaction("ns.k")
    identity = root.stat()
    (released,) = [
        fd
        for fd in descriptor_set()
        if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) == (identity.st_dev, identity.st_ino)
    ]
    store.close()
    sentinel = os.open(outside, os.O_RDONLY | os.O_DIRECTORY)
    try:
        if sentinel != released:
            os.dup2(sentinel, released)
        for operation in ["get", "set", "delete", "is_cleared", "transaction"]:
            with pytest.raises(SecretStoreUnavailableError) as caught:
                call_store(store, operation)
            assert caught.value.reason == "store_closed"
        with pytest.raises(SecretStoreUnavailableError) as caught:
            context.__enter__()
        assert caught.value.reason == "store_closed"
        store.close()
        assert os.fstat(released).st_ino == outside.stat().st_ino
        assert entry_snapshot(outside) == outside_before
        assert entry_snapshot(outside / "sentinel") == sentinel_before
        assert list(root.iterdir()) == []
    finally:
        os.close(sentinel)
        if sentinel != released:
            os.close(released)


@pytest.mark.parametrize("kind", ["regular", "symlink", "hardlink", "fifo"])
def test_stale_predictable_temp_is_untouched(tmp_path, kind):
    stale, target = tmp_path / ".k.tmp", tmp_path / "outside"
    target.write_bytes(b"unchanged")
    if kind == "regular":
        stale.write_bytes(b"unchanged")
        stale.chmod(0o644)
    elif kind == "symlink":
        stale.symlink_to(target)
    elif kind == "hardlink":
        os.link(target, stale)
    else:
        os.mkfifo(stale, 0o600)
    before = stale.lstat()
    with FilesystemSecretStore(tmp_path) as store:
        store.set("k", {"token": "dummy"})
        assert store.get("k") == {"token": "dummy"}
        assert (tmp_path / "k.yaml").stat().st_mode & 0o077 == 0
    assert stale.lstat() == before
    assert target.read_bytes() == b"unchanged"
    if kind != "fifo":
        assert stale.read_bytes() == b"unchanged"


@pytest.mark.parametrize(
    "sidecar,operation",
    [
        (".k.cleared", "delete"),
        (".k.cleared", "is_cleared"),
        (".k.cleared", "set"),
        (".k.lock", "transaction"),
    ],
)
@pytest.mark.parametrize("kind", ["hardlink", "symlink", "directory", "mode"])
def test_invalid_sidecars_preserve_live_record_and_sentinel(tmp_path, sidecar, operation, kind):
    with FilesystemSecretStore(tmp_path) as store:
        store.set("k", {"n": 1})
        target = tmp_path / "outside"
        target.write_bytes(b"sentinel")
        target.chmod(0o600)
        path = tmp_path / sidecar
        if kind == "hardlink":
            os.link(target, path)
        elif kind == "symlink":
            path.symlink_to(target)
        elif kind == "directory":
            path.mkdir()
        else:
            path.write_bytes(b"marker")
            path.chmod(0o644)
        before = path.lstat()
        with pytest.raises(PermissionError):
            call_store(store, operation, "k")
        assert store.get("k") == {"n": 1}
        assert path.lstat() == before
        assert target.read_bytes() == b"sentinel"


def test_postcommit_cleanup_failure_reports_committed_record(tmp_path, monkeypatch):
    with FilesystemSecretStore(tmp_path) as store:
        store.delete("k")
        original = os.unlink

        def fail_marker(path, *args, **kwargs):
            if path == ".k.cleared":
                raise OSError("dummy backend value")
            return original(path, *args, **kwargs)

        with monkeypatch.context() as patcher:
            patcher.setattr(os, "unlink", fail_marker)
            with pytest.raises(SecretStoreUnavailableError) as caught:
                store.set("k", {"n": 2})
        assert caught.value.reason == "write_committed_cleanup_failed"
        assert_safe_error(caught.value, "dummy backend value", str(tmp_path))
        assert store.get("k") == {"n": 2}
        assert store.is_cleared("k")
        with store.transaction("k"):
            store.set("k", {"n": 3})
        assert not store.is_cleared("k")
        assert store.get("k") == {"n": 3}


def descriptor_set():
    from pathlib import Path

    directory = Path("/proc/self/fd")
    if not directory.is_dir():
        pytest.skip("descriptor accounting requires procfs on this verification host")
    descriptors = set()
    for name in os.listdir(directory):
        fd = int(name)
        try:
            os.readlink(directory / name)
        except OSError:
            continue  # The transient directory scan descriptor has already closed.
        descriptors.add(fd)
    return descriptors


def run_child(code, *args):
    import signal
    import subprocess
    import sys

    child = subprocess.Popen(
        [sys.executable, "-I", "-c", code, *map(str, args)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = child.communicate(timeout=15)
        assert child.returncode == 0, stdout + stderr
        return stdout
    finally:
        # Parent owns the entire probe tree, including a timed-out grandchild.
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        child.communicate()


@pytest.mark.parametrize("operation", ["get", "delete", "is_cleared", "set", "transaction"])
def test_fifo_rejection_is_bounded_and_releases_handles(tmp_path, operation):
    name = (
        "k.yaml"
        if operation == "get"
        else ".k.lock"
        if operation == "transaction"
        else ".k.cleared"
    )
    os.mkfifo(tmp_path / name, 0o600)
    before = entry_snapshot(tmp_path / name)
    run_child(
        """
import os, sys
from pathlib import Path
from mountainash_secrets import FilesystemSecretStore
with FilesystemSecretStore(sys.argv[1]) as store:
    before = set(Path('/proc/self/fd').iterdir())
    try:
        operation = sys.argv[2]
        if operation == 'transaction':
            with store.transaction('k'):
                raise AssertionError('entered')
        elif operation == 'set':
            store.set('k', {'dummy': True})
        else:
            getattr(store, operation)('k')
    except PermissionError as error:
        assert error.__cause__ is None and error.__context__ is None
    else:
        raise AssertionError('did not reject')
    assert set(Path('/proc/self/fd').iterdir()) == before
""",
        tmp_path,
        operation,
    )
    assert entry_snapshot(tmp_path / name) == before


@pytest.mark.parametrize(
    "payload,reason",
    [
        (b"token: !!int DUMMYSECRETVALUE\n", "malformed_yaml"),
        (b"token: [DUMMYSECRETVALUE\n", "malformed_yaml"),
        (b"\xffDUMMYSECRETVALUE", "decode_error"),
        (b"- DUMMYSECRETVALUE\n", "invalid_record_shape"),
        (b"DUMMYSECRETVALUE\n", "invalid_record_shape"),
        (b"", "invalid_record_shape"),
        (b"null\n", "invalid_record_shape"),
    ],
)
@pytest.mark.parametrize("ambient", [False, True])
def test_load_errors_are_classified_without_disclosure(tmp_path, store, payload, reason, ambient):
    import traceback

    key = "dummy_input_key"
    path = tmp_path / (key + ".yaml")
    path.write_bytes(payload)
    path.chmod(0o600)
    before = descriptor_set()

    def invoke():
        with pytest.raises(SecretStoreUnavailableError) as caught:
            store.get(key)
        error = caught.value
        assert error.reason == reason
        assert error.__cause__ is None and error.__context__ is None
        diagnostic = str(error) + repr(error) + "".join(traceback.format_exception(error))
        for marker in ("DUMMYSECRETVALUE", "CALLER_SECRET", key, str(tmp_path)):
            assert marker not in diagnostic
        assert path.read_bytes() == payload
        assert descriptor_set() == before

    if ambient:
        try:
            raise RuntimeError("CALLER_SECRET")
        except RuntimeError:
            invoke()
    else:
        invoke()


@pytest.mark.parametrize("failure", [TypeError, OverflowError, RecursionError])
@pytest.mark.parametrize("ambient", [False, True])
def test_loader_conversion_failures_are_sanitized(tmp_path, store, monkeypatch, failure, ambient):
    import mountainash_secrets.stores.filesystem as fs

    store.set("k", {"n": 1})
    before = descriptor_set()
    contents = (tmp_path / "k.yaml").read_bytes()

    def fail(stream):
        raise failure("DUMMY_LOADER_SECRET")

    def invoke():
        with pytest.raises(SecretStoreUnavailableError) as caught:
            store.get("k")
        assert caught.value.reason == "malformed_yaml"
        assert_safe_error(caught.value, "DUMMY_LOADER_SECRET", "CALLER_SECRET", str(tmp_path))
        assert (tmp_path / "k.yaml").read_bytes() == contents
        assert descriptor_set() == before

    monkeypatch.setattr(fs.yaml, "safe_load", fail)
    if ambient:
        try:
            raise RuntimeError("CALLER_SECRET")
        except RuntimeError:
            invoke()
    else:
        invoke()


def test_generated_temp_collision_preserves_entry(tmp_path, store, monkeypatch):
    store.set("k", {"n": 1})
    original = os.open
    collisions = []

    def opening(path, flags, *args, **kwargs):
        if flags & os.O_EXCL and not collisions:
            planted = tmp_path / path
            planted.write_bytes(b"outside")
            collisions.append((planted, entry_snapshot(planted)))
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", opening)
    with pytest.raises(SecretStoreUnavailableError):
        store.set("k", {"n": 2})
    collision, snapshot = collisions[0]
    assert entry_snapshot(collision) == snapshot
    assert store.get("k") == {"n": 1}


@pytest.mark.parametrize("failure", ["serialize", "write", "close", "replace", "fdopen"])
def test_precommit_failure_preserves_state_and_cleans_temp(tmp_path, store, monkeypatch, failure):
    import mountainash_secrets.stores.filesystem as fs

    store.set("k", {"n": 1})
    marker = tmp_path / ".k.cleared"
    marker.write_bytes(b"marker")
    marker.chmod(0o600)
    old = (tmp_path / "k.yaml").read_bytes()
    before = descriptor_set()

    def fail(*args, **kwargs):
        raise OSError("DUMMY_SERIALIZATION_VALUE")

    with monkeypatch.context() as patcher:
        if failure == "serialize":
            patcher.setattr(fs.yaml, "safe_dump", fail)
        elif failure == "replace":
            patcher.setattr(os, "replace", fail)
        elif failure == "fdopen":
            patcher.setattr(os, "fdopen", fail)
        else:
            original = os.fdopen

            class BrokenStream:
                def __init__(self, *args, **kwargs):
                    self.stream = original(*args, **kwargs)

                def __enter__(self):
                    return self

                def write(self, data):
                    if failure == "write":
                        fail()
                    return self.stream.write(data)

                def flush(self):
                    self.stream.flush()

                def __exit__(self, *args):
                    self.stream.close()
                    if failure == "close":
                        fail()

            patcher.setattr(os, "fdopen", BrokenStream)
        with pytest.raises(SecretStoreUnavailableError) as caught:
            store.set("k", {"n": 2})
    assert caught.value.reason == "unavailable"
    assert_safe_error(caught.value, "DUMMY_SERIALIZATION_VALUE", str(tmp_path))
    assert (tmp_path / "k.yaml").read_bytes() == old
    assert marker.read_bytes() == b"marker"
    assert sorted(path.name for path in tmp_path.iterdir()) == [".k.cleared", "k.yaml"]
    assert descriptor_set() == before


def test_temp_is_private_before_plaintext(tmp_path, store, monkeypatch):
    import mountainash_secrets.stores.filesystem as fs

    original = fs.yaml.safe_dump

    def observe(data, stream):
        info = os.fstat(stream.fileno())
        assert info.st_mode & 0o077 == 0
        assert info.st_size == 0
        assert info.st_nlink == 1
        return original(data, stream)

    monkeypatch.setattr(fs.yaml, "safe_dump", observe)
    store.set("k", {"nested": [1, None, {"enabled": True}]})
    assert store.get("k") == {"nested": [1, None, {"enabled": True}]}


def test_failed_temp_inspection_cleans_owned_entry(tmp_path, store, monkeypatch):
    original = os.fstat
    failed = False

    def fail_once(fd):
        nonlocal failed
        info = original(fd)
        import stat

        if stat.S_ISREG(info.st_mode) and not failed:
            failed = True
            raise OSError("dummy inspection failure")
        return info

    monkeypatch.setattr(os, "fstat", fail_once)
    with pytest.raises(SecretStoreUnavailableError):
        store.set("k", {"n": 1})
    assert list(tmp_path.iterdir()) == []


def test_failed_cleanup_reports_private_residue(tmp_path, store, monkeypatch):
    import mountainash_secrets.stores.filesystem as fs

    store.set("k", {"n": 1})

    def fail(*args, **kwargs):
        raise OSError("DUMMY_FAILURE")

    with monkeypatch.context() as patcher:
        patcher.setattr(fs.yaml, "safe_dump", fail)
        patcher.setattr(os, "unlink", fail)
        with pytest.raises(SecretStoreUnavailableError) as caught:
            store.set("k", {"n": 2})
    assert caught.value.reason == "unavailable"
    assert_safe_error(caught.value, "DUMMY_FAILURE", str(tmp_path))
    assert store.get("k") == {"n": 1}
    residues = [p for p in tmp_path.iterdir() if p.name != "k.yaml"]
    assert len(residues) == 1
    assert residues[0].stat().st_mode & 0o077 == 0


@pytest.mark.parametrize("replacement_mode", [0o600, 0o644])
@pytest.mark.parametrize("operation", ["delete", "is_cleared", "transaction", "set"])
def test_sidecar_swap_before_final_inspection_is_refused(
    tmp_path, store, monkeypatch, operation, replacement_mode
):
    store.set("k", {"n": 1})
    name = ".k.lock" if operation == "transaction" else ".k.cleared"
    sidecar = tmp_path / name
    sidecar.write_bytes(b"original")
    sidecar.chmod(0o600)
    import fcntl

    original_flock = fcntl.flock
    acquired = []

    def observe_lock(fd, mode):
        result = original_flock(fd, mode)
        if mode == fcntl.LOCK_EX:
            acquired.append(os.fstat(fd).st_ino)
        return result

    original_stat, original_replace = os.stat, os.replace
    swapped = False

    def swap():
        nonlocal swapped
        sidecar.rename(tmp_path / "retained")
        sidecar.write_bytes(b"replacement")
        sidecar.chmod(replacement_mode)
        swapped = True

    def inspect(path, *args, **kwargs):
        if operation != "set" and path == name and not swapped:
            swap()
        return original_stat(path, *args, **kwargs)

    def replace(*args, **kwargs):
        original_replace(*args, **kwargs)
        swap()

    before = descriptor_set()
    with monkeypatch.context() as patcher:
        patcher.setattr(fcntl, "flock", observe_lock)
        patcher.setattr(os, "stat", inspect)
        if operation == "set":
            patcher.setattr(os, "replace", replace)
        expected = SecretStoreUnavailableError if operation == "set" else PermissionError
        with pytest.raises(expected) as caught:
            call_store(store, operation, "k")
    if operation == "set":
        assert caught.value.reason == "write_committed_cleanup_failed"
    assert store.get("k") == {"n": 2 if operation == "set" else 1}
    assert sidecar.read_bytes() == b"replacement"
    assert (tmp_path / "retained").read_bytes() == b"original"
    assert descriptor_set() == before
    assert acquired == []
    if operation == "set":
        if replacement_mode == 0o600:
            assert store.is_cleared("k")
        else:
            with pytest.raises(PermissionError):
                store.is_cleared("k")


@pytest.mark.parametrize("moment", ["before", "after"])
def test_namespace_swap_binds_opened_directory(tmp_path, store, monkeypatch, moment):
    namespace = tmp_path / "ns"
    outside = tmp_path / "outside"
    namespace.mkdir()
    outside.mkdir()
    original = os.open
    swapped = False

    def swap():
        nonlocal swapped
        namespace.rename(tmp_path / "retained")
        namespace.symlink_to(outside, target_is_directory=True)
        swapped = True

    def opening(path, *args, **kwargs):
        if path == "ns" and not swapped:
            if moment == "before":
                swap()
            fd = original(path, *args, **kwargs)
            if moment == "after":
                swap()
            return fd
        return original(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", opening)
    if moment == "before":
        with pytest.raises(PermissionError):
            store.set("ns.k", {"n": 1})
    else:
        store.set("ns.k", {"n": 1})
        assert (tmp_path / "retained/k.yaml").read_text() == "n: 1\n"
    assert list(outside.iterdir()) == []


def test_read_fdopen_failure_releases_handles(tmp_path, store, monkeypatch):
    store.set("k", {"n": 1})
    before = descriptor_set()

    def fail(*args, **kwargs):
        raise OSError("DUMMY_READ_VALUE")

    monkeypatch.setattr(os, "fdopen", fail)
    with pytest.raises(SecretStoreUnavailableError) as caught:
        store.get("k")
    assert caught.value.__context__ is None
    assert descriptor_set() == before


def test_partial_constructor_failure_releases_root(tmp_path, monkeypatch):
    before = descriptor_set()

    def fail(fd):
        raise OSError("dummy root failure")

    monkeypatch.setattr(os, "fstat", fail)
    with pytest.raises(SecretStoreUnavailableError):
        FilesystemSecretStore(tmp_path)
    assert descriptor_set() == before


def test_context_preserves_body_exception_and_closes(tmp_path):
    error = RuntimeError("caller owned")
    store = FilesystemSecretStore(tmp_path)
    with pytest.raises(RuntimeError) as caught:
        with store:
            raise error
    assert caught.value is error
    with pytest.raises(SecretStoreUnavailableError) as closed:
        store.get("k")
    assert closed.value.reason == "store_closed"


def test_admitted_operation_survives_close(tmp_path):
    run_child(
        """
import os, sys, threading
from mountainash_secrets import FilesystemSecretStore, SecretStoreUnavailableError
store = FilesystemSecretStore(sys.argv[1])
original = os.open
entered, release = threading.Event(), threading.Event()
errors = []
def opening(path, *args, **kwargs):
    if path == 'ns':
        entered.set()
        assert release.wait(5)
    return original(path, *args, **kwargs)
os.open = opening
def worker():
    try:
        store.set('ns.k', {'n': 1})
    except BaseException as error:
        errors.append(error)
thread = threading.Thread(target=worker)
thread.start()
assert entered.wait(5)
store.close()
try:
    store.get('ns.k')
except SecretStoreUnavailableError as error:
    assert error.reason == 'store_closed'
else:
    raise AssertionError('closed read admitted')
release.set()
thread.join(5)
assert not thread.is_alive() and not errors
os.open = original
with FilesystemSecretStore(sys.argv[1]) as fresh:
    assert fresh.get('ns.k') == {'n': 1}
""",
        tmp_path,
    )


@pytest.mark.parametrize("waiting", [False, True])
def test_close_preserves_active_and_waiting_transaction(tmp_path, waiting):
    run_child(
        """
import fcntl, os, sys, threading
from pathlib import Path
from mountainash_secrets import FilesystemSecretStore
root = Path(sys.argv[1])
waiting = sys.argv[2] == 'True'
store = FilesystemSecretStore(root)
fd = os.open(root / '.k.lock', os.O_CREAT | os.O_RDWR, 0o600)
if waiting:
    fcntl.flock(fd, fcntl.LOCK_EX)
entering, acquired, release = threading.Event(), threading.Event(), threading.Event()
original = fcntl.flock
errors = []
def flock(handle, mode):
    if mode == fcntl.LOCK_EX:
        entering.set()
    return original(handle, mode)
fcntl.flock = flock
def worker():
    try:
        with store.transaction('k'):
            acquired.set()
            assert release.wait(5)
    except BaseException as error:
        errors.append(error)
thread = threading.Thread(target=worker)
thread.start()
assert entering.wait(5)
if not waiting:
    assert acquired.wait(5)
store.close()
if waiting:
    assert not acquired.is_set()
    original(fd, fcntl.LOCK_UN)
    assert acquired.wait(5)
try:
    original(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    pass
else:
    raise AssertionError('lock released early')
release.set()
thread.join(5)
assert not thread.is_alive() and not errors
original(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
original(fd, fcntl.LOCK_UN)
os.close(fd)
""",
        tmp_path,
        waiting,
    )


def test_transaction_retains_original_inode_after_name_replacement(tmp_path):
    run_child(
        """
import fcntl, os, sys
from pathlib import Path
from mountainash_secrets import FilesystemSecretStore
root = Path(sys.argv[1])
with FilesystemSecretStore(root) as store:
    with store.transaction('k'):
        path = root / '.k.lock'
        path.rename(root / 'original')
        path.write_bytes(b'replacement')
        path.chmod(0o600)
        contender = os.open(root / 'original', os.O_RDWR)
        try:
            fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            raise AssertionError('original lock not held')
    fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
    fcntl.flock(contender, fcntl.LOCK_UN)
    os.close(contender)
    assert path.read_bytes() == b'replacement'
""",
        tmp_path,
    )


def test_process_transactions_preserve_all_increments(tmp_path):
    run_child(
        """
import subprocess, sys
from mountainash_secrets import FilesystemSecretStore
with FilesystemSecretStore(sys.argv[1]) as store:
    store.set('k', {'n': 0})
code = '''
import sys
from mountainash_secrets import FilesystemSecretStore
with FilesystemSecretStore(sys.argv[1]) as store:
    for _ in range(10):
        with store.transaction('k'):
            record = store.get('k')
            store.set('k', {'n': record['n'] + 1})
'''
children = [subprocess.Popen([sys.executable, '-I', '-c', code, sys.argv[1]]) for _ in range(3)]
try:
    for child in children:
        assert child.wait(timeout=5) == 0
finally:
    for child in children:
        if child.poll() is None:
            child.kill()
        child.wait()
with FilesystemSecretStore(sys.argv[1]) as store:
    assert store.get('k') == {'n': 30}
""",
        tmp_path,
    )


@pytest.mark.parametrize("phase", ["acquire", "unlock"])
@pytest.mark.parametrize("body_error", [False, True])
def test_transaction_failure_releases_handles_without_replacing_body(
    tmp_path, store, monkeypatch, phase, body_error
):
    import fcntl

    before = descriptor_set()
    original = fcntl.flock
    caller = RuntimeError("caller owned")

    def fail(fd, mode):
        if mode == (fcntl.LOCK_EX if phase == "acquire" else fcntl.LOCK_UN):
            raise OSError("DUMMY_BACKEND_LOCK_VALUE")
        return original(fd, mode)

    with monkeypatch.context() as patcher:
        patcher.setattr(fcntl, "flock", fail)
        expected = RuntimeError if body_error and phase == "unlock" else SecretStoreUnavailableError
        with pytest.raises(expected) as caught:
            with store.transaction("k"):
                if body_error:
                    raise caller
    if body_error and phase == "unlock":
        assert caught.value is caller
        assert caller.__context__ is None
    else:
        assert caught.value.__context__ is None
    assert descriptor_set() == before
    with store.transaction("k"):
        store.set("k", {"n": 1})
    assert store.get("k") == {"n": 1}


@pytest.mark.parametrize("mask,mode", [(0o077, 0o700), (0o027, 0o750), (0, 0o777)])
@pytest.mark.parametrize("operation", ["set", "delete", "transaction"])
def test_namespace_creation_respects_application_umask(tmp_path, mask, mode, operation):
    run_child(
        """
import os, sys
from pathlib import Path
from mountainash_secrets import FilesystemSecretStore
root = Path(sys.argv[1])
mask, mode, operation = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
os.umask(mask)
root.chmod(0o770)
before = root.stat()
with FilesystemSecretStore(root) as store:
    assert store.get('absent.k') is None
    assert not store.is_cleared('absent.k')
    assert not (root / 'absent').exists()
    if operation == 'transaction':
        with store.transaction('ns.k'):
            pass
    elif operation == 'set':
        store.set('ns.k', {'n': 1})
    else:
        store.delete('ns.k')
assert os.umask(mask) == mask
assert (root / 'ns').stat().st_mode & 0o777 == mode
assert (root.stat().st_mode, root.stat().st_uid, root.stat().st_gid) == (before.st_mode, before.st_uid, before.st_gid)
for path in (root / 'ns').iterdir():
    assert path.stat().st_mode & 0o077 == 0
""",
        tmp_path,
        mask,
        mode,
        operation,
    )


def test_namespace_inherits_default_acl_and_setgid(tmp_path):
    import shutil
    import subprocess

    if not shutil.which("setfacl") or not shutil.which("getfacl"):
        pytest.skip("default ACL proof requires setfacl and getfacl")
    tmp_path.chmod(0o2770)
    subprocess.run(
        ["setfacl", "-m", "d:u::rwx,d:g::rwx,d:m::rwx,d:o::---", str(tmp_path)], check=True
    )
    before = subprocess.check_output(["getfacl", "-cp", str(tmp_path)], text=True)
    with FilesystemSecretStore(tmp_path) as store:
        store.set("ns.k", {"n": 1})
        store.delete("ns.k")
        with store.transaction("ns.k"):
            store.set("ns.k", {"n": 2})
    namespace = tmp_path / "ns"
    assert namespace.stat().st_mode & 0o2770 == 0o2770
    assert namespace.stat().st_gid == tmp_path.stat().st_gid
    inherited = subprocess.check_output(["getfacl", "-cp", str(namespace)], text=True)
    assert "default:group::rwx" in inherited
    assert subprocess.check_output(["getfacl", "-cp", str(tmp_path)], text=True) == before
    for path in namespace.iterdir():
        assert path.stat().st_mode & 0o077 == 0
        acl = subprocess.check_output(["getfacl", "-cp", str(path)], text=True)
        assert "mask::---" in acl or "group::---" in acl


def test_substituted_temporary_is_not_written_or_removed(tmp_path, store, monkeypatch):
    original = os.stat
    swapped = False

    def inspect(path, *args, **kwargs):
        nonlocal swapped
        if str(path).endswith(".tmp") and not swapped:
            source = tmp_path / path
            source.rename(tmp_path / "retained")
            source.symlink_to(tmp_path / "outside")
            swapped = True
        return original(path, *args, **kwargs)

    target = tmp_path / "outside"
    target.write_bytes(b"untouched")
    monkeypatch.setattr(os, "stat", inspect)
    with pytest.raises(PermissionError):
        store.set("k", {"n": 1})
    assert target.read_bytes() == b"untouched"
    assert (tmp_path / "retained").read_bytes() == b""
    assert (tmp_path / "retained").stat().st_mode & 0o077 == 0
    assert not (tmp_path / "k.yaml").exists()
    assert len([p for p in tmp_path.iterdir() if p.is_symlink()]) == 1


def test_delete_marker_creation_failure_is_nonatomic(tmp_path, store, monkeypatch):
    store.set("k", {"n": 1})
    original = os.open

    def fail(path, flags, *args, **kwargs):
        if path == ".k.cleared" and flags & os.O_CREAT:
            raise OSError("dummy marker failure")
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fail)
    with pytest.raises(SecretStoreUnavailableError) as caught:
        store.delete("k")
    assert caught.value.reason == "unavailable"
    assert store.get("k") is None
    assert not store.is_cleared("k")


@pytest.mark.parametrize("operation", ["get", "set", "delete"])
@pytest.mark.parametrize("kind", ["hardlink", "symlink", "mode", "directory"])
def test_invalid_credential_is_refused_untouched(tmp_path, store, operation, kind):
    target, credential = tmp_path / "outside", tmp_path / "k.yaml"
    target.write_bytes(b"n: 1\n")
    target.chmod(0o600)
    if kind == "hardlink":
        os.link(target, credential)
    elif kind == "symlink":
        credential.symlink_to(target)
    elif kind == "mode":
        credential.write_bytes(b"n: 1\n")
        credential.chmod(0o644)
    else:
        credential.mkdir()
    entry_before, target_before = entry_snapshot(credential), entry_snapshot(target)
    before = descriptor_set()
    with pytest.raises(PermissionError):
        call_store(store, operation, "k")
    assert entry_snapshot(credential) == entry_before
    assert entry_snapshot(target) == target_before
    assert descriptor_set() == before


def test_three_segment_layout_preserves_lifecycle(tmp_path, store):
    with store.transaction("domain.provider.user"):
        store.set("domain.provider.user", {"n": 1})
        assert (tmp_path / "domain/provider-user.yaml").read_text() == "n: 1\n"
        assert store.get("domain.provider.user") == {"n": 1}
        store.delete("domain.provider.user")
        assert store.is_cleared("domain.provider.user")
        store.set("domain.provider.user", {"n": 2})
    assert not store.is_cleared("domain.provider.user")


def test_closed_context_entry_and_nonmapping_errors_are_chain_free(tmp_path):
    with FilesystemSecretStore(tmp_path) as store:
        try:
            raise RuntimeError("ambient")
        except RuntimeError:
            with pytest.raises(ValueError) as caught:
                store.set("k", [])
        assert caught.value.__context__ is None
        assert list(tmp_path.iterdir()) == []
    with pytest.raises(SecretStoreUnavailableError) as closed:
        with store:
            pytest.fail("closed context entered")
    assert closed.value.reason == "store_closed"


def entry_snapshot(path):
    import stat

    info = path.lstat()
    contents = path.read_bytes() if stat.S_ISREG(info.st_mode) else None
    target = os.readlink(path) if stat.S_ISLNK(info.st_mode) else None
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        contents,
        target,
    )


def assert_safe_error(error, *markers):
    import traceback

    assert error.__cause__ is None and error.__context__ is None
    diagnostic = str(error) + repr(error) + "".join(traceback.format_exception(error))
    for marker in markers:
        assert marker not in diagnostic


def test_existing_directory_policy_is_not_repaired(tmp_path):
    ancestor = tmp_path / "ancestor"
    root, namespace = ancestor / "root", ancestor / "root/ns"
    ancestor.mkdir(mode=0o751)
    root.mkdir(mode=0o770)
    namespace.mkdir(mode=0o750)
    paths = [ancestor, root, namespace]
    policy = [(p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in paths]
    with FilesystemSecretStore(root) as store:
        assert store.get("ns.k") is None
        assert not store.is_cleared("ns.k")
        with store.transaction("ns.k"):
            store.set("ns.k", {"n": 1})
            store.delete("ns.k")
            assert store.is_cleared("ns.k")
    assert [(p.stat().st_mode, p.stat().st_uid, p.stat().st_gid) for p in paths] == policy
