# mountainash-secrets v0 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build v0 of the `mountainash-secrets` package — a capability-graded secret-store port (`SecretReader`/`SecretWriter`/`ClearableStore`/`VersionedReader`), an injected `RegistryResolver`, an error hierarchy, four stores (in-memory, filesystem, env, namespaced wrapper), a `require()` helper, and a reusable behavioral conformance suite.

**Architecture:** A zero-third-party-dependency `core/` (protocols, resolver, errors, access helper) plus a `stores/` package of concrete adapters. The package imports neither auth-client nor settings; SDK adapters and consumer migration are explicitly OUT of v0 (spec §7 steps 2–5). Stores are validated by behavioral conformance tests, not by `isinstance` alone.

**Tech Stack:** Python ≥3.10, `pyyaml` (only runtime dep), hatchling build, pytest, ruff. CalVer `26.6.0`.

**Spec:** `docs/superpowers/specs/2026-06-14-secrets-store-port-design.md`

**Conventions for every task:**
- **Repo root:** `/home/nathanielramm/git/mountainash-io/mountainash/mountainash-secrets`
- **Test runner (PY):** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest`
- **Lint gate:** `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m ruff check src tests` (no mypy env exists).
- All commands assume CWD = repo root.
- Commit messages end with the `Co-Authored-By` trailer shown in Task 1.
- This is a brand-new repo on branch `develop` with no remote; commit directly to `develop` (initial package build-out). The PR to a remote happens after v0 is complete and a remote is created — do NOT attempt to push.

---

## File Structure

```
mountainash-secrets/
  pyproject.toml                         # Task 1 — hatchling, deps, ruff, coverage
  README.md                              # Task 1
  src/mountainash_secrets/
    __init__.py                          # Task 10 — public API re-exports
    __version__.py                       # Task 1 — "26.6.0"
    core/
      __init__.py                        # Task 2 (empty marker)
      errors.py                          # Task 2 — exception hierarchy
      protocols.py                       # Task 3 — the capability ladder + SecretRecord/JSONValue
      resolver.py                        # Task 4 — SecretStoreResolver + RegistryResolver
      access.py                          # Task 9 — require() helper
    stores/
      __init__.py                        # Task 5 (empty marker)
      memory.py                          # Task 5 — InMemoryStore (full ClearableStore)
      namespaced.py                      # Task 6 — NamespacedStore wrapper
      filesystem.py                      # Task 7 — FilesystemStore (lift of settings' FilesystemBackend)
      env.py                             # Task 8 — EnvReader (read-only)
  tests/
    __init__.py                          # Task 1
    test_errors.py                       # Task 2
    test_protocols.py                    # Task 3
    test_resolver.py                     # Task 4
    test_memory.py                       # Task 5
    test_namespaced.py                   # Task 6
    test_filesystem.py                   # Task 7
    test_env.py                          # Task 8
    test_access.py                       # Task 9
    test_conformance.py                  # Task 11 — parametrized behavioral suite over writer stores
    test_public_api.py                   # Task 10
```

---

### Task 1: Package scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `README.md`
- Create: `src/mountainash_secrets/__version__.py`
- Create: `src/mountainash_secrets/__init__.py` (temporary stub, finalized in Task 10)
- Create: `tests/__init__.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "mountainash_secrets"
dynamic = ["version"]
description = "Mountain Ash — capability-graded secret-store port"
readme = "README.md"
requires-python = ">=3.10"
authors = [
    { name = "Nathaniel Ramm", email = "nathaniel.ramm@discretedatascience.com" },
]
classifiers = [
    "Development Status :: 4 - Beta",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
]
dependencies = [
    "pyyaml>=6.0",
]

[project.optional-dependencies]
aws = ["boto3>=1.29.0"]
azure = ["azure-keyvault-secrets>=4.8.0", "azure-identity>=1.16.0"]
gcp = ["google-cloud-secret-manager>=2.18.0"]
hashicorp = ["hvac>=2.1.0"]

[tool.hatch.version]
path = "src/mountainash_secrets/__version__.py"

[tool.hatch.build.targets.wheel]
packages = ["src/mountainash_secrets"]

[tool.ruff]
line-length = 100
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "B"]

[tool.coverage.run]
source_pkgs = ["mountainash_secrets", "tests"]
branch = true
omit = ["src/mountainash_secrets/__version__.py"]
```

- [ ] **Step 2: Write `src/mountainash_secrets/__version__.py`**

```python
__version__ = "26.6.0"
```

- [ ] **Step 3: Write `README.md`**

```markdown
# mountainash-secrets

A capability-graded secret-store port: one protocol family
(`SecretReader` → `SecretWriter` → `ClearableStore`, plus `VersionedReader`)
with pluggable stores (in-memory, filesystem, env) and an injected resolver.

The package authenticates nothing and depends on neither `mountainash-settings`
nor `mountainash-auth-client`. Authenticated SDK clients are built by the
application composition root and handed to store adapters.

See `docs/superpowers/specs/2026-06-14-secrets-store-port-design.md`.
```

- [ ] **Step 4: Write stub `src/mountainash_secrets/__init__.py`**

```python
"""mountainash-secrets — capability-graded secret-store port."""
from .__version__ import __version__

__all__ = ["__version__"]
```

- [ ] **Step 5: Write empty `tests/__init__.py`**

```python
```

- [ ] **Step 6: Editable-install into the dev venv and verify import**

Run:
```bash
/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pip install -e .
/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -c "import mountainash_secrets; print(mountainash_secrets.__version__)"
```
Expected: prints `26.6.0`

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml README.md src tests
git commit -m "$(cat <<'EOF'
chore: scaffold mountainash-secrets package

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: Error hierarchy

**Files:**
- Create: `src/mountainash_secrets/core/__init__.py`
- Create: `src/mountainash_secrets/core/errors.py`
- Test: `tests/test_errors.py`

- [ ] **Step 1: Write empty `src/mountainash_secrets/core/__init__.py`**

```python
```

- [ ] **Step 2: Write the failing test `tests/test_errors.py`**

```python
from mountainash_secrets.core.errors import (
    CapabilityError,
    ResolverError,
    SecretNotFoundError,
    SecretStoreError,
    StoreUnavailableError,
)


def test_all_errors_subclass_base():
    for exc in (ResolverError, CapabilityError, StoreUnavailableError, SecretNotFoundError):
        assert issubclass(exc, SecretStoreError)


def test_base_is_exception():
    assert issubclass(SecretStoreError, Exception)


def test_errors_are_distinct():
    assert ResolverError is not CapabilityError
    assert StoreUnavailableError is not SecretNotFoundError
```

- [ ] **Step 3: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_errors.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.core.errors'`

- [ ] **Step 4: Write `src/mountainash_secrets/core/errors.py`**

```python
"""Exception hierarchy for the secret-store port.

Error messages MUST NOT include secret record values.
"""
from __future__ import annotations

__all__ = [
    "SecretStoreError",
    "ResolverError",
    "CapabilityError",
    "StoreUnavailableError",
    "SecretNotFoundError",
]


class SecretStoreError(Exception):
    """Base of every error raised by this package."""


class ResolverError(SecretStoreError):
    """Raised when a store name is unknown or already registered."""


class CapabilityError(SecretStoreError):
    """Raised when a named store lacks a requested capability rung."""


class StoreUnavailableError(SecretStoreError):
    """Raised when a backend/transport/IO operation fails."""


class SecretNotFoundError(SecretStoreError):
    """Raised by the strict ``require()`` helper when a key has no live record."""
```

- [ ] **Step 5: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_errors.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_secrets/core/__init__.py src/mountainash_secrets/core/errors.py tests/test_errors.py
git commit -m "$(cat <<'EOF'
feat: secret-store error hierarchy

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: The capability-graded protocol ladder

**Files:**
- Create: `src/mountainash_secrets/core/protocols.py`
- Test: `tests/test_protocols.py`

- [ ] **Step 1: Write the failing test `tests/test_protocols.py`**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_protocols.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.core.protocols'`

- [ ] **Step 3: Write `src/mountainash_secrets/core/protocols.py`**

```python
"""The capability-graded secret-store port.

`runtime_checkable` checks method NAMES only — not signatures or semantics.
Semantic conformance is covered by tests/test_conformance.py, not by isinstance.
"""
from __future__ import annotations

import typing as t
from contextlib import AbstractContextManager

__all__ = [
    "JSONValue",
    "SecretRecord",
    "SecretReader",
    "SecretWriter",
    "ClearableStore",
    "VersionedReader",
]

JSONValue = t.Union[
    str, int, float, bool, None, t.List["JSONValue"], t.Dict[str, "JSONValue"]
]
# A secret record is a mapping of JSON-native values. Stores MUST round-trip
# JSON-native values losslessly; callers encode datetimes (int/ISO str) and
# binary (base64 str) themselves.
SecretRecord = t.Dict[str, "JSONValue"]


@t.runtime_checkable
class SecretReader(t.Protocol):
    """Read a live secret record by key. The base capability."""

    def get(self, key: str) -> SecretRecord | None:
        """Return the live record, or None if no live record exists."""
        ...


@t.runtime_checkable
class SecretWriter(SecretReader, t.Protocol):
    """Read + mutate. ``transaction`` is the atomicity primitive."""

    def set(self, key: str, data: SecretRecord) -> None: ...

    def delete(self, key: str) -> None: ...

    def transaction(self, key: str) -> AbstractContextManager[None]: ...


@t.runtime_checkable
class ClearableStore(SecretWriter, t.Protocol):
    """Distinguishes 'deliberately cleared' (tombstone) from 'never set'."""

    def is_cleared(self, key: str) -> bool: ...


@t.runtime_checkable
class VersionedReader(SecretReader, t.Protocol):
    """Vault-style versioned read (additive; not all stores support it)."""

    def get_version(self, key: str, version: str) -> SecretRecord | None: ...

    def list_versions(self, key: str) -> list[str]: ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_protocols.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_secrets/core/protocols.py tests/test_protocols.py
git commit -m "$(cat <<'EOF'
feat: capability-graded secret-store protocol ladder

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Resolver (injected, capability-aware)

**Files:**
- Create: `src/mountainash_secrets/core/resolver.py`
- Test: `tests/test_resolver.py`

- [ ] **Step 1: Write the failing test `tests/test_resolver.py`**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_resolver.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.core.resolver'`

- [ ] **Step 3: Write `src/mountainash_secrets/core/resolver.py`**

```python
"""Injected, capability-aware store resolution.

There is no process-global resolver. An application composition root builds one
RegistryResolver of pre-constructed stores and injects it into consumers.
"""
from __future__ import annotations

import threading
import typing as t

from .errors import CapabilityError, ResolverError
from .protocols import SecretReader

__all__ = ["SecretStoreResolver", "RegistryResolver"]

C = t.TypeVar("C", bound=SecretReader)


@t.runtime_checkable
class SecretStoreResolver(t.Protocol):
    def resolve(self, name: str) -> SecretReader: ...

    def resolve_as(self, name: str, capability: type[C]) -> C: ...


class RegistryResolver:
    """Resolves a name to a PRE-BUILT store. Never constructs or authenticates.

    register()/replace are composition-time operations; resolve()/resolve_as()
    are read-only lookups. A lock guards the dict for defensiveness, but mutation
    after startup is not a supported concurrency pattern.
    """

    def __init__(self, stores: dict[str, SecretReader] | None = None) -> None:
        self._stores: dict[str, SecretReader] = dict(stores) if stores else {}
        self._lock = threading.Lock()

    def register(self, name: str, store: SecretReader, *, replace: bool = False) -> None:
        with self._lock:
            if name in self._stores and not replace:
                raise ResolverError(f"Store already registered: {name!r}")
            self._stores[name] = store

    def resolve(self, name: str) -> SecretReader:
        with self._lock:
            try:
                return self._stores[name]
            except KeyError:
                raise ResolverError(f"No store registered under name: {name!r}") from None

    def resolve_as(self, name: str, capability: type[C]) -> C:
        store = self.resolve(name)
        if not isinstance(store, capability):
            raise CapabilityError(
                f"Store {name!r} does not satisfy {capability.__name__}"
            )
        return t.cast(C, store)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_resolver.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_secrets/core/resolver.py tests/test_resolver.py
git commit -m "$(cat <<'EOF'
feat: injected capability-aware RegistryResolver

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: InMemoryStore (full ClearableStore, canonical test double)

**Files:**
- Create: `src/mountainash_secrets/stores/__init__.py`
- Create: `src/mountainash_secrets/stores/memory.py`
- Test: `tests/test_memory.py`

- [ ] **Step 1: Write empty `src/mountainash_secrets/stores/__init__.py`**

```python
```

- [ ] **Step 2: Write the failing test `tests/test_memory.py`**

```python
from mountainash_secrets.core.protocols import ClearableStore
from mountainash_secrets.stores.memory import InMemoryStore


def test_set_then_get_round_trips():
    s = InMemoryStore()
    s.set("k", {"a": 1, "b": ["x", {"c": True}]})
    assert s.get("k") == {"a": 1, "b": ["x", {"c": True}]}


def test_get_unknown_returns_none():
    assert InMemoryStore().get("missing") is None


def test_delete_makes_get_none_and_marks_cleared():
    s = InMemoryStore()
    s.set("k", {"a": 1})
    s.delete("k")
    assert s.get("k") is None
    assert s.is_cleared("k") is True


def test_never_set_is_not_cleared():
    assert InMemoryStore().is_cleared("k") is False


def test_set_after_delete_clears_tombstone():
    s = InMemoryStore()
    s.set("k", {"a": 1})
    s.delete("k")
    s.set("k", {"a": 2})
    assert s.is_cleared("k") is False
    assert s.get("k") == {"a": 2}


def test_get_returns_deeply_isolated_copy():
    # Mutating a NESTED structure of the returned record must not affect the
    # store — guards against a shallow copy (SecretRecord supports nesting).
    s = InMemoryStore()
    s.set("k", {"a": 1, "nested": {"x": [1, 2]}})
    got = s.get("k")
    got["nested"]["x"].append(999)
    assert s.get("k") == {"a": 1, "nested": {"x": [1, 2]}}


def test_set_stores_deeply_isolated_copy():
    # Mutating a NESTED structure of the input after set must not leak in.
    s = InMemoryStore()
    payload = {"a": 1, "nested": {"x": [1, 2]}}
    s.set("k", payload)
    payload["nested"]["x"].append(999)
    assert s.get("k") == {"a": 1, "nested": {"x": [1, 2]}}


def test_transaction_is_a_context_manager():
    s = InMemoryStore()
    with s.transaction("k"):
        s.set("k", {"a": 1})
    assert s.get("k") == {"a": 1}


def test_satisfies_clearable_store():
    assert isinstance(InMemoryStore(), ClearableStore)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_memory.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.stores.memory'`

- [ ] **Step 4: Write `src/mountainash_secrets/stores/memory.py`**

```python
"""InMemoryStore — full ClearableStore; the canonical single-process test double."""
from __future__ import annotations

import copy
import threading
import typing as t
from contextlib import contextmanager

if t.TYPE_CHECKING:
    from collections.abc import Iterator

    from ..core.protocols import SecretRecord

__all__ = ["InMemoryStore"]


class InMemoryStore:
    """Stores records in a dict. Single-process; transaction uses per-key locks.

    Records are deep-copied on set and get so callers cannot mutate stored state
    through a shared reference.
    """

    def __init__(self) -> None:
        self._data: dict[str, SecretRecord] = {}
        self._cleared: set[str] = set()
        self._key_locks: dict[str, threading.RLock] = {}
        self._guard = threading.Lock()

    def get(self, key: str) -> SecretRecord | None:
        value = self._data.get(key)
        return copy.deepcopy(value) if value is not None else None

    def set(self, key: str, data: SecretRecord) -> None:
        self._data[key] = copy.deepcopy(data)
        self._cleared.discard(key)

    def delete(self, key: str) -> None:
        self._data.pop(key, None)
        self._cleared.add(key)

    def is_cleared(self, key: str) -> bool:
        return key in self._cleared

    @contextmanager
    def transaction(self, key: str) -> Iterator[None]:
        with self._guard:
            lock = self._key_locks.setdefault(key, threading.RLock())
        with lock:
            yield
```

- [ ] **Step 5: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_memory.py -v`
Expected: PASS (9 passed)

- [ ] **Step 6: Commit**

```bash
git add src/mountainash_secrets/stores/__init__.py src/mountainash_secrets/stores/memory.py tests/test_memory.py
git commit -m "$(cat <<'EOF'
feat: InMemoryStore (full ClearableStore test double)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: NamespacedStore (key-prefix wrapper)

**Files:**
- Create: `src/mountainash_secrets/stores/namespaced.py`
- Test: `tests/test_namespaced.py`

**Note:** v0 `NamespacedStore` wraps a `ClearableStore` (the real collision case is
the shared `FilesystemStore` between the `oauth` and `cred` namespaces). Preserving
arbitrary capabilities (e.g. versioned) generically is deferred per spec §10. The
`prefix` must be a single reserved top-level segment (`oauth`, `cred`) — it is joined
to the key as `f"{prefix}.{key}"`, so a multi-segment prefix could blur the
prefix/key boundary; v0 uses fixed single-segment prefixes only.

- [ ] **Step 1: Write the failing test `tests/test_namespaced.py`**

```python
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_namespaced.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.stores.namespaced'`

- [ ] **Step 3: Write `src/mountainash_secrets/stores/namespaced.py`**

```python
"""NamespacedStore — a key-prefixing wrapper that isolates consumers sharing a store."""
from __future__ import annotations

import typing as t

if t.TYPE_CHECKING:
    from contextlib import AbstractContextManager

    from ..core.protocols import ClearableStore, SecretRecord

__all__ = ["NamespacedStore"]


class NamespacedStore:
    """Prepends ``{prefix}.`` to every key and forwards to a wrapped ClearableStore.

    Lets two consumers (e.g. OAuth tokens under 'oauth', settings credentials
    under 'cred') share one underlying store without key collisions.
    """

    def __init__(self, inner: ClearableStore, prefix: str) -> None:
        self._inner = inner
        self._prefix = prefix

    def _k(self, key: str) -> str:
        return f"{self._prefix}.{key}"

    def get(self, key: str) -> SecretRecord | None:
        return self._inner.get(self._k(key))

    def set(self, key: str, data: SecretRecord) -> None:
        self._inner.set(self._k(key), data)

    def delete(self, key: str) -> None:
        self._inner.delete(self._k(key))

    def is_cleared(self, key: str) -> bool:
        return self._inner.is_cleared(self._k(key))

    def transaction(self, key: str) -> AbstractContextManager[None]:
        return self._inner.transaction(self._k(key))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_namespaced.py -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_secrets/stores/namespaced.py tests/test_namespaced.py
git commit -m "$(cat <<'EOF'
feat: NamespacedStore key-prefix wrapper

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: FilesystemStore (lift of settings' FilesystemBackend)

**Files:**
- Create: `src/mountainash_secrets/stores/filesystem.py`
- Test: `tests/test_filesystem.py`

**Note:** This is a near-verbatim port of
`mountainash_settings/secrets/filesystem.py` — same secure-YAML, fcntl-flock,
tombstone behavior — with the class renamed `FilesystemBackend` → `FilesystemStore`.

- [ ] **Step 1: Write the failing test `tests/test_filesystem.py`**

```python
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


def test_satisfies_clearable_store(tmp_path):
    assert isinstance(FilesystemStore(tmp_path), ClearableStore)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_filesystem.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.stores.filesystem'`

- [ ] **Step 3: Write `src/mountainash_secrets/stores/filesystem.py`**

```python
"""FilesystemStore — secure YAML credential storage on disk (full ClearableStore).

Ported from mountainash_settings.secrets.filesystem.FilesystemBackend.
Atomicity (transaction) uses fcntl.flock — atomic across processes on a LOCAL
filesystem only; NOT safe over NFS/CIFS.
"""
from __future__ import annotations

import fcntl
import os
import re
import typing as t
from contextlib import contextmanager
from pathlib import Path

import yaml

from ..core.errors import StoreUnavailableError

if t.TYPE_CHECKING:
    from collections.abc import Iterator

    from ..core.protocols import SecretRecord

__all__ = ["FilesystemStore"]

_VALID_SEGMENT = re.compile(r"^[a-z0-9_]+$")


def _validate_segment(name: str) -> None:
    if not _VALID_SEGMENT.match(name):
        raise ValueError(f"Invalid key segment: {name!r} — must match [a-z0-9_]+")


def _key_to_paths(base_dir: Path, key: str) -> tuple[Path, Path, Path, Path]:
    """Convert a dot-separated key to (yaml, tmp, tombstone, lock) paths.

    - "simple"               -> base_dir/simple.yaml
    - "domain.leaf"          -> base_dir/domain/leaf.yaml
    - "domain.provider.user" -> base_dir/domain/provider-user.yaml
    """
    parts = key.split(".")
    for part in parts:
        _validate_segment(part)

    if len(parts) == 1:
        directory = base_dir
        stem = parts[0]
    elif len(parts) == 2:
        directory = base_dir / parts[0]
        stem = parts[1]
    else:
        directory = base_dir / parts[0]
        stem = "-".join(parts[1:])

    yaml_path = directory / f"{stem}.yaml"
    tmp_path = directory / f".{stem}.tmp"
    tombstone_path = directory / f".{stem}.cleared"
    lock_path = directory / f".{stem}.lock"
    return yaml_path, tmp_path, tombstone_path, lock_path


class FilesystemStore:
    """Stores records as YAML files with secure (0o600/0o700) permissions.

    Note: a broken symlink (existing link, missing target) reads as absent
    (``get`` returns None via the ``exists()`` check); a symlink whose target
    exists is rejected with PermissionError to defeat file-swap attacks.
    """

    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)

    def get(self, key: str) -> SecretRecord | None:
        yaml_path, _, _, _ = _key_to_paths(self.base_dir, key)
        if not yaml_path.exists():
            return None
        if yaml_path.is_symlink():
            raise PermissionError(f"Credential file is a symlink: {yaml_path}")
        mode = yaml_path.stat().st_mode
        if mode & 0o077:
            raise PermissionError(f"Credential file has unsafe permissions: {yaml_path}")
        with yaml_path.open("r") as fh:
            data = yaml.safe_load(fh)
        if data is None:
            return None
        if not isinstance(data, dict):
            raise StoreUnavailableError(
                f"Corrupt secret record (not a mapping): {yaml_path}"
            )
        return data

    def set(self, key: str, data: SecretRecord) -> None:
        yaml_path, tmp_path, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        yaml_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(yaml_path.parent), 0o700)
        try:
            fd = os.open(str(tmp_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                yaml.safe_dump(data, fh)
            os.replace(str(tmp_path), str(yaml_path))
        except Exception:
            if tmp_path.exists():
                tmp_path.unlink()
            raise
        if tombstone_path.exists():
            tombstone_path.unlink()

    def delete(self, key: str) -> None:
        yaml_path, _, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        if yaml_path.exists():
            yaml_path.unlink()
        tombstone_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(tombstone_path.parent), 0o700)
        fd = os.open(str(tombstone_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.close(fd)

    def is_cleared(self, key: str) -> bool:
        _, _, tombstone_path, _ = _key_to_paths(self.base_dir, key)
        return tombstone_path.exists()

    @contextmanager
    def transaction(self, key: str) -> Iterator[None]:
        _, _, _, lock_path = _key_to_paths(self.base_dir, key)
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(str(lock_path.parent), 0o700)
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_filesystem.py -v`
Expected: PASS (11 passed)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_secrets/stores/filesystem.py tests/test_filesystem.py
git commit -m "$(cat <<'EOF'
feat: FilesystemStore (secure YAML, lifted from settings)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: EnvReader (read-only)

**Files:**
- Create: `src/mountainash_secrets/stores/env.py`
- Test: `tests/test_env.py`

- [ ] **Step 1: Write the failing test `tests/test_env.py`**

```python
from mountainash_secrets.core.protocols import SecretReader, SecretWriter
from mountainash_secrets.stores.env import EnvReader


def test_reads_value_from_environment(monkeypatch):
    monkeypatch.setenv("MASECRET_DB_PASSWORD", "hunter2")
    r = EnvReader(prefix="MASECRET_")
    assert r.get("db.password") == {"value": "hunter2"}


def test_missing_env_var_returns_none(monkeypatch):
    monkeypatch.delenv("MASECRET_NOPE", raising=False)
    assert EnvReader(prefix="MASECRET_").get("nope") is None


def test_default_prefix_is_empty(monkeypatch):
    monkeypatch.setenv("API_KEY", "k")
    assert EnvReader().get("api.key") == {"value": "k"}


def test_is_reader_not_writer():
    r = EnvReader()
    assert isinstance(r, SecretReader)
    assert not isinstance(r, SecretWriter)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_env.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.stores.env'`

- [ ] **Step 3: Write `src/mountainash_secrets/stores/env.py`**

```python
"""EnvReader — read-only SecretReader backed by environment variables.

A key like "db.password" maps to env var "{prefix}DB_PASSWORD". A present
variable returns ``{"value": <string>}``; an absent one returns None.
"""
from __future__ import annotations

import os
import typing as t

if t.TYPE_CHECKING:
    from ..core.protocols import SecretRecord

__all__ = ["EnvReader"]


class EnvReader:
    def __init__(self, prefix: str = "") -> None:
        self._prefix = prefix

    def _var(self, key: str) -> str:
        return f"{self._prefix}{key.upper().replace('.', '_')}"

    def get(self, key: str) -> SecretRecord | None:
        value = os.environ.get(self._var(key))
        if value is None:
            return None
        return {"value": value}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_env.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_secrets/stores/env.py tests/test_env.py
git commit -m "$(cat <<'EOF'
feat: EnvReader (read-only env-var SecretReader)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: require() strict-fetch helper

**Files:**
- Create: `src/mountainash_secrets/core/access.py`
- Test: `tests/test_access.py`

- [ ] **Step 1: Write the failing test `tests/test_access.py`**

```python
import pytest

from mountainash_secrets.core.access import require
from mountainash_secrets.core.errors import SecretNotFoundError
from mountainash_secrets.stores.memory import InMemoryStore


def test_require_returns_record_when_present():
    s = InMemoryStore()
    s.set("k", {"a": 1})
    assert require(s, "k") == {"a": 1}


def test_require_raises_when_absent():
    with pytest.raises(SecretNotFoundError):
        require(InMemoryStore(), "missing")


def test_require_raises_after_delete():
    s = InMemoryStore()
    s.set("k", {"a": 1})
    s.delete("k")
    with pytest.raises(SecretNotFoundError):
        require(s, "k")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_access.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'mountainash_secrets.core.access'`

- [ ] **Step 3: Write `src/mountainash_secrets/core/access.py`**

```python
"""Strict-fetch helper. ``get`` returns None for a missing key; ``require`` raises."""
from __future__ import annotations

import typing as t

from .errors import SecretNotFoundError

if t.TYPE_CHECKING:
    from .protocols import SecretReader, SecretRecord

__all__ = ["require"]


def require(store: SecretReader, key: str) -> SecretRecord:
    """Return the live record for ``key`` or raise SecretNotFoundError."""
    record = store.get(key)
    if record is None:
        raise SecretNotFoundError(f"No live secret for key: {key!r}")
    return record
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_access.py -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_secrets/core/access.py tests/test_access.py
git commit -m "$(cat <<'EOF'
feat: require() strict-fetch helper

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 10: Public API surface

**Files:**
- Modify: `src/mountainash_secrets/__init__.py` (replace the Task 1 stub)
- Test: `tests/test_public_api.py`

- [ ] **Step 1: Write the failing test `tests/test_public_api.py`**

```python
import mountainash_secrets as ms


def test_public_symbols_are_exported():
    expected = {
        "__version__",
        # protocols
        "SecretReader",
        "SecretWriter",
        "ClearableStore",
        "VersionedReader",
        "SecretRecord",
        "JSONValue",
        # resolver
        "SecretStoreResolver",
        "RegistryResolver",
        # errors
        "SecretStoreError",
        "ResolverError",
        "CapabilityError",
        "StoreUnavailableError",
        "SecretNotFoundError",
        # stores
        "InMemoryStore",
        "FilesystemStore",
        "EnvReader",
        "NamespacedStore",
        # access
        "require",
    }
    assert expected.issubset(set(ms.__all__))
    for name in expected:
        assert hasattr(ms, name), name


def test_end_to_end_resolve_and_namespace():
    resolver = ms.RegistryResolver({"local": ms.InMemoryStore()})
    store = resolver.resolve_as("local", ms.ClearableStore)
    tokens = ms.NamespacedStore(store, "oauth")
    tokens.set("garmin", {"access_token": "T", "expires_at": 123})
    assert tokens.get("garmin") == {"access_token": "T", "expires_at": 123}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_public_api.py -v`
Expected: FAIL (AssertionError — symbols not yet exported / missing attributes)

- [ ] **Step 3: Replace `src/mountainash_secrets/__init__.py`**

```python
"""mountainash-secrets — capability-graded secret-store port."""
from .__version__ import __version__
from .core.access import require
from .core.errors import (
    CapabilityError,
    ResolverError,
    SecretNotFoundError,
    SecretStoreError,
    StoreUnavailableError,
)
from .core.protocols import (
    ClearableStore,
    JSONValue,
    SecretReader,
    SecretRecord,
    SecretWriter,
    VersionedReader,
)
from .core.resolver import RegistryResolver, SecretStoreResolver
from .stores.env import EnvReader
from .stores.filesystem import FilesystemStore
from .stores.memory import InMemoryStore
from .stores.namespaced import NamespacedStore

__all__ = [
    "__version__",
    "SecretReader",
    "SecretWriter",
    "ClearableStore",
    "VersionedReader",
    "SecretRecord",
    "JSONValue",
    "SecretStoreResolver",
    "RegistryResolver",
    "SecretStoreError",
    "ResolverError",
    "CapabilityError",
    "StoreUnavailableError",
    "SecretNotFoundError",
    "InMemoryStore",
    "FilesystemStore",
    "EnvReader",
    "NamespacedStore",
    "require",
]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_public_api.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/mountainash_secrets/__init__.py tests/test_public_api.py
git commit -m "$(cat <<'EOF'
feat: public API surface

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 11: Behavioral conformance suite

**Files:**
- Create: `tests/test_conformance.py`

**Purpose:** Cover the semantic guarantees `isinstance` cannot (spec §4.1, §8) by
running the SAME behavioral assertions against every writable store. New writable
stores added later (e.g. an encrypting store) get conformance for free by adding a
factory to the parametrization.

- [ ] **Step 1: Write `tests/test_conformance.py`**

```python
"""Behavioral conformance suite — runs identical semantics over every writer store."""
import threading
import time

import pytest

from mountainash_secrets.stores.filesystem import FilesystemStore
from mountainash_secrets.stores.memory import InMemoryStore
from mountainash_secrets.stores.namespaced import NamespacedStore


@pytest.fixture(params=["memory", "filesystem"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryStore()
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
    oauth = NamespacedStore(store, "oauth")
    cred = NamespacedStore(store, "cred")
    oauth.set("github", {"token": "T"})
    cred.set("github", {"password": "P"})
    assert oauth.get("github") == {"token": "T"}
    assert cred.get("github") == {"password": "P"}
```

- [ ] **Step 2: Run the conformance suite**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest tests/test_conformance.py -v`
Expected: PASS (16 passed — 8 tests × 2 store params)

- [ ] **Step 3: Commit**

```bash
git add tests/test_conformance.py
git commit -m "$(cat <<'EOF'
test: behavioral conformance suite over writer stores

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 12: Full suite + lint gate (green-bar checkpoint)

**Files:** none (verification only)

- [ ] **Step 1: Run the full test suite**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m pytest -v`
Expected: PASS — all tests across all modules green (≈65 tests).

- [ ] **Step 2: Run the lint gate**

Run: `/home/nathanielramm/git/mountainash-ide/mountainash-dev-local/.venv/bin/python -m ruff check src tests`
Expected: `All checks passed!`
If ruff reports fixable issues, run `... -m ruff check --fix src tests`, re-run Step 1, and review the diff before committing.

- [ ] **Step 3: Commit any lint fixes (only if Step 2 changed files)**

```bash
git add -A
git commit -m "$(cat <<'EOF'
style: ruff clean

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Out of scope for v0 (do NOT implement here)

These are spec §7 steps 2–5, each its own later plan:
- **SDK store adapters** (`stores/aws.py`, `vault.py`, `azure.py`, `gcp.py`) — port utils-secrets handlers; take authenticated clients.
- **settings deprecation shim** + reference-resolution migration onto an injected resolver.
- **auth-client** OAuth-flow migration onto the injected resolver / `ClearableStore`.
- **wearables** composition-root wiring.
- Publishing/remote/PR — a remote does not exist yet; v0 lands on local `develop`.
```
