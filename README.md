# mountainash-secrets

A capability-graded secret-store port: one protocol family
(`SecretReader` → `SecretWriter` → `ClearableSecretStore`, plus `VersionedSecretReader`)
with pluggable stores (in-memory, filesystem, env) and an injected resolver.
Requires Python 3.12 or later.

The package authenticates nothing and depends on neither `mountainash-settings`
nor `mountainash-auth-client`. Application composition constructs stores and
injects a `SecretRegistryResolver`; the resolver selects preconstructed objects,
not plugins or authenticated SDK clients.

## Installation and shipped capabilities

Install the selected verified candidate wheel by passing its local path to
`python -m pip install`. Candidate builds are not evidence of PyPI publication;
public-index installation remains a separate release gate.

The only runtime dependency is PyYAML. No cloud adapters or SDK extras are shipped:
`aws`, `azure`, `gcp`, `hashicorp` and aggregate `all` have been removed. Consumers
must stop requesting those extras; applications using SDKs directly own those
dependencies independently.

| Public implementation | Capability and boundary |
| --- | --- |
| `InMemorySecretStore` | Clearable records; deep-copy isolation and cooperative single-process transactions |
| `FilesystemSecretStore` | Clearable YAML records; application-provisioned root and local POSIX locking |
| `EnvReader` | Read-only environment lookup |
| `NamespacedSecretStore` | Trusted prefix wrapper over an injected clearable store; not tenant isolation |

`VersionedSecretReader` is an extension protocol, not an implemented versioned
store or cloud service. Runtime capability checks establish method availability,
not authorization or semantic correctness.

Public package imports load the filesystem module and require `fcntl`, even when
only memory/environment stores are selected. Windows imports are not supported.
Filesystem acceptance has been exercised on Linux; macOS is not certified by that
evidence. NFS/CIFS and distributed locking are outside the supported contract.

The [historical design](https://github.com/mountainash-io/mountainash-central/blob/main/04.planning/mountainash-secrets/superpowers/specs/2026-06-14-secrets-store-port-design.md)
is a draft planning reference, not a shipped capability list or an approved
consumer migration. The usage and limitations below are self-contained.


## Filesystem storage and ownership

Provision the root directory before constructing the store. The application owns
its users, groups, directory modes, umask, ACLs and trusted initialization path.
The store never creates a missing root or repairs directory permissions.

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast
from mountainash_secrets import (
    ClearableSecretStore,
    FilesystemSecretStore,
    SecretRegistryResolver,
)

with TemporaryDirectory() as temporary:
    root = Path(temporary) / "credentials"
    root.mkdir(mode=0o700)  # Example application policy, not a library requirement.
    with FilesystemSecretStore(root) as filesystem:
        resolver = SecretRegistryResolver({"local": filesystem})
        capability = cast(type[ClearableSecretStore], ClearableSecretStore)
        store = resolver.resolve_as("local", capability)
        with store.transaction("service.account"):
            assert store.get("service.account") is None
            assert not store.is_cleared("service.account")
            store.set("service.account", {"token": "dummy-example"})
            assert store.get("service.account") == {"token": "dummy-example"}
            store.delete("service.account")
            assert store.get("service.account") is None
            assert store.is_cleared("service.account")
            store.set("service.account", {"token": "dummy-replacement"})
            assert not store.is_cleared("service.account")
            assert store.get("service.account") == {"token": "dummy-replacement"}
```

Deletion leaves a tombstone: `is_cleared()` distinguishes deliberately cleared
records from never-set keys; a successful subsequent write removes that marker.
The outer context owns the store handle; `transaction()` only coordinates
participating operations on one key and does not close the store. The narrow
protocol-token cast supports Mypy 1.10.1; see [installed typing](#installed-package-typing).

Application composition owns and closes injected filesystem stores. Capability
protocols do not require `close()`, and namespace wrappers do not close shared
stores. Namespace prefixes and capability checks are not authorization boundaries.

### Root selection, privacy and lifetime

Trusted deployment-controlled root/ancestor links are allowed at initialization.
The actual opened root is pinned: retargeting its alias or assigning `base_dir`
cannot retarget an existing instance. Construct a new instance to select a new
root. Internal namespace and managed-file symlinks are refused.

Filesystem keys are dot-separated nonempty segments matching `[a-z0-9_]+`.
Use the public `to_key_segment()` helper for arbitrary identifiers rather than
embedding emails, uppercase strings or path separators directly in a key.

Keys retain their layout: `key` becomes `key.yaml`, `domain.key` becomes
`domain/key.yaml`, and `domain.provider.user` becomes `domain/provider-user.yaml`.
Missing read/cleared checks create nothing. Write/delete/transaction may create
a namespace with requested mode `0777`, subject to application umask, default ACL
and setgid/group inheritance. Existing directory policy is not changed.

Credentials, markers and locks must be regular, singly linked files with no
group/other permission bits. New managed files request `0600` and are checked
before use; invalid existing entries are rejected, never chmodded or repaired.
Credential hard links are now rejected. Unpredictable temporary files are
exclusively created before plaintext is written; stale `.key.tmp` entries are
unrelated and untouched. A no-writer FIFO is rejected without a blocking read.

`close()` is terminal, idempotent and nonwaiting. Newly started operations,
including entry into a previously created transaction context, fail after close.
Already admitted operations can finish on their own handles. Active or waiting
transactions retain their own lock until exit; close does not cancel a blocked
flock, release another operation's lock or roll back its write. Finish operations
before closing where possible. Context exit preserves an exception from user code.

### Errors and partial completion

Filesystem-generated diagnostics contain fixed messages, not keys, paths, record
values or retained raw cause/context exceptions—even inside a caller's exception
handler. Rejected keys/nonmapping writes raise `ValueError`; unsafe filesystem
entries raise `PermissionError`. Other failures raise the existing
`SecretStoreUnavailableError`; inspect its `reason`, not its message:

| Reason | Meaning |
| --- | --- |
| `unavailable` | Backend I/O, serialization or cleanup failed; mutation may have occurred |
| `store_closed` | New operation attempted after terminal close |
| `unsupported_filesystem` | Required safe filesystem mechanisms are unavailable |
| `decode_error` | Credential is not valid UTF-8 |
| `malformed_yaml` | YAML parsing/construction/conversion failed |
| `invalid_record_shape` | Parsed credential is not a mapping, including empty/null |
| `write_committed_cleanup_failed` | New credential committed, marker cleanup failed |

A genuinely missing credential returns `None`; corrupt empty/null files do not.
No raw diagnostic mode is provided. Records themselves are plaintext dictionaries,
not redacting containers. This does not redact caller exceptions or debugger
captures of arbitrary memory.

Atomic replacement is the write commit point. Before it, a failed write preserves
the old credential and marker; cleanup removes only the operation's owned temp
when possible. Cleanup failure can leave a private temporary file.
After replacement, failed marker cleanup raises
`write_committed_cleanup_failed` without rolling back the new record.
`get()` still reads that record; a surviving valid marker makes `is_cleared()`
true, while an invalid marker is rejected. An explicit subsequent write under
application-owned `transaction()` coordination can restore ordinary
live-record/absent-marker state. There is no automatic retry or recovery.

Delete is not a two-file atomic operation: marker creation can fail after the
credential has been removed, leaving absence without a marker. A pre-existing
invalid marker is rejected *before* credential removal.

### Filesystem limits

This backend requires local POSIX descriptor-relative operations and `fcntl.flock`.
Direct reads/writes/deletes do not lock automatically. All participants must use
the same stable lock inode; locks are never replaced to bypass contention.
No nested/reentrant transaction, fairness, timeout, NFS/CIFS or Windows guarantee
is provided. Verification on Linux does not certify macOS.

The application must prevent untrusted directory mutation and secure initial root
selection. Descriptor pinning and no-follow inode checks are not a hostile
same-UID/administrator sandbox. Name-to-inode inspection followed by
unlink/replace/flock is not atomic against a later directory writer. Privileged
relocation of an opened directory is outside this boundary.

Atomic visibility is not power-loss durability: no fsync guarantee or secure
deletion is provided. Crashes can leave private plaintext temporary files; the
store does not sweep them.

## Installed-package typing

The wheel and sdist include the PEP 561 `py.typed` marker. Type checkers can use
the package's inline annotations through installed public imports; no
`ignore_missing_imports` or `import-untyped` suppression is needed.

`resolve()` returns `SecretReader`; `resolve_as()` preserves the requested
capability type. Mypy 1.10.1 rejects a protocol class passed directly to a
`type[C]` parameter with `type-abstract`, even though the resolver only checks
`isinstance` and never constructs the capability. Use a narrow cast of the
protocol class token with that checker:

```python
from typing import assert_type, cast
from mountainash_secrets import (
    ClearableSecretStore,
    InMemorySecretStore,
    SecretRegistryResolver,
)

resolver = SecretRegistryResolver({"local": InMemorySecretStore()})
capability = cast(type[ClearableSecretStore], ClearableSecretStore)
store = resolver.resolve_as("local", capability)
assert_type(store, ClearableSecretStore)
store.set("service.token", {"value": "dummy"})
```

This cast does not cast the store or result to `Any`; incompatible records and
unsupported capability methods remain type errors. Concrete store classes need
no workaround. Static typing does not replace runtime capability checks or
establish authorization. Mypy is a development tool, not a runtime dependency.

## Candidate verification and publishing

CI follows the MountainAsh PR/release conventions: pytest with coverage and Codecov,
Ruff, Radon, source-branch validation for `main`, and a release build-environment
check. Secrets is a leaf package, so no sibling checkouts, dependency manifest, or
private-dependency bootstrap is needed. Its core dependency is public PyYAML.

`build-and-release-package.yml` builds one wheel and sdist, verifies the candidate
and sdist-derived wheel in fresh external Python 3.12 environments, and records
public dependency sources, `pip check`, module origins, and artifact hashes.
It also generates full/direct JSON SBOMs through `build_github`.

| Trigger | GitHub release and wheels PR | PyPI |
| --- | --- | --- |
| Open or updated PR | No; build and verify only | No |
| Merged PR | Yes | No |
| Manual, default inputs | No; build and verify only | No |
| Manual, `release=true` | Yes | Only if separately enabled |
| Manual on `main`, `publish=true` | Only if `release=true` | Yes, after approval |

Merged PRs to `main` use the reviewed source version. Merges to `develop` produce
`rc<run_number>` versions; merges to other configured branches produce
`b<run_number>` versions. Manual MountainAsh releases choose `release_type`
(`production`, `rc`, or `beta`). Build-only suffixes are never committed.

GitHub releases contain the verified wheel, sdist, and SBOMs. The distribution
workflow opens a release-branch PR targeting `mountainash-wheels/develop`, without
pushing directly to `develop` or `main`. Configure `CI_APP_ID` and
`CI_APP_PRIVATE_KEY` for a GitHub App with contents/pull-request write access to
`mountainash-wheels`. Configure `CODECOV_TOKEN` for coverage uploads.

To publish to both destinations in one run, dispatch on `main` with
`release=true`, `publish=true`, and `release_type=production`. Both publishers
consume the same verified artifact IDs/hashes without rebuilding or overwriting
existing releases. If the version is already distributed on GitHub, leave
`release=false` for a PyPI-only run.

PyPI publication requires the `pypi` GitHub environment with human reviewers and a
custom deployment policy allowing only `main`, plus PyPI Trusted Publishing for
this repository, workflow filename `build-and-release-package.yml`, and environment
`pypi`. A pending publisher does not reserve the project name. After upload, the
workflow checks public file hashes and a clean public-PyPI install/import.
