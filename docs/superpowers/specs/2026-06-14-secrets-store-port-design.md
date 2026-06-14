# mountainash-secrets — Secret Store Port Design

**Status:** Draft for review (Codex adversarial pass folded)
**Date:** 2026-06-14
**Author:** Nathaniel Ramm (with Claude)
**Repo:** `mountainash-secrets` (new, dedicated package)

---

## 1. Motivation

Credential and secret handling is currently split across two packages with two
unrelated abstractions, and a third package (settings) that should own neither:

- **`mountainash_settings.secrets`** ships a *persistence* contract —
  `SecretsBackend` (`get/set/delete/transaction`) plus a `FilesystemBackend`
  (secure YAML-on-disk, fcntl locking, tombstones) and a global registry.
  auth-client reads this registry to persist and refresh OAuth tokens, and
  settings *itself* reads it to resolve credential references during settings
  load. **Storing credentials is not a settings concern** — the user's framing:
  "a pragmatic hack at the wrong level."
- **`mountainash-utils-secrets`** ships a *retrieval* stack — per-provider
  handlers (`AWSSecretsHandler`, `HashiCorpVaultHandler`, …) exposing
  `get_secret(name) -> SecretStr` with versioning/metadata. It is **read-only**
  in practice: `set_secret`/`delete_secret` are abstract and unimplemented by
  every provider. It also carries its **own** copy of the auth-strategy
  machinery to authenticate to the vaults.

These are two views of **one domain**: a keyed store of secret material. Today
they are two parallel stacks, neither at the right architectural level, with a
latent dependency cycle (`utils-secrets` already depends on `settings`, so
moving the persistence contract *into* utils-secrets would create
`settings → utils-secrets → settings`).

This design replaces both with a single dedicated package, **`mountainash-secrets`**,
built around one **capability-graded secret-store port**. settings and
auth-client become *consumers* that depend *down* onto the port; neither owns
storage, and there is no cycle.

## 2. Goals

1. **One port, graded by capability.** A single protocol family expresses
   read / read-write / clearable / versioned stores. Consumers depend on the
   narrowest capability they need; capability mismatches are caught at **wiring
   time** (resolution) and by **behavioral conformance tests**, not by call-time
   `NotImplementedError`.
2. **A dedicated home.** `mountainash-secrets` owns the port and all store
   implementations (filesystem token store, in-memory test double, vault
   readers). settings and auth-client stop owning credential storage.
3. **No dependency cycle, no new floor.** The port sits *below* both settings
   and auth-client. Store adapters take an already-authenticated client, so the
   package has **no dependency on auth-client** and duplicates no auth strategy.
4. **Injection over global singletons.** Name→store indirection is preserved
   (config references a store by name), but resolution goes through an
   **injected** resolver wired at an application composition root — there is no
   process-global mutable registry.
5. **Migratable.** settings' credential-reference resolution and auth-client's
   OAuth persistence move onto the port with minimal churn; utils-secrets'
   vault adapters are reframed as stores and the package is retired.

## 3. Non-Goals

- **Not** a secrets *rotation* engine, KMS wrapper, or policy system.
- **Not** an auth library. Authenticating *to* a vault is auth-client's job;
  this package receives authenticated clients.
- **Not** a settings/config loader. Resolving `${secret:...}` references stays
  in settings; this package only supplies the read capability it delegates to.
- **No** encryption-at-rest scheme beyond what a concrete store chooses (the
  filesystem store relies on file permissions + secure YAML; a future
  encrypting store is an additive adapter).
- **No memory zeroization / secret-lifetime guarantee.** CPython cannot reliably
  scrub `str`/`dict` from memory; pursuing it would be security theater. Instead
  the package adopts two concrete hygiene rules: (a) `SecretRecord` values MUST
  NOT be placed in exception messages or `repr`/`str` of store/resolver objects;
  (b) callers are responsible for not logging records. Lifetime management
  (short-lived handles) is a consumer concern, called out but not enforced.

## 4. Architecture

### 4.1 The capability-graded port (core, zero-dependency)

The heart of the package is a protocol ladder. Each rung is `runtime_checkable`.
Consumers annotate against the **narrowest** rung they require.

```python
# mountainash_secrets/core/protocols.py
import typing as t
from contextlib import AbstractContextManager

JSONValue = t.Union[str, int, float, bool, None, list["JSONValue"], dict[str, "JSONValue"]]
SecretRecord = dict[str, JSONValue]   # the value lingua franca — see §4.2

@t.runtime_checkable
class SecretReader(t.Protocol):
    """Read a live secret record by key. The base capability.

    Returns the record, or None if no LIVE record exists (key never set, or
    deleted/tombstoned). See §6 for the get()/is_cleared() contract.
    """
    def get(self, key: str) -> SecretRecord | None: ...

@t.runtime_checkable
class SecretWriter(SecretReader, t.Protocol):
    """Read + mutate. `transaction(key)` is the atomicity primitive (§4.7)."""
    def set(self, key: str, data: SecretRecord) -> None: ...
    def delete(self, key: str) -> None: ...
    def transaction(self, key: str) -> AbstractContextManager[None]: ...

@t.runtime_checkable
class ClearableStore(SecretWriter, t.Protocol):
    """Distinguishes 'deliberately cleared' from 'never set' (tombstones).

    OAuth refresh needs this: a cleared token must not be mistaken for a
    first-time authorization.
    """
    def is_cleared(self, key: str) -> bool: ...

@t.runtime_checkable
class VersionedReader(SecretReader, t.Protocol):
    """Vault-style versioned read (additive; not all stores support it)."""
    def get_version(self, key: str, version: str) -> SecretRecord | None: ...
    def list_versions(self, key: str) -> list[str]: ...
```

**Honest scope of the type ladder.** `runtime_checkable` `isinstance` checks
method *names only* — not signatures, return types, or semantics. The ladder
therefore buys two concrete things, and we do not overclaim a third:

- **Static typing:** a consumer annotated `store: ClearableStore` is checked by
  the type checker against callers passing a read-only reader.
- **Wiring-time capability check:** resolution is capability-aware
  (`resolve_as`, §4.3) and raises `CapabilityError` when a named store lacks the
  requested rung — so a read-only vault wired where a writer is required fails
  at startup, not at `.set()` time.
- **NOT semantic proof.** A store can satisfy the method names yet behave wrong
  (a non-locking `transaction`). That is caught by the **behavioral conformance
  suite** (§8), which every store must pass — not by `isinstance`.

A combined versioned-and-writable protocol is intentionally **not** defined
(YAGNI); if a writable versioned store appears, add the intersection protocol
then.

### 4.2 Value type — `SecretRecord`, with a fidelity contract

**Decision: the value is a mapping of JSON-native values,
`dict[str, JSONValue]` (`SecretRecord`).** This keeps the dict shape (both
current consumers already speak dicts — auth-client persists an OAuth bundle,
settings resolves a credential record) and adds the contract that closes the
silent-coercion hole Codex flagged:

**Fidelity contract.** Every store MUST round-trip JSON-native values
*losslessly*. Values therefore MUST be JSON-native (`str`/`int`/`float`/`bool`/
`None`/`list`/nested `dict`). The store does **not** accept or invent richer
types:

- **Timestamps** (e.g. OAuth `expires_at`) are stored as an `int` epoch-seconds
  or an ISO-8601 `str` by caller convention — never a `datetime` object (which
  YAML/JSON would coerce unpredictably).
- **Binary material** (certs, keys) is base64-`str` in a record field; the
  *field name* carries the encoding convention (e.g. `cert_b64`). The port does
  not transcode.
- **Readers return the secret payload, not the provider envelope.** A vault
  response of `{data, metadata, lease, version}` is unwrapped by the adapter to
  the payload mapping; provider metadata is exposed only via `VersionedReader`
  methods or omitted. Adapters MUST document their unwrapping.

Opaque `bytes` was considered and rejected: it imposes a codec on every consumer
for no present benefit (YAGNI), whereas the JSON-native contract gives lossless
round-tripping with zero serialization churn at the auth-client boundary (it
already calls `set(key, dict)`).

### 4.3 Resolution — injected resolver, capability-aware, no global

Config references a store by **name** (you cannot serialize a live filesystem
handle into an auth profile). That name→store mapping is legitimate. The
*global mutable singleton* implementing it today is not — it forces every test
to `clear_secrets_registry()` and couples import order. **There is no
process-global default resolver in this design.** A single resolver is built at
the application composition root (§4.4) and injected into each consumer.

```python
# mountainash_secrets/core/resolver.py
C = t.TypeVar("C", bound=SecretReader)

@t.runtime_checkable
class SecretStoreResolver(t.Protocol):
    def resolve(self, name: str) -> SecretReader: ...
    def resolve_as(self, name: str, capability: type[C]) -> C: ...

class RegistryResolver:
    """A resolver backed by an explicit, instance-scoped mapping of
    name -> already-constructed store. It LOOKS UP pre-built stores; it never
    constructs or authenticates them (that is the composition root's job, §4.4).
    """
    def __init__(self, stores: dict[str, SecretReader] | None = None) -> None: ...
    def register(self, name: str, store: SecretReader, *, replace: bool = False) -> None: ...
    def resolve(self, name: str) -> SecretReader: ...          # raises ResolverError if unknown
    def resolve_as(self, name: str, capability: type[C]) -> C: ...  # raises CapabilityError if rung missing
```

- **Capability-aware resolution** closes the "resolver returns `SecretReader`
  but auth-client needs `ClearableStore`" gap: auth-client calls
  `resolver.resolve_as(name, ClearableStore)`, which `isinstance`-checks the
  named store against the protocol and raises `CapabilityError` at wiring time,
  returning a correctly-typed handle. settings calls
  `resolver.resolve_as(name, SecretReader)`.
- **Thread-safety:** `register`/`replace` are **composition-time** operations
  (single-threaded startup); `resolve`/`resolve_as` are read-only lookups safe
  for concurrent access against an unchanging map. `RegistryResolver` guards its
  dict with a lock for defensiveness, but mutation after startup is out of the
  intended usage and not a supported concurrency pattern.
- **Test isolation is automatic:** a test constructs
  `RegistryResolver({"local": InMemoryStore()})` and injects it. No global, no
  teardown.

### 4.4 Composition root — who builds authenticated stores

This is the wiring site Codex correctly identified as unspecified. **The
application composition root owns store construction and registration:**

1. The app (e.g. wearables, or a service bootstrap) builds each concrete store.
   For SDK-backed stores this is where it uses **auth-client** to construct an
   authenticated client and hands it to the adapter:
   ```python
   boto_client = build_authed_secretsmanager_client(iam_auth_profile)  # uses auth-client
   resolver.register("vault-prod", AwsSecretsReader(boto_client))
   resolver.register("local", FilesystemStore(base_dir))
   ```
2. The app injects that one `resolver` into settings and auth-client.
3. settings/auth-client `resolve`/`resolve_as` by name at use time, against
   **pre-built** instances.

Consequences, and why the no-auth-client claim holds:

- **Adapters take a fully-constructed client only.** The earlier
  "or a `connect_kwargs` dict" escape hatch is **removed** — it would have
  pulled auth decisions back into the adapter. Construction + auth happen *above*
  the package, at the composition root.
- **`mountainash-secrets` imports neither auth-client nor settings.** It shares
  no exception bases, enums, or profile types with them; the dependency arrows
  point only *into* `mountainash-secrets`. The acyclicity in §4.6 is therefore
  structural, not merely conventional.

### 4.5 Key namespacing — avoiding cross-consumer collisions

Two consumers share one store (e.g. the `local` `FilesystemStore`), so their key
spaces must not collide. The port defines a **reserved-prefix convention** plus a
helper:

- Keys are dot/slash-segmented. Each consumer owns a top-level namespace:
  `oauth/<provider>/<account>` for auth-client tokens; `cred/<reference>` for
  settings-resolved credentials. Cross-namespace writes are a consumer bug.
- `core/stores/namespaced.py` provides
  `NamespacedStore(inner: S, prefix: str) -> S` — a transparent wrapper that
  prepends `prefix` to every key and forwards the full capability of `inner`.
  A consumer wraps its resolved store once
  (`tokens = NamespacedStore(store, "oauth")`) and is collision-isolated by
  construction.

### 4.6 Dependency graph (acyclic)

```
            mountainash-secrets            (floor; pyyaml only, SDKs optional)
             ▲        ▲          ▲
             │        │          │
   mountainash-settings   mountainash-auth-client
             ▲        ▲          ▲
             └────────┴──────────┘   (consumers inject concrete stores)
```

- `settings → mountainash-secrets` (for `SecretReader` + a resolver). One-way.
- `auth-client → mountainash-secrets` (for `ClearableStore` + the resolver).
  One-way.
- `mountainash-secrets` depends on **neither** (and shares no types with them).
  No cycle. No new floor package — `mountainash-secrets` *is* the floor.
- The settings deprecation shim (§7) imports *from* `mountainash-secrets`; since
  secrets has no deps, `settings.secrets → mountainash-secrets` stays one-way
  even while `auth-client → settings` exists for unrelated APIs. No cycle.

### 4.7 Concurrency contract

`transaction(key)` is the single cross-actor atomicity primitive a `SecretWriter`
exposes. Its guarantee is **per-store-documented**:

- `InMemoryStore`: in-process lock — single-process only (test/dev double).
- `FilesystemStore`: `fcntl.flock` — atomic across processes on a **local**
  filesystem; explicitly NOT safe over NFS/CIFS (documented limitation).
- Any future **remote writable** store MUST implement `transaction` via the
  backend's compare-and-swap / conditional-write, or document that it provides
  no cross-writer atomicity. The read-modify-write inside `transaction` for
  token refresh (auth-client) depends on this; a store that cannot honor it must
  not be registered under a name used for token persistence.

### 4.8 Package structure

```
mountainash-secrets/
  src/mountainash_secrets/
    __init__.py          # public API: protocols, resolver, stdlib stores, NamespacedStore
    __version__.py
    core/                # ZERO third-party deps
      protocols.py       # SecretReader/Writer/ClearableStore/VersionedReader, SecretRecord, JSONValue
      resolver.py        # SecretStoreResolver, RegistryResolver
      errors.py          # SecretStoreError hierarchy (§6)
    stores/
      memory.py          # InMemoryStore  — full ClearableStore; canonical test double
      filesystem.py      # FilesystemStore — full ClearableStore (the OAuth token persistence)
      env.py             # EnvReader       — SecretReader (read-only)
      namespaced.py      # NamespacedStore — capability-preserving key-prefix wrapper
      aws.py             # AwsSecretsReader (+VersionedReader)   [extra: aws]
      vault.py           # VaultStore      (hvac)                [extra: hashicorp]
      azure.py           # AzureKeyVaultReader                   [extra: azure]
      gcp.py             # GcpSecretsReader                      [extra: gcp]
  docs/superpowers/specs/2026-06-14-secrets-store-port-design.md
  pyproject.toml         # CalVer; core needs only pyyaml; SDKs are optional extras
```

`FilesystemStore` is a near-verbatim lift of settings' `FilesystemBackend`
(secure YAML, `_key_to_paths`, fcntl `flock` transaction, tombstones,
`0o600/0o700` perms, symlink/perm guards) onto the new protocol names.

## 5. Consumer migration

### 5.1 settings — credential-reference resolution becomes a consumer

- The `mountainash_settings.secrets` subpackage is reduced to a **deprecation
  shim** re-exporting from `mountainash_secrets` with a `DeprecationWarning`
  (one release), then removed (§7).
- Reference resolution (`base_settings.py`, `resolve.py`) depends on
  `mountainash_secrets.SecretReader` and takes a resolver injected by the
  application. settings owns the **feature** (substituting `${secret:...}`), not
  the storage, and resolves under the `cred/` namespace.

### 5.2 auth-client — OAuth persistence moves onto the port

- `connections/oauth2/flow.py` and `oauth1/flow.py` replace
  `from mountainash_settings.secrets.registry import get_secrets_backend` with a
  resolver injected into the flow; they obtain the token store via
  `resolver.resolve_as(name, ClearableStore)` and wrap it
  `NamespacedStore(store, "oauth")`.
- The call shape (`get/set/delete/transaction/is_cleared`) is **unchanged** —
  the port preserves those names and the `dict` value type — so only the
  acquisition path and the (new) resolver constructor argument change.
- Test fixtures swap `register_secrets_backend`/`clear_secrets_registry` for a
  freshly-injected `RegistryResolver({name: InMemoryStore()})` per test.

### 5.3 utils-secrets — reframed and retired

- Vault handlers become `stores/` adapters on the port, taking authenticated
  clients; honest capabilities (most are `SecretReader`/`VersionedReader`).
- The duplicated `_core/auth/` strategy copy is **deleted** (auth lives at the
  composition root).
- `mountainash-utils-secrets` is **deprecated and archived** once the adapters
  land here. No long-term wrapper.

## 6. Error handling and read semantics

`core/errors.py`:

- `SecretStoreError` (base)
- `ResolverError` — unknown store name.
- `CapabilityError` — named store lacks a requested capability rung
  (`resolve_as`). Raised at wiring time.
- `StoreUnavailableError` — backend/transport/IO failure (wraps SDK errors).

**`get()` / tombstone semantics (no ambiguity):**

- `get(key)` returns the live record, or `None` iff **no live record exists** —
  whether the key was never set or was deleted/tombstoned. A present key always
  maps to a non-`None` record (there is no "known-empty present key").
- `is_cleared(key)` (ClearableStore) returns `True` iff a tombstone exists —
  this is how a caller distinguishes *deliberately cleared* from *never set*
  when both yield `get() == None`.
- `get` never raises for a missing key. An optional strict helper
  `require(store, key)` raises `SecretNotFoundError`; `get` itself does not.
- `get_version(key, version)` returns the record for that version, or `None` iff
  the key or that version is absent; provider/transport errors raise
  `StoreUnavailableError`. (Distinguishing absent-key from absent-version is not
  guaranteed across providers and is explicitly not promised.)

Adapters wrap provider-SDK exceptions into this hierarchy so consumers handle one
error family regardless of backend. Error messages MUST NOT include record
values (§3 hygiene rule).

## 7. Migration, compatibility, and sequencing

Cross-repo and version-boundary-sensitive. **The shim-vs-clean-break question is
decided now: ship the shim** (its cost is ~10 lines and it removes the
partial-upgrade breakage window Codex flagged). Order:

1. **`mountainash-secrets` v0** — `core` (port + resolver + errors) +
   `InMemoryStore` + `FilesystemStore` + `EnvReader` + `NamespacedStore` + the
   behavioral conformance suite. SDK adapters deferred (not on the
   OAuth/wearables path). Publish.
2. **settings** — add `mountainash-secrets` dep; migrate reference resolution
   onto `SecretReader` + injected resolver; replace `mountainash_settings.secrets`
   with the **deprecation shim** (re-exports from `mountainash_secrets`, emits
   `DeprecationWarning`). Release. *This lands before the auth-client cutover so
   no release ever has new-auth-client + old-settings-secrets.*
3. **auth-client** — migrate OAuth flows + fixtures onto the injected resolver /
   `ClearableStore`; add `mountainash-secrets` dep; drop the
   `mountainash_settings.secrets` import; bump version.
4. **SDK store adapters** (`aws`/`vault`/`azure`/`gcp`) — port utils-secrets'
   handlers; deprecate + archive utils-secrets.
5. **wearables** (the original downstream driver) — now unblocked: its
   composition root builds a `FilesystemStore`, registers it, injects the
   resolver; OAuth token persistence flows through it.

**Partial-upgrade safety:** because the runtime contract auth-client relies on
(method names + `dict` value) is preserved and the shim keeps the old import
path alive for one release, there is no window where a consumer can resolve
against a missing symbol. Steps 2→3 ordering removes the new-auth/old-settings
hazard. Downstream pins must move settings (step 2) and auth-client (step 3) in
that order.

## 8. Testing strategy

- **Behavioral conformance suite:** a reusable, parametrized suite run against
  **every** store. It asserts not just `isinstance` against the
  `runtime_checkable` protocols but the *semantics* of each rung present:
  round-trip fidelity of JSON-native records (including nested + the
  int-timestamp / base64-binary conventions), `set`→`get` visibility,
  `delete`→`get==None`-and-`is_cleared==True`, transaction atomicity (a
  concurrent writer is serialized), and namespace isolation via `NamespacedStore`.
  This is where the "names-only `isinstance`" gap (§4.1) is actually covered.
- **`InMemoryStore` is the canonical double** — full `ClearableStore`, used by
  auth-client/settings tests instead of touching disk or any global.
- **`FilesystemStore`:** port settings' existing filesystem tests (flock,
  tombstones, permission/symlink guards, atomic replace).
- **Resolver:** injection; `resolve` unknown name → `ResolverError`;
  `resolve_as` capability shortfall → `CapabilityError`; no cross-test state.
- **No feature-count tests.** Conformance is structural/behavioral, never a
  count of providers.

## 9. Decisions locked in this revision

The following were open in the first draft and are now settled (Codex pass):

1. **`SecretRecord` = `dict[str, JSONValue]` with a lossless round-trip
   fidelity contract** (§4.2). Opaque `bytes` rejected (YAGNI).
2. **No process-global resolver; injection from a composition root** (§4.3–4.4).
3. **Resolution is capability-aware** (`resolve_as` → `CapabilityError`) so
   read/write mismatches fail at wiring time (§4.3).
4. **Adapters take a fully-authenticated client only**; no `connect_kwargs`
   (§4.4). The package has no auth-client dependency.
5. **Key namespacing convention + `NamespacedStore`** for shared stores (§4.5).
6. **settings ships a one-release deprecation shim**, sequenced before the
   auth-client cutover (§7).
7. **SDK adapters deferred to step 4**; v0 is filesystem/memory/env only (§7).
8. **utils-secrets is deprecated and archived**, not kept as a wrapper (§5.3).

## 10. Remaining questions for the review gate

- **Namespace ownership registry:** §4.5 reserves `oauth/` and `cred/` by
  convention. Is a convention enough, or should the package expose an enum of
  reserved namespaces to make collisions a typed error? (Lean: convention for
  v0; revisit if a third consumer appears.)
- **`require()` placement:** strict-fetch helper as a free function vs a mixin on
  the protocols. (Lean: free function in `core` — keeps the protocol minimal.)
