# mountainash-secrets

A capability-graded secret-store port: one protocol family
(`SecretReader` → `SecretWriter` → `ClearableStore`, plus `VersionedReader`)
with pluggable stores (in-memory, filesystem, env) and an injected resolver.

The package authenticates nothing and depends on neither `mountainash-settings`
nor `mountainash-auth-client`. Authenticated SDK clients are built by the
application composition root and handed to store adapters.

See `docs/superpowers/specs/2026-06-14-secrets-store-port-design.md`.
