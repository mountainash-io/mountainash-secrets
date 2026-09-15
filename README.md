# mountainash-secrets

A capability-graded secret-store port: one protocol family
(`SecretReader` → `SecretWriter` → `ClearableStore`, plus `VersionedReader`)
with pluggable stores (in-memory, filesystem, env) and an injected resolver.
Requires Python 3.12 or later.

The package authenticates nothing and depends on neither `mountainash-settings`
nor `mountainash-auth-client`. Authenticated SDK clients are built by the
application composition root and handed to store adapters.

See `docs/superpowers/specs/2026-06-14-secrets-store-port-design.md`.

## Candidate verification and publishing

Public PyPI publication remains unconfirmed. `build-and-release-package.yml` builds candidates for PRs targeting `main`/`develop` and for manual runs. It verifies the wheel and sdist-derived wheel in fresh external Python 3.12 environments, with public PyPI dependencies and recorded module origins.

Publication requires separate authorization: configure the existing `pypi` GitHub environment with human reviewers and a custom deployment policy allowing only the `main` branch, and configure PyPI Trusted Publishing for this repository, workflow filename `build-and-release-package.yml`, and environment `pypi`. A pending publisher does not reserve the project name.

Prepare the final version in source through the normal reviewed release PR. Dispatch on `main` with `publish=true`, review the candidate hashes/evidence, then approve the environment. The job uploads the exact same-run wheel/sdist without rebuilding or `skip-existing`. Public file/hash and install/import confirmation is required before calling the release published. The default `publish=false` produces only a candidate.
