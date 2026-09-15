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
