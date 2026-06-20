# Skylos Release Workflow

This document defines how Skylos releases are prepared, created, and published.

## Scope

- Automated semantic versioning with Release Please
- GitHub release creation
- PyPI package build and publish
- Required repo guardrails and ownership responsibilities

## Who Is Involved

- **Contributors**
  - Open PRs with semantic PR titles.
  - Ensure tests and docs are updated.
- **Maintainers/Reviewers**
  - Review and merge contributor PRs.
  - Review and merge Release Please PRs.
  - Maintain branch protection and required checks.
- **GitHub Actions (automation)**
  - Generates release PRs.
  - Creates tags/releases.
  - Publishes packages to PyPI from release tags.

## Required Guardrails and Prerequisites

These must be enabled for predictable releases:

1. **Branch protection on `main`**
   - Require pull request before merge.
   - Require status checks to pass.
   - Include PR title validation and core CI checks.
   - Change merge strategy to squash merges for clean release semantics/changelogs.
   - Keep the publish workflow's required release checks in sync with branch
     protection. `publish.yml` blocks PyPI/GHCR publish unless `test`,
     `analyzer-speed`, `corpus`, `quality-benchmark`, and `scan` have passed
     for the release commit.

2. **PR title policy enabled**
   - Workflow: `.github/workflows/pr-title.yml`
   - Required format: `<type>(<scope>): <message>`
   - Allowed semantic types:
     - `feat`
     - `fix`
     - `docs`
     - `refactor`
     - `test`
     - `chore`
     - `perf`
     - `style`
     - `ci`
     - `infra`
     - `revert`

3. **Release Please configured**
   - Workflow: `.github/workflows/release-please.yml`
   - Config: `tools/release/release-please-config.json`
   - Manifest: `tools/release/.release-please-manifest.json`

4. **PyPI token configured**
   - Repo secret required: `PYPI_TOKEN`
   - Must be a valid token with publish access for `skylos`.

5. **GitHub Actions permissions**
   - `contents: write`
   - `issues: write`
   - `pull-requests: write`

6. **Preferred release token**
   - Repo secret preferred: `RELEASE_PLEASE_TOKEN`
   - Fallback: `GITHUB_TOKEN`
   - For repos with required PR checks, a dedicated token/App is preferred so release PR checks can report normally.

## Release Baseline (Bootstrap)

Skylos bootstraps Release Please from the existing version history using:

- `tools/release/.release-please-manifest.json`:
  - `"." : "4.2.1"`
- `tools/release/release-please-config.json`:
  - `bootstrap-sha: a498b27b6902b34e469acfddac1068635aae8122`

This prevents retroactive release generation for older history and starts automation from the established baseline.

`CHANGELOG.md` is preserved and continued from this baseline. Release Please appends new versions after the current changelog state instead of regenerating the changelog from scratch.

## End-to-End Release Flow

1. Contributors merge PRs to `main` with semantic titles.
2. On push to `main`, Release Please updates or opens a release PR.
3. Maintainer reviews and merges the Release Please PR.
4. Release Please creates the GitHub tag/release (`vX.Y.Z`).
5. The tag push triggers `.github/workflows/publish.yml`.
6. `publish.yml`:
   - checks out the generated tag,
   - builds wheel + sdist,
   - validates artifacts (`twine check`),
   - publishes to PyPI using `PYPI_TOKEN`.

## Version Bump Rules

- `feat` -> **minor** bump
- `fix` -> **patch** bump
- Breaking change notes (`BREAKING CHANGE` footer) -> **major** bump
- Other allowed types usually do not trigger a version bump unless accompanied by breaking metadata.

## Operational Notes

- Release orchestration and publishing are intentionally split:
  - `release-please.yml` manages release PRs and tags.
  - `publish.yml` publishes from immutable tags.
- `publish.yml` runs on both `push.tags: ["v*"]` and `workflow_dispatch`.
- Publish uses `--skip-existing` to reduce failure risk on re-runs.

## Manual Validation (Optional)

Before merging a release PR, maintainers can validate packaging locally:

```bash
python -m pip install --upgrade pip
python -m pip install "build>=1.2.2" "twine>=6.1.0"
python -m build --sdist --wheel --outdir dist
python -m twine check dist/*
```

## Recovery Playbook

If automated publish fails:

1. Fix the cause (token, package metadata, transient registry error).
2. Re-run failed `publish.yml` job if safe.
3. If the release tag was created but publish did not run, trigger `.github/workflows/publish.yml` manually with `ref=vX.Y.Z` only. Do not publish from a branch ref.
4. Confirm version appears on PyPI and matches the GitHub release tag.
