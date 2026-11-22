# Incremental UML and code-review report

From the repository root, run in the environment containing Skylos's dependencies:

```bash
python scripts/build_uml.py
open UML/index.html
```

The default output is the ignored `UML/` directory. **What changed** opens first and explains changes found by Skylos. **UML map** has the interactive diagrams, search, and source reader. A regular local run builds the full map and compares working-tree edits with `HEAD`.

## What gets reused

- With no input changes, the runner verifies the saved outputs and stops. It does not parse sources, regenerate explanations, or recompress the UI.
- Changed source files are content-hashed and reparsed. Unchanged native parser records and file relationship facts are reused.
- Function facts use body and import-context hashes. Editing one function reuses its unchanged siblings' facts. Source locations are rebased after line-only changes.
- Test-link lookups are reused while the code relationships they depend on are unchanged. Changed links refresh the affected lookups.
- Added and removed files update the map. Caller context is refreshed using both the previous and current graphs. Authored explanations are marked for refresh when their body or linked context changes.
- Changing only UI assets rerenders the report from cached analysis.

The runner still checks the file list and fingerprints, and rebuilds the combined graph/report when needed. A first build, missing/invalid cache, changed analysis engine, or `--force` can require a full pass.

```bash
python scripts/build_uml.py --force
```

`UML/update-stats.json` records analyzed/reused counts and elapsed time. `UML/.cache/` contains JSON/gzip data only. Cache writes are atomic, and concurrent invocations share a build lock.

## CI

The **Skylos Advisory Scan** workflow builds the UML report on PRs and on pushes with a comparison base. It uses the same base as the Skylos scan. A manual run compares against the parent commit. Once the builder is on the base branch, PR runs use that branch's builder and viewer assets to render the proposed changes.

The Actions run summary links to **Download the UML report**. Unzip it and open `index.html` in a browser. The report is self-contained and the download is available for seven days. A finding that blocks the scan can still have a UML report.

The CI map builds from the changed files even on a fresh runner. Skylos's change map can examine other files to identify callers. **What changed** also lists file changes such as deletions, renames, and documentation edits. A comparison without a base shows an empty diff. **Update details** lists the analysis counts.

```bash
python scripts/build_uml.py --base origin/main --ci --output UML/ci-report
```

## Descriptions and privacy

Core descriptions live in `assets/default-descriptions.json`. Local runs prefer `UML/curation.json` when present. CI uses the shared descriptions, so personal notes are not added to its report or cache.

The offline HTML includes source for the mapped files. The Actions artifact contains `index.html` and `update-stats.json`.

Descriptions and static test links assist reading; they do not establish correctness or runtime coverage. See `CODE_REVIEW.md` in the generated report.
