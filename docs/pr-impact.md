# PR impact reporting

Removing a caller can make a function unused even when its definition did not
change. Report this dependency impact before merge:

```bash
skylos . --diff origin/main --diff-mode impact --gate --strict --format json-ci
```

The CLI performs a full static head scan and a static scan of the merge-base
source. Newly unused findings include `change_status: "introduced"` and
`report_scope: "dependency_impact"`; existing unused findings outside changed
lines are omitted. Identity includes the repository-relative file, qualified
symbol name and category, so unrelated line shifts do not create new findings.
The JSON receipt is `analysis_summary.pr_impact`.

The base snapshot uses raw Git blobs in a temporary directory. It does not
check out files, apply Git filters, install packages or run target code. Missing
or invalid head or base analysis returns incomplete analysis (exit 2), rather than
claiming every head finding is newly introduced. Snapshots are bounded at
20,000 tracked regular files, 128 MiB total and 2 MiB per file. All tracked
regular files are retained, including templates with arbitrary names,
documentation and project metadata that affect static liveness. Exceeding any
bound, including a large binary asset, produces an incomplete receipt.
Tracked symlinks and submodules currently produce an incomplete receipt.
The comparison adds a second static scan; no latency improvement is claimed.
An explicit `--config-file` also applies to baseline file processing. Scalar
and multiple-path scans preserve their respective scope in the baseline.

`--diff` alone retains changed-line reporting. Impact mode requires `--diff`
and cannot be combined with the partial-file `--diff-base` option. Impact scans,
including scans without `--gate`, read policy from the immutable base revision
for both head and baseline. An explicit operator config file remains supported.
This option expands dead-code reporting; it does not prove runtime reachability
or expand all security rules into an interprocedural PR impact engine.
