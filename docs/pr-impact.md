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

PR summaries name introduced unused symbols that have no inline comment,
including findings past the inline-comment limit or whose inline posting failed.
Legacy dead-code comments without symbol-specific keys do not establish that
another same-line symbol was already shown. They may be repeated once as keyed
comments; subsequent pushes match those keys precisely.

The base snapshot uses raw Git blobs in a temporary directory. It does not
check out files, apply Git filters, install packages or run target code. Missing
or invalid head or base analysis returns incomplete analysis (exit 2), rather than
claiming every head finding is newly introduced. Snapshots are bounded at
20,000 tracked entries and 128 MiB total. Every tracked regular file is
retained, including templates with arbitrary names, documentation and project
metadata that affect static liveness, except a file over 2 MiB that is not
analyzed source (images, archives, model weights, data): it defines nothing and
is left out. Analyzed source is kept at any size. A symlink is resolved
through the base tree's own links, one path component at a time as the
operating system does (so `s/..` is the parent of where `s` points), without
reading anything on disk. When it resolves inside the repository it is
recreated as the same link. One that leaves the repository, reaches its root
or `.git`, loops, or goes through a path the tree does not hold is left out,
and so is one whose path a case-insensitive file system could read another
way (a spelling that differs from a tree path only by case or Unicode form,
or any non-ASCII component). A submodule the checkout did not initialize is
left out (it is an empty folder in the head scan too); an initialized
submodule produces an
incomplete receipt. Leaving an entry out only removes references from the
baseline, so it can hide a newly unused finding but never invent one, and a
finding located in a left-out path is never marked introduced. The receipt
counts left-out entries by reason under `omitted`. Exceeding a bound produces
an incomplete receipt.
The comparison adds a second static scan; no latency improvement is claimed.
An explicit `--config-file` also applies to baseline file processing. Scalar
and multiple-path scans preserve their respective scope in the baseline.

`--diff` alone retains changed-line reporting. Impact mode requires `--diff`
and cannot be combined with the partial-file `--diff-base` option. Impact scans,
including scans without `--gate`, read policy from the immutable base revision
for both head and baseline. An explicit operator config file remains supported.
This option expands dead-code reporting; it does not prove runtime reachability
or expand all security rules into an interprocedural PR impact engine.
