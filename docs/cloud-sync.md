# Cloud configuration and suppression sync

`skylos sync pull` fetches the linked project's configuration and reviewed
findings. The repository needs a git remote (`git remote add origin <url>`):
reviewed findings are tied to its remote URL, so without one the pull stops
before contacting Skylos Cloud. It validates both responses, their project
identities, and supported suppression schema before activating either
repository file.

```bash
skylos sync pull
skylos sync pull --format json
skylos sync pull --dry-run --format json
```

The pulled `gate` section replaces the repository's `[tool.skylos.gate]`, and
`skylos . --gate` checks it the way Skylos Cloud does: the mode (`zero-new`,
`category`, `severity` or `both`) with its `by_category` and `by_severity`
limits, any critical security issue, and the `block_secrets` and
`block_ai_defect_severities` switches. Any secret still fails locally whatever
the Cloud limit. The verdict line prints the Cloud limits. Skylos Cloud counts
only new issues, so check a branch with `skylos . -a --gate --diff origin/main`
(or `--baseline`); a full scan prints a line saying so. The pulled file applies
to `--diff` gates while it is not committed; a copy committed only on the
branch is branch content and does not. A Cloud gate that is turned off leaves the
built-in limits, and an unknown mode or unusable limit reads as zero new
issues, so a damaged file never loosens the gate.

`--dry-run` authenticates and validates the responses without creating or
modifying repository files or the private trusted-suppression cache. Its JSON
receipt has `status: "validated"`, `dry_run: true`, the destination file paths,
the suppression count, and `trusted_suppressions: "unchanged"`. A regular pull
reports `status: "synced"` and `trusted_suppressions: "refreshed"`. JSON mode
emits one document without progress text. Unknown arguments are rejected with
exit code 2 before authentication or writes.

A failed pull exits with code 1 and a JSON `status: "failed"` receipt when
requested. An authenticated non-dry-run attempt invalidates previously trusted
suppression state, including when the service is unavailable. This conservative
invalidation prevents stale reviewed findings from continuing to hide findings.
Dry runs preserve existing trust even when validation fails.

The writer refuses a symlinked `.skylos` directory or destination file. Files
are staged before activation. An exception while activating the second file or
storing trusted state restores the previous repository file contents. Activation
also rolls back if the files no longer match the authenticated bytes. Errors
that prevent restoration are reported explicitly. On platforms supporting
directory descriptors, reads and writes use validated filenames beneath held
no-follow directory descriptors. Windows uses native handle-relative opens,
renames and deletes. A platform without either capability refuses the pull;
checking paths before a write is insufficient to prevent directory-swap races.

This is rollback for caught failures, not a multi-file transaction across a
process crash or power loss. A crash between the two file replacements can
leave a mixed generation. The trusted cache remains invalidated until its
authenticated refresh succeeds. Immutable generation directories and a shared
activation pointer would be needed for crash-atomic reader behavior.

Custom-rule loading also reports coverage: `load_custom_rules()` returns
`complete`, `not_connected`, or `unavailable`, with the rules and an optional
failure reason. An empty successfully loaded ruleset is distinct from a failed
request. The legacy `get_custom_rules()` list-returning API remains available.
