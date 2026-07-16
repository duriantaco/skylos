# AI Code Verification Coverage

`skylos verify` checks generated or edited source code before an agent hands it
to review. It is deterministic static analysis: Skylos does not execute target
code, invoke package managers or compilers, call an LLM judge, or query a
network service for local/workspace API verification.

This command has a narrower purpose than `skylos defend`:

- `skylos verify`: did the edited code contain a proven AI-code defect, and did
  every applicable deterministic verification check complete?
- `skylos defend`: does an agent implementation contain expected static
  guardrails before deployment?

Neither command currently proves the runtime behavior of a running agent.

## Status and exit codes

Schema-version-2 responses use three statuses:

| Status | Exit | Meaning |
|:---|:---:|:---|
| `pass` | `0` | No verified findings and every applicable expected check completed |
| `fail` | `1` | At least one verified AI-code finding exists |
| `incomplete` | `2` | No finding exists, but one or more required proofs were unsupported, skipped, uncertain, or missing |

Findings take precedence over incomplete coverage. `--no-fail` changes the
process exit code to `0`, but does not change the JSON status.

## Local API verification support

The local/workspace API suite currently has deterministic proof for:

| Language | Check ID | Scope |
|:---|:---|:---|
| Python | `python_local_api_reference` | Repo-local imported references with statically resolvable module surfaces |
| TypeScript / JavaScript | `typescript_local_api_surface` | Local and workspace imports, exports, namespaces, re-exports, and CommonJS surfaces |
| Go | `go_workspace_api_surface` | Exported selectors from local modules, workspaces, and local replacements |
| Java | `java_workspace_api_surface` | Explicitly attributable local types and statically knowable members |

PHP, Rust, Dart, C#, Kotlin, and Shell remain supported by their existing
Skylos static-analysis rules, but deterministic local/workspace API proof is
not implemented for those languages. Their expected checks are emitted as
unsupported and `skylos verify` reports `incomplete` rather than silently
claiming a complete proof.

## Coverage object

When AI verification runs, the response includes an `coverage` object:

```json
{
  "schema_version": 1,
  "state": "incomplete",
  "detected_languages": ["go", "php"],
  "expected_checks": [
    {
      "id": "go_workspace_api_surface",
      "languages": ["go"],
      "applicable_files": 2,
      "capability": "local_workspace_api_surface",
      "support": "supported"
    },
    {
      "id": "php_workspace_api_surface",
      "languages": ["php"],
      "applicable_files": 1,
      "capability": "local_workspace_api_surface",
      "support": "unsupported",
      "reason": "local_api_verification_not_implemented"
    }
  ],
  "missing_checks": [],
  "language_support": [
    {
      "language": "go",
      "capability": "local_workspace_api_surface",
      "status": "supported",
      "check_id": "go_workspace_api_surface"
    },
    {
      "language": "php",
      "capability": "local_workspace_api_surface",
      "status": "unsupported",
      "check_id": "php_workspace_api_surface",
      "reason": "local_api_verification_not_implemented"
    }
  ],
  "completed_checks": ["go_workspace_api_surface"],
  "skipped_checks": [
    {
      "id": "php_workspace_api_surface",
      "reasons": ["unsupported_capability"]
    }
  ],
  "checks": [
    {
      "id": "go_workspace_api_surface",
      "status": "completed",
      "outcome": "pass",
      "references": 1,
      "verified_references": 1,
      "skipped_references": 0,
      "finding_count": 0
    },
    {
      "id": "php_workspace_api_surface",
      "status": "skipped",
      "outcome": "incomplete",
      "references": 0,
      "verified_references": 0,
      "skipped_references": 0,
      "finding_count": 0,
      "reasons": [{"code": "unsupported_capability", "count": 1}]
    }
  ]
}
```

Fields have these meanings:

- `state`: `complete` only when every applicable expected proof completed;
  otherwise `incomplete`.
- `detected_languages`: canonical source-language labels found in the selected
  scan files.
- `expected_checks`: the required proof universe derived from those files,
  including explicit support state.
- `missing_checks`: supported checks that were expected but produced no record.
- `language_support`: one support record per detected language and capability.
- `completed_checks`: check IDs whose detector completed, including detectors
  that completed with verified findings.
- `skipped_checks`: skipped check IDs and deterministic reason codes.
- `checks`: reconciled check records with reference, finding, and skip counts.

Malformed or duplicate detector records are reconciled conservatively. They
add `malformed_check_record` or `duplicate_check_record` reasons and keep
coverage incomplete instead of allowing the last record to silently win.

Inline `skylos: ignore` comments are explicit waivers. A waived finding is
removed from the failure count, but its check records `suppressed_findings` and
a `finding_suppressed` reason so the resulting pass is not silent. Project-level
rule disables remain incomplete because the required detector did not run.

The TypeScript/JavaScript languages share one check record when both are
present. A repository with no applicable source files has no expected checks
and remains complete.

## Conservative proof rules

`SKY-L012` remains the common hallucinated-reference rule across languages.
Findings add `metadata.language` and `metadata.reference_kind` rather than
creating language-specific rule IDs.

Skylos reports a finding only when the relevant local API surface is complete.
Parser failures, wildcard ownership, build-conditional Go surfaces, ambiguous
packages or Java types, generated/inherited Java members, shadowed qualifiers,
and unsupported instance-type inference produce incomplete coverage instead of
a critical finding or a false pass.

Java proof is also bounded by source set, nearest build/source module, member
kind, and visibility. Test fixtures or unrelated modules cannot prove a
production reference; nested-type and protected cross-package cases remain
incomplete when inheritance or ownership cannot be established statically.
File-scoped Go and Java scans carry `exclude_folders` into workspace discovery;
excluded workspace paths therefore cannot supply evidence. Python imports that
resolve to local modules outside the selected subtree are reported as
`local_import_outside_scan` incompleteness rather than being trusted or treated
as external.
