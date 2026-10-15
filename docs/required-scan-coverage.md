# Required scan coverage

Findings, operational failures, and coverage limits are separate outcomes.
Finding thresholds determine whether known issues fail a gate. An unavailable
scanner makes analysis incomplete and exits `2`. A source file that does not
parse, or files of a language whose engine is missing, are coverage gaps: the
gate is evaluated on the code that was analysed and the gap is reported (see
[Exit Codes And Incomplete Analysis](./cli-output.md#exit-codes-and-incomplete-analysis)).
A policy requiring coverage can reject a completed scan whose supported
inventory does not meet that requirement, exiting `1`.

## Requiring complete source coverage

To keep a gate from passing while any source file was not analysed:

```toml
[tool.skylos.gate.coverage]
require_complete = true
```

With it, `skylos . --gate` and `skylos cicd gate` exit `2` (`Quality Gate:
INCOMPLETE`) on any coverage gap, as `--strict` does, while keeping your
configured limits. Without it, the gate passes or fails on the analysed code
and prints the gap as a warning.

## Dependency coverage policy

SCA remains optional by default. Its JSON receipt is retained under
`analysis_summary.sca_coverage`. A passing scan does not imply every package
ecosystem or unresolved dependency version was checked.

To require a supported dependency inventory and resolved dependency versions:

```toml
[tool.skylos.gate.coverage]
required = ["sca"]
require_resolved_versions = true
```

Run `skylos . --sca --gate`. Gate policy is evaluated in strict mode too.
Synced Cloud gate policy takes precedence over repository TOML: a checked-out
pull request cannot remove a synced coverage requirement.

`required = ["sca", "custom_rules"]` also requires configured custom rules to
be checked. It enables quality analysis even when another scan category was
explicitly selected. Their receipt is `analysis_summary.custom_rules_coverage`.
Current YAML custom rules target Python; executable Python rule definitions are
unsupported and are never executed. Active rules without Python targets
report `unsupported`; loaded rules without requested quality analysis report
`not_scanned`. Trusted CI jobs can supply the rule list through the existing
`SKYLOS_CUSTOM_RULES` environment variable without exposing a Cloud credential
to the scanner. Malformed environment rules report `unavailable`.
Missing or disconnected rule coverage rejects the gate with exit `1`;
an unavailable required rule service produces an analysis error and exit `2`.
Unknown required category names reject the gate instead of silently passing.

| Receipt | Default gate | Required SCA | Required resolved versions |
|:---|:---|:---|:---|
| No SCA receipt | Other gate checks apply | Exit `1` | Exit `1` |
| `no_supported_manifests` | Other gate checks apply | Exit `1` | Exit `1` |
| `complete`, including a supported empty manifest | Other gate checks apply | Other gate checks apply | Other gate checks apply |
| `complete_with_unresolved_versions` | Other gate checks apply | Other gate checks apply | Exit `1` |
| Unsupported lockfile inventory | Other gate checks apply | Exit `1` | Exit `1` |
| `incomplete`, `unavailable`, or `unknown` | Exit `2` | Exit `2` | Exit `2` |

`require_resolved_versions = true` also enables required SCA coverage. A required
SCA receipt must identify at least one supported manifest, record valid dependency
and query counts, and confirm that every inventoried dependency was queried. A
supported empty manifest passes with both counts zero; it needs no network query.
Unsupported manifest or lockfile inventory rejects required coverage. Resolved
version policy additionally requires verified zero unresolved counts for both
manifest and lockfile dependencies. A `complete` status alone cannot satisfy these
checks. This requires the inventory the SCA parser supports; it does not add
support for Cargo, Maven, or other unimplemented dependency formats. Coverage
warnings state how many dependency versions could not be queried.

## GitHub Actions input failures

When security analysis is requested, malformed YAML, non-mapping YAML,
recursive/resource-limited YAML, refused symlinks, invalid UTF-8, and unreadable
or oversized Actions files produce structured `analysis_errors`:

```json
{
  "rule_id": "SKY-ANALYSIS-INCOMPLETE",
  "kind": "config_parse_error",
  "component": "github_actions",
  "file": ".github/workflows/ci.yml",
  "line": 1,
  "severity": "HIGH",
  "message": "GitHub Actions analysis incomplete: invalid YAML or YAML resource limit exceeded"
}
```

The parser does not include source excerpts in these messages. `line: 1`
identifies the file; it does not claim an exact syntax-error location.
`config_read_error` and `config_parser_unavailable` identify reading and parser
availability failures. The CLI exits `2`, including with an advisory gate or
`--force`. A file outside a selected diff does not make that diff incomplete.

## CLI-generated Cloud workflow

The `skylos sync setup` template and tokenless workflow example scan PRs with SCA and
an explicit strict gate. Their immutable PR base SHA and `--diff-mode impact`
scope enforcement to newly introduced findings, including indirect dead-code
changes outside edited definition lines. Unchanged legacy findings do not
fail that PR gate.

These PR jobs have read-only repository permissions and do not pull Cloud policy,
upload scans, or request OIDC tokens. Default-branch upload jobs pull policy,
include SCA, and use `--gate` to apply the configured Cloud thresholds. Mark the
PR check as required in branch protection to enforce it before merge.

## JSON upload outcomes

With `--upload --format json` or `json-ci`, the CLI prints one JSON document
after the upload attempt. Its `upload` object carries the confirmed scan ID,
dashboard URL, and available Cloud gate decision and reasons. Unknown transport
fields are omitted. The printed scan remains independent of upload preparation
or display filtering.

```json
{
  "upload": {
    "status": "uploaded",
    "scan_id": "saved-scan",
    "url": "https://skylos.dev/dashboard/scans/saved-scan",
    "quality_gate": {"passed": false, "reasons": ["required SCA missing"]}
  }
}
```

An upload failure preserves the local report with `upload.status: "failed"`
and exits `1`. Incomplete analysis (exit `2`) does not upload: it reports
`{"status": "skipped", "reason": "analysis_incomplete"}` and exits `2`. A scan
with only coverage gaps uploads with a partial scan-coverage receipt.
An unconfirmed managed GitLab comment delivery retains its saved scan ID and
separate `upload.delivery` outcome, exiting `2`. Completed scans upload their
findings even when a strict gate rejects them; enforcing the gate happens after
the outcome has been rendered. Uploads do not require credits.
