# Compare Skylos With Your Current Scanner

`skylos compare` runs a local, advisory comparison without replacing an
existing quality gate. Its default scan does not upload source code or make
network queries. It accepts SARIF, SonarQube issue-search JSON, or a normalized
`findings` array.

Use it to answer three questions on the same commit:

1. Which incumbent and Skylos findings occur at the same source location?
2. Which findings are unique to either scanner?
3. Which incumbent findings sit inside symbols Skylos classifies as likely or
   validated dead code?

## Quick Start

Run Skylos and compare the result with an incumbent report in one command:

```bash
skylos compare . --against incumbent.sarif
```

To preserve the comparison as a project-bound Cloud receipt without changing
the incumbent gate:

```bash
skylos compare . --against incumbent.sarif --upload
```

Cloud upload is always explicit. It uses the normal Skylos project API key or
GitHub OIDC identity, sends a bounded comparison receipt, and leaves the local
comparison advisory. The Cloud receipt keeps aggregate evidence and
repository-relative review metadata; scanner messages, fingerprints, local
paths, and source snippets remain only in the local report.
A serialized Cloud upload envelope is limited to 4,000,000 bytes (about 4 MB).
If a comparison is larger, the complete JSON receipt remains available locally
and Skylos asks you to upload a smaller comparison.
Scanner Proof receipts are opt-in audit evidence. Cloud applies hard count and
byte ceilings and retains them until their project or workspace is deleted;
deleting either also deletes its comparison receipts.
A Cloud receipt also requires a network Git remote identity. Skylos refuses
local-path and `file://` remotes before serialization so workstation paths
cannot cross the upload boundary; the complete local comparison remains
available.

Or reuse an existing Skylos JSON result so the comparison is repeatable:

```bash
skylos . -a --format json -o skylos.json
skylos compare --against sonar-issues.json --skylos-results skylos.json
```

Write the full machine-readable report for CI or later analysis:

```bash
skylos compare \
  --against codeql.sarif \
  --skylos-results skylos.json \
  --format json \
  -o scanner-value-report.json
```

For the strongest clean-worktree provenance, keep JSON report inputs outside
the scanned repository (CI temporary/artifact storage is ideal). An untracked
`.sarif` input is treated as a non-source artifact; other in-tree report files
keep the comparison provisional because analyzer families may consume their
extension.

The default scan does not upload or query anything. It runs dead-code,
source-security/reliability, quality, and offline AI checks. Repository-wide
secret-file traversal and dependency SCA are excluded from this bounded shadow
profile; an incumbent secret category is therefore shown as uncovered rather
than compared. Opt into bounded dependency checks when comparing dependency
scanners:

```bash
skylos compare . --against snyk.sarif --sca
```

`--sca` may query OSV with package and version metadata. It queries only exact
direct pins; ranges such as `>=2.0` and `^1.2.3` are recorded as unresolved
rather than treated as installed versions. It does not provide full
lockfile/transitive resolution, so
the report keeps `DEPENDENCY` category coverage incomplete and does not claim
Snyk/Trivy-equivalent completeness. Its receipt records operation status,
supported manifests, unsupported lockfiles, unresolved versions, bounded
inventory/query counts, and scope. Project-owned OSV cache data is never
read or written, so it cannot skip a query, establish a clean result, or dirty
the scanned repository.
Dependency hallucination registry checks remain disabled in comparison mode,
so AI-defect coverage is explicitly partial rather than silently presented as
a complete category.

## Keep The Existing Dashboard

The evaluation does not need to introduce a second developer dashboard.
SonarQube accepts third-party SARIF reports, so a Sonar customer can run:

```bash
skylos . -a --format sarif -o .skylos/skylos.sarif
sonar-scanner -Dsonar.sarifReportPaths=.skylos/skylos.sarif
```

Keep Skylos as an advisory external analyzer during the evaluation. Sonar's
SARIF import has its own category and issue-management limitations, so native
Skylos policy and triage should remain authoritative if the check is later
promoted to blocking. See Sonar's
[SARIF import documentation](https://docs.sonarsource.com/sonarqube-cloud/enriching/importing-issues-from-sarif-reports).

## Supported Incumbent Reports

- SARIF 2.1-style reports. Skylos supports direct or indexed rules and
  artifacts, source regions, rule/result severity, fingerprints, invocation
  success, and version-control provenance. Producer-specific extensions may
  remain unnormalized and should be checked during a pilot.
- The JSON response from SonarQube's `api/issues/search` endpoint. Export every
  page for a complete comparison.
- A JSON object with a `findings` array containing common fields such as
  `rule_id`, `file_path`, `line_number`, `severity`, and `category`. Set
  top-level `complete: true` only for a full export, and include `revision`
  when available. To verify repository scope, also include
  `scope: {"complete_repository": true, "repository_identity": "..."}`.

Accepted SARIF suppressions, passing/not-applicable results, absent baseline
results, and closed/resolved/accepted Sonar issues are excluded from the active
population. Their counts and exclusion reasons remain in the report. A failed
SARIF invocation or partial Sonar page makes the comparison unusable for value
claims.

Compare reports generated for the same commit and source tree. Path and line
drift otherwise reduce useful overlap.

Python currently has the richest symbol-liveness evidence. Other supported
languages are accepted, but may produce more `reachability unknown` results
when precise symbol spans are unavailable.

## Reading The Report

`same-location overlap` counts findings for which both tools reported the same
unambiguous file and line. It is corroboration, not proof that the rules
describe the same root cause. Multiple rules can share one location; a
basename-only path match is too weak and remains unknown.

`raw Skylos-only` spans every enabled Skylos category. It must not be presented
as incumbent misses. Use `skylos_only_in_observed_comparable_categories`, the
per-category counts, and the scan-scope metadata for a fair review.

`incumbent findings in likely-dead code` means the finding falls inside a
symbol whose Skylos liveness evidence supports `likely_dead` or
`validated_dead`. These findings are review or deletion candidates. Skylos
does not automatically call them false positives or suppress them.

The commercial-benefit count is narrower than reachability context. Only
source security, reliability, quality, and AI-defect findings can become
deletion candidates. Secrets still require rotation and history review;
dependency findings still require dependency remediation. Neither category is
counted as deletion savings merely because it appears in unused code.

`reachability unknown` means Skylos could not conservatively associate the
finding with a live or reportable dead symbol. Unknown is never treated as
safe.

The report carries normalized scanner versions, canonical input digests,
revision IDs, Skylos file/language/category scope, and excluded findings. A
revision mismatch invalidates the comparison. Matching revision IDs on a dirty
worktree remain provisional. If a report lacks provenance, use
`--external-revision` or `--skylos-revision`; these assertions fill missing
metadata and cannot overwrite conflicting report provenance.

AI verification and SCA also carry category-level completion receipts. An
incomplete category is removed from comparable and benefit counts while valid
security/dead-code context remains usable. Top-level completeness is scoped to
the categories actually observed in the incumbent export. The separate
`coverage.all_requested_categories_complete` field shows whether Skylos's whole
requested profile completed.
An incumbent category absent from `skylos_scanned_categories` is explicitly
listed under `uncovered_external_categories` and cannot contribute to benefit
or comparable counts.
`completeness_reasons` lists every material limitation, so an incomplete
category cannot hide unknown export completeness or unverified revisions.

Scope is conservative too. Repository-root local scans carry a scope receipt;
file/subdirectory scans remain provisional. Saved reports without scope
metadata remain usable for inspection but cannot reach
`inputs_verified_same_revision`. A full-export attestation, full-repository
Skylos scope, matching normalized repository identities, and matching revision
are all required for that state. An explicit repository-identity mismatch
invalidates the comparison.

The JSON report retains the normalized external findings, per-finding
reachability context, overlapping Skylos rule IDs, Skylos-only findings,
analysis errors, and explicit limitations.

SARIF and unpaged Sonar JSON do not prove that every incumbent finding was
exported. In that case the report uses
`completeness_state: external_completeness_unknown` and limits its benefit
claim to the imported-findings scope shown in `benefit.claim_scope`. This is
not a failed Skylos analysis, but it
must not be presented as a complete incumbent export. A report is
`inputs_verified_same_revision` only when both report inputs carry recognizable
completion metadata and their revisions match. This verifies the comparison
inputs, not exhaustive detector coverage; `coverage_attested` remains `false`
because some best-effort subchecks do not yet emit coverage receipts.
If duplicate suffix paths make a monorepo location ambiguous, Skylos reports
reachability as unknown instead of guessing.

## A Safe Evaluation Workflow

1. Keep the incumbent required check unchanged.
2. Run Skylos in advisory mode on representative repositories.
3. Compare the same commits for two to four weeks.
4. Review a sample of unique and dead-code-associated findings.
5. Blind-review samples, then measure developer-visible alerts, review time,
   scan completion, and customer-confirmed high-impact findings. Do not turn
   raw unique counts into ROI.
6. Promote Skylos to a required gate only after the evidence supports it.

The command exits with status `2` when the Skylos result is unrecognized,
contains analysis errors, reports an incomplete language engine, or when the
incumbent export is known to be partial. Unknown SARIF export completeness is
advisory rather than an error, but limits all claims to the imported findings.
An incomplete comparison must not be interpreted as a clean result.
