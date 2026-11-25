# Registered SQLite worker SQL replay

SKY-D211 now checks source-owned registry dispatch into a queued SQLite
worker. The proof connects the registered callback, argument-preserving
decorator, native queue, job callback, and still-open SQLite cursor. It
tracks caller-supplied row data only in the statement argument. A successful
proof produces a HIGH review finding. It leaves the application's external
input origin unresolved.

## PyLoad

The historical and fixed source anchors are the same line in each revision.
The historical query places row data in SQL text. The fixed query builds its
placeholder string from the number of rows and passes the values separately.

| Source inventory | Upstream baseline | Candidate |
|---|---|---|
| Original 12 files per revision | 0 TP, 1 FN, 0 FP, 1 TN | 0 TP, 1 FN, 0 FP, 1 TN |
| Original files plus 7 same-commit context files per revision | 0 TP, 1 FN, 0 FP, 1 TN | 1 TP, 0 FN, 0 FP, 1 TN |

The extra context includes the package's method-provider re-exports and
source for the registered providers. Source hashes and Git blob IDs were
checked for both revisions. The target windows stayed fixed, and the two
inventories were scored separately. The 16 Skylos scans completed without
analysis errors. Both the workspace and the candidate prepared on upstream
main show the same gain on the enriched pair.
[Context manifest](evidence/pyload-context-labels.json) ·
[Paired Skylos results](evidence/pyload-results.json)

On the enriched PyLoad pair, Bandit B608 1.9.4 reports both revisions
for 1 TP and 1 FP. Semgrep Core 1.185.0's formatted-query rule reports
the historical call and stays quiet on the fixed call for 1 TP and
1 TN. Both profiles completed without errors.
[Peer results](evidence/enriched-peers.json)

## Independent first-use pair

An independent reviewer froze the Rucio historical and fixed revisions
before any scan. Both Skylos snapshots gave 0 TP, 1 FN, 0 FP and 1 TN.
All four scans read ten source files each and completed with zero analysis
errors. The fixed revision stayed quiet. The historical query uses a streamed
generator and a PostgreSQL plugin, an adjacent case with a different driver
and dispatch mechanism. The diagnostic Bandit and Semgrep profiles completed
with zero results. Their covered mechanisms exclude the scored Psycopg 3
composition path, so those diagnostics are outside the scored peer totals.
[Blind labels](evidence/blind-labels.json) ·
[Blind results](evidence/blind-results.json)

## Regression replay

The same 87 frozen source revisions were replayed on the workspace and
upstream baselines. Each comparison has the same verdicts, completion
statuses and normalized danger findings on both sides.

| Comparison | Baseline TP / FN / FP / TN | Candidate TP / FN / FP / TN |
|---|---:|---:|
| Workspace snapshot containing earlier local security work | 25 / 18 / 4 / 57 | 25 / 18 / 4 / 57 |
| Upstream main snapshot and scoped worker patch | 7 / 35 / 6 / 54 | 7 / 35 / 6 / 54 |

The upstream comparison has two incomplete Lodash revisions because the
scanner skips the selected generated file. Both publish arms have the same
scope exclusions. The workspace replay also preserves the prior enriched
LangGraph detection and its quiet fixed control, the prior SQL pair scores,
and all five true positives in the independent Python SQL fixtures.

Both candidates passed all 277 standard and 9 adversarial security cases.
The publication snapshot passed 4,447 selected security and regression tests.
[Wide replay delta](evidence/wide-worker-delta.json) ·
[Validation receipt](evidence/validation.json)

## Reproduce

Stage only the files recorded in the manifests from the specified upstream
commits. Verify their Git blob IDs and SHA-256 values. Preserve the sparse
and enriched inventories in separate directories. Run the installed Skylos
CLI from each snapshot with the snapshot on `PYTHONPATH` and
`SKYLOS_CUSTOM_RULES=[]`, using a fresh output path outside the source tree.

```sh
skylos /path/to/staged-revision --danger --no-upload --no-grep-verify \
  --format json --output /path/to/raw-report.json
```

Match findings by rule family, repository-relative file, and frozen line
window. Count a quiet control only after verifying a complete scan. The
receipts include raw report and engine hashes. The scans parse source and
leave the applications idle.
