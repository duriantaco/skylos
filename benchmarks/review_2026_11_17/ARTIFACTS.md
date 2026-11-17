# Review evidence and archived runs

The PR retains canonical benchmark cases and fixtures, the three immutable
five-repository source-label files, their independent review receipts, source
adjudications, the corpus/gap inventory and one compact
[result index](ground_truth_audit/RESULTS.json). The
[confirmed results](ground_truth_audit/confirmed_results.md) explain the scope
and competitor limitations. Generated scan dumps, repeated before/after arms,
duplicate manifests, draft copies and superseded reports are archived.

## Verified archive

The complete pre-cleanup evidence is preserved from commit
`ca17bb2e12248bc02893ead2dc957f19cb25baff`:

- Location: `~/Desktop/skylos-benchmark-2026-11-14/pr1251-cleanup-ca17bb2e/`
- File: `tracked-evidence.tar.gz` (906,789 bytes; 226 original files)
- SHA-256: `d8cd23c931eb28906b65791368afe20914df98357c8bd5d8ac69409a3bb24f18`
- `INDEX.json` records each original path, Git blob, byte count and SHA-256.
- `SHA256SUMS` verifies the archive before extraction.

That archive contains the whole historical manifest/review/draft chains,
including the copied `benchmarks/dead_code/reviewed_manifest_2026_11_17.json`.
The canonical dead-code manifest already contains the reviewed corrections.
Earlier full raw scans and target checkouts remain under
`~/Desktop/skylos-benchmark-2026-11-14/review_2026_11_17/`.

The original tracked artifacts also remain recoverable from the source commit:

```bash
mkdir -p /tmp/skylos-review-evidence
git archive ca17bb2e12248bc02893ead2dc957f19cb25baff \
  benchmarks/review_2026_11_17 \
  benchmarks/dead_code/reviewed_manifest_2026_11_17.json \
  | tar -x -C /tmp/skylos-review-evidence
```

The cleanup reduces the PR's combined file diff. Earlier commits still contain
the original evidence; branch history has not been rewritten.

## Reproduction inputs

The five-repository development runner reads the retained `SOURCE_LABELS_*`
files. It needs the pinned external checkouts at the paths stored in those
labels, a trusted Go engine and the recorded Go environment. See the
[label provenance](ground_truth_audit/GROUND_TRUTH_PROVENANCE.json) and
[measurement index](ground_truth_audit/RESULTS.json). No label bytes changed.

The older `run_holdouts.py` and `run_reviewed_ground_truth.py` harnesses remain
for regression tests. Their historical datasets are archived as complete
chains. To replay them, extract the archive outside this checkout and pass
`--manifest` and `--scope-review`, or `--freeze`, pointing into that extracted
tree. Use each runner's `--help` for the required checkout/analyzer/output
arguments. Do not combine an old seal with rewritten or partial draft files.

The small PHP, Node preload, exact-location and literal-null regression
fixtures remain versioned. Current default suites use the canonical manifests
under `benchmarks/dead_code`, `benchmarks/security` and `corpus`.

The five new repositories became development evidence once their results were
used for fixes. After-fix scans are not a second blind study. Unknown,
unsupported and incomplete facts remain unscored; real-repository security
recall remains unmeasured.
