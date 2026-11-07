# Offline secrets shape contracts

This suite checks native filesystem discovery, candidate detection and provider
labels against 20 fixed synthetic cases (13 positives and seven safe controls).
Expected answers were reviewed before running either scanner. Fixtures are
constructed deterministically at runtime; no issued credentials are committed,
verified or sent to provider services. This is not live-secret precision or an
independent deployment benchmark.

Run the known-supported Skylos regression subset:

```bash
python scripts/secrets_benchmark.py --track regression --output .skylos/evals/secrets/regression
```

Run the entire capability suite against an explicitly selected source checkout:

```bash
python scripts/secrets_benchmark.py --source /absolute/path/to/skylos-source --output .skylos/evals/secrets/candidate
```

Run the same filesystem inputs with an independently installed, checksum-verified
TruffleHog 3.99.8 binary:

```bash
python scripts/secrets_benchmark.py --scanner trufflehog --trufflehog /absolute/path/to/trufflehog --output .skylos/evals/secrets/trufflehog
```

The adapter always uses default built-in detectors, `--no-verification`,
`--no-update`, `--fail-on-scan-errors` and
`--results=verified,unverified,unknown`. It records the executable
version and SHA256. It does not install or download tools. A non-live synthetic
candidate may be reported as unverified; this is not evidence that it works.

The fixture generator, manifest and grader are independent from the analyzer
selected by `--source`. A fresh Python worker imports that analyzer and verifies
its source location. Each scanner receives the same input bytes. Native scans
use the normal analyzer entry point, so file discovery and test-directory gaps
remain visible. A benign source file gives every fixture a native completeness
anchor; it is never treated as proof that the candidate-bearing file was read.
Capability cases can intentionally fail; they are not all release gates.

Positive detection credit requires the reviewed file and source line. Presence
and provider classification are separate. A fine-grained GitHub-shaped
value found only by the generic detector counts as a detected candidate and a
provider-label gap, rather than a recall miss. Repeated findings, two rules for
the same candidate, and unique case detections are reported separately. Output
outside the expected fixture location does not receive detection credit.

Every run stores expected case records, per-file input hashes, source hashes,
tool/runtime identities, raw scanner JSON, stdout/stderr, elapsed time and
normalized outcomes under the output directory. Existing output is never
overwritten. Scanner errors, missing reports, incomplete analysis, modified
inputs or changed source fail honestly. Raw TruffleHog output contains the
generated synthetic material; keep `.skylos/` outputs local.

The suite has no Git-history, archive or external-service scan. Those are separate
scope comparisons. Its small fixed counts must not be used as a universal
precision/recall ranking. Provider discovery support, synthetic detection,
classification, quiet safe controls and execution failures have different
denominators.
