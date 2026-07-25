# Deep Audit Logic Benchmark

This benchmark exercises the repository-aware `LogicInvestigator`, not the
fast agent-review lane or a static logic heuristic. Fixture source is treated
as untrusted evidence and is never executed by the harness.

The checked-in cases cover cross-tenant refunds, middleware ordering, webhook
signature ordering, tenant-scoped cache keys, concurrent payment replay, and
claim-before-side-effect partial failure. Paired cases keep their entry points
identical and place alternative implementations under `archive/` or `legacy/`.
A correct result has to follow the reachable import. Decoys may be inspected,
but unreachable alternatives cannot support finding, mitigation, or clean
evidence.

Every case has one ground-truth label:

- `vulnerable`: a positive case that must produce a finding.
- `safe`: a negative case with reachable protection evidence.
- `lookalike`: a negative case containing a deliberately suspicious decoy.

Schema-v1 manifests without labels remain supported: a positive finding-count
contract is inferred as `vulnerable`, otherwise the case is inferred as
`safe`.

Stable semantic expectations are checked into `expected.json`. Model prose,
hashes, timing, and token counts are intentionally not golden-filed. The result
includes TP/FP/FN/TN, precision, recall, F1, aggregate model usage, and
failure-oriented counters. A vulnerable case earns true-positive credit only
when every emitted finding matches its allowed rule, category contract, symbol,
primary file, evidence files, and decisive source-line anchors. A case may use
`required_any_categories` when one concrete flaw has multiple defensible
taxonomy labels, but all other target fields must match that same finding.
Unmatched sibling findings fail the case and count as false positives instead
of being hidden behind one correct result. Clean cases likewise require exact
protection-line anchors. `false_clean_count` means a vulnerable case completed
with zero findings. `incomplete_count` means the investigator did not return
`complete`. An incomplete vulnerable case is conservatively a false negative
even if it emitted a partial finding. An incomplete negative case with a
finding is a false positive; one with no finding is an `abstention` and does not
earn true-negative credit. `classified_count` is the confusion-matrix total,
so precision and recall cannot improve merely by leaving cases incomplete.

Investigator protocol v3 gives every citation a typed purpose. Shared-state
claims must pair population/write evidence with consumption/read evidence, and
protection citations used in a finding must be linked to the matching
`mitigation_evidence` check. Every positive finding also receives one bounded
evidence-review pass before acceptance; the model may use a read-only tool
during that pass when an exact decisive range is missing. Clean completions do
not pay for this additional review.

Run the live configured provider and save the projected actual result outside
the fixture:

```bash
python scripts/deep_audit_logic_benchmark.py \
  --model gpt-5.4 \
  --provider openai \
  --reasoning-effort high \
  --max-tokens 16384 \
  --output /private/tmp/skylos-deep-audit-logic.actual.json
```

The per-call token cap includes hidden reasoning and visible structured output
for reasoning models. The conservative default remains 4096 to avoid silently
quadrupling cost for non-reasoning runs; pass 16384 explicitly for GPT-5.4 at
high reasoning effort. Token exhaustion, including a nonempty truncated JSON
response, is reported immediately as incomplete rather than retried at the same
cap or misreported as clean.

JSON reports are projection-only by default: they retain categories, locations,
usage, and bounded transport diagnostics without model-authored finding prose.
`--output` uses an atomic, no-symlink-following private file (`0600`). Pass
`--include-model-prose` only when the destination is trusted and retaining
potentially source-derived text is intentional.

This command makes paid provider calls. The deterministic pytest fixture uses
the same source and expectations to test orchestration, evidence validation,
and comparison logic, but only the live run measures real-model reasoning.
