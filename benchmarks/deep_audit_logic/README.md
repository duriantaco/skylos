# Deep Audit Logic Benchmark

This benchmark exercises the repository-aware `LogicInvestigator`, not the
fast agent-review lane or a static logic heuristic.

The two fixtures have byte-identical `api.py` and `refunds/service.py` files.
Both repositories also contain safe and unsafe `can_refund` implementations:
the only difference is which implementation is reachable through
`refunds.service`. A correct result therefore has to follow the real import and
must not use `archive/policy.py` as decision evidence.

Stable semantic expectations are checked into `expected.json`. Model prose,
hashes, timing, and token counts are intentionally not golden-filed.

Run the live configured provider and save the projected actual result outside
the fixture:

```bash
python scripts/deep_audit_logic_benchmark.py \
  --model gpt-4.1 \
  --output /private/tmp/skylos-deep-audit-logic.actual.json
```

This command makes paid provider calls. The deterministic pytest fixture uses
the same source and expectations to test orchestration, evidence validation,
and comparison logic, but only the live run measures real-model reasoning.
