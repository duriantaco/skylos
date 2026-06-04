# Verify Benchmark

This benchmark is intentionally separate from the checked-in
`ai_code_defects` regression suite.

The regression suite is designed to keep known `skylos verify` behavior from
breaking. This suite is designed to ask a harder question:

> If a tool is treated as a black box, does it find representative AI-code
> defects without being handed Skylos-shaped expectations?

## Methodology

The design follows common benchmark patterns from:

- OWASP Benchmark: per-case expected true/false labels and scoreable output
- NIST SAMATE/SARD: known-bad and known-good software artifacts with metadata
- SWE-bench: realistic software-engineering task framing over toy snippets

The manifest does not use `SKY-*` rule IDs. It uses neutral defect labels such
as `phantom_reference`, `api_signature`, `dependency_version`, and
`incomplete_generation`.

The runner invokes the configured tool through its CLI. For Skylos, that means:

```bash
skylos verify <fixture> --output <tmp.json> --no-fail
```

The runner then adapts tool output into neutral labels for scoring. A new agent
can run this benchmark without inspecting `skylos.verify_change` or any analyzer
implementation.

## What It Tests

- stale references after realistic local refactors
- installed API member and keyword drift
- Python dependency version drift
- npm workspace version drift
- compound AI edits with multiple defect types
- file/range scoped precision
- clean cases that should produce no findings

Some cases intentionally cover areas Skylos may not support yet. That is the
point: this is an accuracy/gap benchmark, not a pass-preserving regression
suite.

Run it with:

```bash
python scripts/verify_benchmark.py --tool-command .venv/bin/skylos
```

Use `--json` for machine-readable output or `--report /path/report.md` for a
markdown report.
