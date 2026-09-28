# LLM Output Validation Benchmark

This suite checks whether Skylos links a particular LLM response to a particular
use and to any validation on that path. Each `# ov-call:` and `# ov-use:` marker
anchors one labeled call-to-use path in `manifest.json`. The labels describe the
fixture's code, independently of Skylos's current verdict:

- `safe`: this response is parsed or schema-validated before the marked use.
- `unsafe`: at least one reachable path sends this response to the marked use
  without that validation.
- `unknown`: the fixture omits code needed to establish whether validation occurs.

Here, “safe” means **the output-validation rule's narrow condition is met**.
It does not mean a value is safe for a shell, SQL, HTML, or any other specific
sink. Sink-specific safety requires separate analysis.

## Run

From the repository root:

```bash
python -m benchmarks.output_validation.benchmark
python -m benchmarks.output_validation.benchmark --json
python -m benchmarks.output_validation.benchmark --case two-calls-one-validated
python -m benchmarks.output_validation.benchmark --cohort adversarial
pytest -q test/test_output_validation_benchmark.py
```

The runner calls `detect_integrations()` on each fixture directory. It never
imports or executes fixture code. The `external-validator` fixture deliberately
imports a module that is absent to test uncertainty handling.

The manifest separates the initial 13-case `pilot` from seven later
`adversarial` cases. The latter challenge container indexing, tuple member
attribution, `yield`, conditional expressions, a trusted Pydantic
`TypeAdapter`, a visible `Any`-typed identity helper, and field access on a
parsed JSON dictionary. The report scores
the cohorts separately. “Adversarial” means these cases were added after the
pilot; it does not imply an independent real-world sample.

## What the comparison means

The `baseline` arm clones each discovered integration with the new flow status
cleared, then asks the existing `output-validation` defense plugin for its
function-scoped decision. The `candidate` arm reads `output_flow_status` from
the same integration and also runs the defense plugin. Both arms therefore use
the same discovered LLM calls; the comparison isolates validation judgment.

- **False pass:** an `unsafe` path classified `safe`.
- **False alarm:** a `safe` path classified `unsafe`.
- **Unknown on known:** a `safe` or `unsafe` path classified `unknown`.
- **Discovery miss:** Skylos did not discover the LLM call at its marked line.
- **Unknown overclaim:** an `unknown` path classified as safe or unsafe.

The report also includes safe retention, unsafe detection, per-case scan time,
and whether flow evidence cites the labeled call and use lines. Scan time is
the candidate scanner's end-to-end time on these tiny fixtures; the paired
legacy arm does not provide a historical baseline scan-time measurement.

This is a small synthetic regression suite, not an independent estimate of
field accuracy. It is useful for proving specific false passes are removed
without turning clean paths into alarms or unknowns. A broader, separately
labeled corpus would be needed to estimate deployment precision and recall.
