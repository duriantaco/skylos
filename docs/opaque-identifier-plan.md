# Opaque Identifier Readability Plan

## Goal

Add a low-noise quality rule that catches names like `x = request.args.get("user_id")` when the short or vague name hides useful meaning from the right-hand side and the variable lives long enough to hurt reviewability.

## Rule Shape

- Rule ID: `SKY-Q806`
- Category: `quality`
- Kind: `readability`
- Default severity: `LOW`
- No new feature flag. The rule is enabled with existing `--quality` analysis and can only be disabled through the normal rule ignore list.

## Precision Constraints

The rule must not flag short names by length alone. It should require all of these signals:

- The assigned name is genuinely opaque, such as a one-letter non-counter name or a generic placeholder like `tmp`, `value`, `obj`, or `result`.
- The RHS has recoverable key or subscript evidence, such as `.get("user_id")` or `request.headers["Authorization"]`. Call names can add context, but they are not enough by themselves for default-quality findings.
- The variable has meaningful lifetime or usage, such as being used several lines later, passed onward, returned, or used in a branch.

The rule must skip common acceptable short-name cases:

- loop counters and compact iteration names such as `i`, `j`, `k`, `n`, and `m`
- exception variables like `e`
- file handles like `f`, `fp`, `fd`, and `fh`
- throwaway names beginning with `_`
- `x`, `y`, and `z` when the RHS already names the same coordinate or is clearly numeric/math-shaped
- test files and small throwaway scopes

## Implementation Steps

- Add `skylos/rules/quality/_readability.py` with a module-scoped AST rule.
- Register `SKY-Q806` in the analyzer, rule catalog, CWE/standard metadata, and quality node dispatch table.
- Add unit tests for positive, negative, coordinate, short-scope, and test-file behavior.
- Add a quality benchmark fixture that includes one hard positive and multiple clean counterexamples.
- Run focused tests and the quality benchmark. Keep the rule only if the benchmark stays at 100 and the clean fixture remains clean for `SKY-Q806`.

## Acceptance Criteria

- `SKY-Q806` fires on an opaque long-lived variable whose RHS clearly exposes a better name.
- `SKY-Q806` does not fire on coordinate/math short names, loop counters, exception variables, file handles, small temporary values, or test files.
- Checked-in quality benchmark passes with no new failures.

## Execution Result

- Implemented `SKY-Q806` as default `--quality` behavior with no new feature flag.
- Tightened the rule after self-scan evidence showed call-name-only matching was too noisy.
- Final rule requires direct key/subscript evidence and at least a five-line usage span.
- Validation:
  - `test/test_good_practices_rules.py test/test_quality_benchmark.py test/test_quality_standards.py test/test_debt.py`: `100 passed`
  - `test/test_architecture.py test/test_rules_cmd.py`: `48 passed`
  - `benchmarks/quality/manifest.json`: `100.0/100`, `0` failures
  - Skylos source-tree FP probe: `0` `SKY-Q806` findings
