# Scanner Bypass Reference

Use this for false negatives, evidence-filter bugs, unsafe suppressions, and
rules that miss reachable security problems.

## Bypass Workflow

1. Preserve the original report and claimed path.
2. Build the smallest vulnerable fixture that should be detected.
3. Run or invoke the relevant analyzer path without executing target code.
4. Locate where the finding is lost: discovery, rule matching, evidence filter,
   config ignore, output filtering, baseline, or CI gate.
5. Fix the proof condition or data-flow logic.
6. Add a regression test that asserts the finding survives to output.

For security false negatives, a permissive filter is usually more dangerous
than a noisy detector. Prefer requiring stronger proof before suppressing.

## Unsafe Proof Patterns

Do not classify a sink as safe based only on:

- Uppercase variable names.
- No local mutation seen in the same file.
- Comments, docstrings, or type hints.
- Helper names such as `safe_*`, `trusted_*`, or `validated_*`.
- A whitelist variable that is assigned from request data, config, environment,
  files, network responses, or function parameters.

Safe-sink proofs should trace to trusted literals, immutable allowlists, typed
framework APIs with documented guarantees, or sanitizers with tests.

## Evidence Filters

Review these areas for LLM finding suppression:

- `skylos/llm/analyzer.py`
- `skylos/llm/finding_evidence.py`
- `skylos/llm/security_verifier.py`
- `skylos/llm/verify_orchestrator.py`
- `test/test_*evidence*.py`
- targeted security tests near the affected rule.

When adding a filter, make it conservative:

- Refute only one narrow finding shape.
- Require positive proof of safety.
- Add tests for safe and unsafe lookalikes.
- Ensure the finding category and rule ID match the intended filter.

## Regression Test Pattern

Write tests with both sides:

- Vulnerable fixture: must produce a finding.
- Safe fixture: may be filtered or ignored.
- Lookalike fixture: same surface syntax but attacker-controlled data; must not
  be filtered.

Prefer assertions on rule ID, category, file, and symbol rather than broad count
assertions only.

## Output Path Checks

If the finding exists internally but disappears from final output, inspect:

- Project config ignores.
- Baseline filtering.
- Diff filtering.
- Severity/category filters.
- LLM post-processing.
- CI gate conversion.
- JSON/SARIF/GitHub annotation rendering.
