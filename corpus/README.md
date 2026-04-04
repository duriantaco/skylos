# Corpus Guard

This corpus is a deterministic false-positive guard for Skylos static analysis.

The fixtures are intentionally small and local, but each case is traced back to a reputable upstream project and a real framework pattern. That keeps CI fast and stable while still grounding expectations in real-world usage.

Acceptance rules:

- A corpus case must encode a stable semantic truth, not a style preference.
- The source pattern must come from an official project, official docs, or another highly trusted upstream library.
- The fixture must be minimal and isolate one runtime contract or one closely related pattern.
- If liveness depends on framework registration, the fixture must show real registration or real runtime use.
- Expectations must be explicit and binary, such as "`home` must not appear in `unused_functions`."
- Avoid whole-project assertions and avoid gating on total finding counts.
- Prefer cases that protect common frameworks, must-not-miss hooks, and critical static-analysis edge cases.

Why this is better than scanning whole upstream repositories on every PR:

- Whole-repo scans are noisy because mature libraries may contain legitimate findings unrelated to the regression you are trying to catch.
- Whole-repo scans are slow and brittle because upstream code changes over time.
- Distilled fixtures let us assert exact expectations like "this symbol must not be reported as dead code" without hiding unrelated issues.

How to add a case:

1. Add a new fixture directory under `corpus/fixtures/`.
2. Add a manifest entry in `corpus/manifest.json` with upstream repo, license, and expectation metadata.
3. Keep the fixture minimal. Only include the framework pattern you need to protect.
4. Add or update a unit test in `test/test_corpus_ci.py` if the runner contract changes.
