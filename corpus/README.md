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

How this complements [liveness_primer](../docs/liveness-primer.md):

- The primer compares two Skylos revisions on the same pinned upstream projects. It shows real-project changes without requiring every existing finding to be labeled.
- Corpus Guard checks small, explicit expectations like "this symbol must not be reported as dead code." Those expectations let CI distinguish a regression from an intended change.
- When primer review uncovers a bug, reduce it to a regression test or corpus fixture here. Keep both checks: broad change detection and precise correctness checks.

How to add a case:

1. Add a new fixture directory under `corpus/fixtures/`.
2. Add a manifest entry in `corpus/manifest.json` with upstream repo, license, and expectation metadata.
3. Keep the fixture minimal. Only include the framework pattern you need to protect.
4. Add or update a unit test in `test/test_corpus_ci.py` if the runner contract changes.
