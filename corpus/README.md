# Corpus Guard

This corpus checks that Skylos keeps valid framework code quiet and still
reports real findings beside it.

The fixtures are intentionally small and local, but each case is traced back to a reputable upstream project and a real framework pattern. That keeps CI fast and stable while still grounding expectations in real-world usage.

Acceptance rules:

- A corpus case must encode a stable semantic truth, not a style preference.
- The source pattern must come from an official project, official docs, or another highly trusted upstream library.
- The fixture must be minimal and isolate one runtime contract or one closely related pattern.
- If liveness depends on framework registration, the fixture must show real registration or real runtime use.
- Expectations must be explicit and binary, such as "`home` must not appear in `unused_functions`."
- Pair quiet controls with actual findings from the same pattern. An empty
  detector result must fail the real-finding side of the pair.
- Keep reporting policy separate from source liveness. `whitelisted` and
  `dead_code_abstentions` are evidence categories, not reported unused symbols.
- Avoid whole-project assertions and avoid gating on total finding counts.
- Prefer cases that protect common frameworks, must-not-miss hooks, and critical static-analysis edge cases.

## Current coverage

The manifest has 49 cases and 191 explicit expectations: 112 absence checks and
79 presence checks. Presence includes 74 unused-symbol controls, two quality
tokens, and three separately recorded policy controls. These are assertions,
not a whole-repository precision or recall score.

All 46 original absence-only cases now include real unused-symbol controls.
The always-false loop has a separate reachable-loop partner. A model/settings
case checks used classes beside unreferenced classes with the same framework
bases. Each fixture scans from its own temporary copy, including metadata inside
its declared directory, so neighbouring fixtures and regression tests cannot
keep its symbols alive. Fixture programs and frameworks are never executed.

The four model fixtures explicitly construct/read/serialize their models.
The serializer fixture uses a wrap serializer that delegates to normal field
serialization, so its field and model hooks both have a source-visible use path.
Uncalled methods inside an unused class are checked as grouped under the class;
separate constructed owners test standalone unused-method findings.

Two unreferenced helper functions remain in `dead_code_abstentions`, and a helper
in a test file remains `whitelisted`. Their source is still unreferenced; the
manifest records those existing reporting policies separately and also includes
actual unused-symbol findings. None is counted as a detector fix.

## Validity and execution

Parse failures, incomplete analysis, invalid report data and zero analyzed
source files are `UNSCORED` failures. They satisfy no expectations and make the
command exit nonzero. Valid files with no symbols remain eligible; symbol counts
are not used as a completeness test. Unknown requested case IDs are rejected.

```bash
python scripts/corpus_ci.py --manifest corpus/manifest.json --json
pytest -q test/test_corpus_ci.py test/test_corpus_ci_completeness.py \
  test/test_corpus_ci_framework_controls.py test/test_corpus_ci_language_controls.py
```

How this complements [liveness_primer](../docs/liveness-primer.md):

- The primer compares two Skylos revisions on the same pinned upstream projects. It shows real-project changes without requiring every existing finding to be labeled.
- Corpus Guard checks small, explicit expectations like "this symbol must not be reported as dead code." Those expectations let CI distinguish a regression from an intended change.
- When primer review uncovers a bug, reduce it to a regression test or corpus fixture here. Keep both checks: broad change detection and precise correctness checks.

How to add a case:

1. Add a new fixture directory under `corpus/fixtures/`.
2. Add a manifest entry in `corpus/manifest.json` with upstream repo, license, and expectation metadata.
3. Include both a valid use and a real finding, or link separate companion cases
   with `paired_with`. Show real registration or use; inheritance alone does not
   prove that a class has a consumer.
4. Add or update a unit test in `test/test_corpus_ci.py` if the runner contract changes.
