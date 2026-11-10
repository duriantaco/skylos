# Cleanup pattern corpus

This development corpus measures which concrete patterns Skylos detects and
which findings appear in the cleanup queue. Every problematic example has a
control for the same pattern. A catch requires the expected rule, source file
and line range; an unrelated warning does not count.

The initial slice contains 16 independently authored examples, arranged as
eight pairs. These are synthetic development fixtures informed by external
corpora, not an independent real-project accuracy study. They do not establish
whether code was written by an AI. No detector implementation is imported.

## Run

From an editable checkout with the normal Skylos dependencies installed:

```bash
python -m skylos.benchmarks.cleanup_corpus \
  --manifest benchmarks/cleanup/corpus/manifest.json \
  --output /tmp/skylos-cleanup-corpus.json
```

The runner validates paths, pairs, source references, rule IDs and line spans.
It copies each case into a neutral temporary source directory and invokes the
actual cleanup command in a fresh Python process, with an empty operator
configuration and synced policy. Jobs are limited to one. The original
fixtures remain unchanged. Network connections, corpus-file imports and
non-Git subprocesses are blocked by an audit guard; only bounded read-only
Git command shapes are allowed. This guard is an evaluation aid, not a sandbox
for arbitrary programs.

The run does not install target dependencies, execute target tests, use trace,
request model review, apply patches, upload results or write cleanup history.
The all-advice view is derived separately from the same captured analyzer
report. This preserves the difference between raw detection and default queue
visibility. Repair correctness is not evaluated.

## Initial coverage

| Pattern | Mapping | Why the counterpart matters |
| --- | --- | --- |
| Blocking HTTP inside an async function | `SKY-Q401` | An awaited asynchronous request should remain clean. |
| Mutation of a shared mutable default | `SKY-L001` | Allocating a fresh list per call should remain clean. |
| Python write error swallowed silently | `SKY-L007` | Propagating the error should remain clean. |
| TypeScript rejected write swallowed by an empty catch | `SKY-L007` | Propagating the rejection should remain clean. |
| Meaningless constant assertion | Unmapped | Checking an actual result is materially different. |
| Adjacent duplicated assertion | Unmapped | Checking distinct result properties adds evidence. |
| Empty test | Unmapped | A real assertion checks the expected result. |
| Fixed sleep before checking completion | Unmapped | Waiting on an explicit completion event is different from assuming a delay is sufficient. |

The four test patterns currently have no direct standalone snapshot mapping.
Diff-based assertion weakening, deleted-test checks and mutation testing are
separate capabilities; their presence does not establish snapshot coverage of
these cases. Unmapped patterns are recorded as gaps, including their controls,
and are excluded from mapped detection/false-positive counts.

`baseline.json` records the initial measured outcome and source hashes. Its
revision identifies the analyzer baseline; the runner and fixture hashes bind
the new evaluation files. Counts apply only to these development examples.
The initial run detects all four mapped problematic cases, leaves their four
controls clean for the specified rules, and records eight unmapped examples
across the four test-pattern pairs. All 16 scans completed with unchanged
source and no blocked execution or network events.
Repository-policy advice and other incidental findings are summarized by rule
in the checked-in receipt and do not count toward the labeled pattern. The
runner's full JSON output retains those observations; the condensed receipt
records its digest and binds each case's metadata and source bytes.

The runner reports `detected`, `missed`, `clean_control`, `false_positive`,
`unmapped` and `incomplete` separately. Incomplete scans never become passing
controls or detection misses. Exit 2 means incomplete execution; exit 1 means
a mapped detection/control failed; exit 0 means the mapped observations
completed without those failures. Unmapped gaps remain explicit even at exit 0.

## Sources and reuse

`python_tests.json` records pinned concept references to
[PyNose's test fixtures](https://github.com/JetBrains-Research/PyNose/tree/081e5f9dcc416da4a290bcc5102ce46f104afefa/plugin/src/test/resources/org/jetbrains/research/pynose/plugin/inspections/data).
`code_patterns.json` records pinned references to Ruff and ESLint. The
`source.license` field identifies the reference material's license. The
independently authored fixtures inherit Skylos's Apache-2.0 license.

`real_repairs.json` separately records two historical BugsJS/Express repairs:
an object-valued JSONP callback used without a string check, and a response
error that fails to reach the error continuation. Before/fix/test revisions,
source ranges, Git blob IDs, SHA256 digests and license links were verified.
Those are reference-only cases, excluded from this runner's detection totals.
Their regression tests were read, not executed; their upstream source is not
vendored here. Full-project context and independently reviewed detector
expectations are needed before adding them to measured coverage.

Further sources worth curating include
[CodeTaste](https://github.com/logic-star-ai/codetaste) for real multi-file
refactorings, [BugsInPy](https://github.com/soarsmu/BugsInPy) for Python repairs,
[AIDev](https://huggingface.co/datasets/hao-li/AIDev) for agent PRs and human
review observations, and
[SlopCodeBench](https://github.com/SprocketLab/slop-code-bench) for degradation
under evolving requirements. These have different evidence and reuse terms;
PR provenance, synthetic labels and derived metrics are not interchangeable
with manually adjudicated defects. Preserve the relevant upstream terms when
adding source material. Keep held-out repositories separate from development
fixtures, and retain every old positive and control when expanding coverage.
