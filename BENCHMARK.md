# Skylos Benchmarks

This document separates two things that must not be mixed:

- **Regression benchmarks:** checked into this repo, run in CI/local testing, and
  used to prevent known bugs from returning.
- **Independent benchmarks:** frozen before Skylos runs, built from external
  corpora, and used for credible tool-comparison claims.

The current `benchmarks/` directory is a regression benchmark suite. It is useful
and intentionally strict, but it is not an independent proof that Skylos is
state of the art.

## Current Regression Suites

### Dead Code

Run:

```bash
python scripts/dead_code_benchmark.py --strict-labels
python scripts/dead_code_compare_scanners.py
```

Latest local result:

| Scanner | Cases | Skipped | TP | FP | FN | TN | Precision | Recall | F1 | Score |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Skylos | 16 | 0 | 36 | 0 | 0 | 59 | 1.0 | 1.0 | 1.0 | 100.0 |
| Vulture | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A | N/A |
| Ruff | 13 | 3 | 2 | 0 | 28 | 50 | 1.0 | 0.0667 | 0.125 | 62.67 |

Vulture and Ruff are Python-only baselines here, so non-Python cases are
reported as skipped instead of counted as misses. Vulture is not installed in
the current local environment, so it was skipped in the latest rerun.

The dead-code suite covers Python framework liveness, package entrypoints,
plugin loading, SQLAlchemy models, and cross-language Go, Java, TypeScript, and
JavaScript reachability cases.

### External Demo Target

Run:

```bash
python scripts/dead_code_benchmark.py --target /Users/oha/skylos-demo
```

Latest local result:

| Target | TP | FP | FN | TN | Precision | Recall | Unlabeled |
|:---|---:|---:|---:|---:|---:|---:|---:|
| `/Users/oha/skylos-demo` | 12 | 0 | 0 | 12 | 1.0 | 1.0 | 92 |

The demo target is useful as a realistic smoke test, but the `92` unlabeled
findings mean it is not a strict independent benchmark yet. Those findings need
manual triage before being counted as ground truth.

### Security

Run:

```bash
python scripts/security_benchmark.py
python scripts/security_compare_scanners.py
python scripts/security_benchmark.py --scanner bandit
```

Latest local result:

| Scanner | Cases | Skipped | TP | FP | FN | TN | Precision | Recall | F1 | Score |
|:---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Skylos | 20 | 0 | 11 | 0 | 0 | 10 | 1.0 | 1.0 | 1.0 | 100.0 |
| Bandit | 14 | 6 | 1 | 1 | 7 | 6 | 0.5 | 0.125 | 0.2 | 47.14 |

Bandit is a Python security baseline, so Go, Java, and TypeScript cases are
skipped for Bandit.

The security suite covers SQL injection, SSRF, command injection, YAML loader
precision, path traversal, XSS, open redirect, JWT verification bypass, CORS,
Go Zip Slip, Java path traversal, and TypeScript eval.

### Quality

Run:

```bash
python scripts/quality_benchmark.py
```

Latest local result:

| Cases | Failures | Recall | Absence Guard | Latency | Score |
|---:|---:|---:|---:|---:|---:|
| 6 | 0 | 1.0 | 1.0 | 1.0 | 100.0 |

### Agent Review

Run:

```bash
python scripts/agent_review_benchmark.py
```

Latest local result:

| Cases | Failures | Recall | Absence Guard | Latency | Score |
|---:|---:|---:|---:|---:|---:|
| 25 | 0 | 1.0 | 1.0 | 1.0 | 100.0 |

## Why Skylos Scores Highly Here

Skylos scores highly on the checked-in regression suites because the suites are
small, labeled, and the analyzer has already been improved against several of
their failures. That is exactly what a regression suite is for.

It does **not** mean:

- Skylos is universally better than every competitor.
- The current benchmark is independent.
- The current benchmark covers the full industry problem space.
- A `100.0` score here should be used as a marketing claim without caveats.

## Golden Benchmark Status

The current independent corpus is frozen as `golden-v0.2`.

This is a real locked baseline, not a mutable draft. It is still a small first
version, so broad industry claims need the remaining requirements below:

| Requirement | Current status |
|:---|:---|
| External corpus provenance with repo, commit, license, and fixture origin | Partial |
| Labels frozen before Skylos or competitor runs | Done for `golden-v0.2` |
| Independent label review, not derived from Skylos output | Missing |
| Dev/public/holdout splits with no analyzer tuning on holdout | Missing |
| Per-language and per-category minimum case counts | Missing |
| Competitor versions and configs locked in a benchmark lockfile | Done for current runnable tools |
| Raw tool outputs retained and normalized by adapters | Done for current runnable tools |
| TP/FP/FN/TN, TPR/FPR, precision/recall/F1 reported per language | Done |
| Unsupported scanner/language pairs reported separately | Done |
| Before/after Skylos runs recorded before analyzer fixes | Partial |
| Statistical confidence intervals or rank stability for large suites | Missing |
| Reproducible runner environment, ideally Docker-backed | Missing |

Until those boxes are closed, the checked-in numbers should be read as
regression evidence only.

Implementation lives in a sibling local corpus at `../skylos-benchmarks`. That
corpus is intentionally outside this analyzer repo. The current manifest set is
frozen as `golden-v0.2`; each manifest has `label_state: frozen`, and exact
manifest, harness, and result hashes are recorded in
`../skylos-benchmarks/benchmark.lock.json`.

The first external corpus has also been materialized there:

- OWASP Benchmark Java cloned at
  `c13134045a3964c4159889afdf065f09eb70b925`
- `expectedresults-1.2.csv` imported into
  `manifests/security.owasp-java.dev.json`
- 240 OWASP Java cases currently validate as a frozen manifest

Current frozen `golden-v0.2` results from `../skylos-benchmarks` are split by suite,
tool, and language. Unsupported scanner/language pairs are marked `N/A` instead
of receiving a score.

| Suite | Corpus | Tool | Language | Cases Run | Skipped | TP | FP | FN | TN | Score |
|:---|:---|:---|:---|---:|---:|---:|---:|---:|---:|---:|
| Dead code frozen | seeded dev | Skylos | Python | 4 | 0 | 15 | 1 | 1 | 11 | 93.33 |
| Dead code frozen | seeded dev | Skylos | TypeScript | 2 | 0 | 6 | 0 | 0 | 3 | 100.0 |
| Dead code frozen | seeded dev | Skylos | JavaScript | 1 | 0 | 3 | 0 | 0 | 2 | 100.0 |
| Dead code frozen | seeded dev | Skylos | Go | 1 | 0 | 3 | 0 | 0 | 1 | 100.0 |
| Dead code frozen | seeded dev | Skylos | Java | 1 | 0 | 2 | 0 | 0 | 1 | 100.0 |
| Dead code frozen | seeded dev | Vulture | Python | 4 | 0 | 14 | 2 | 2 | 10 | 86.67 |
| Dead code frozen | seeded dev | Vulture | TypeScript | 0 | 2 | 0 | 0 | 0 | 0 | N/A |
| Dead code frozen | seeded dev | Vulture | JavaScript | 0 | 1 | 0 | 0 | 0 | 0 | N/A |
| Dead code frozen | seeded dev | Vulture | Go | 0 | 1 | 0 | 0 | 0 | 0 | N/A |
| Dead code frozen | seeded dev | Vulture | Java | 0 | 1 | 0 | 0 | 0 | 0 | N/A |
| Dead code frozen | seeded dev | Ruff | Python | 4 | 0 | 0 | 0 | 16 | 11 | 55.0 |
| Security frozen | seeded dev | Skylos | Python | 3 | 0 | 10 | 1 | 0 | 7 | 94.32 |
| Security frozen | seeded dev | Skylos | TypeScript | 1 | 0 | 5 | 0 | 0 | 1 | 100.0 |
| Security frozen | seeded dev | Skylos | Go | 2 | 0 | 5 | 0 | 0 | 2 | 100.0 |
| Security frozen | seeded dev | Bandit | Python | 3 | 0 | 6 | 3 | 4 | 7 | 64.33 |
| Security frozen | seeded dev | Bandit | TypeScript | 0 | 1 | 0 | 0 | 0 | 0 | N/A |
| Security frozen | seeded dev | Bandit | Go | 0 | 2 | 0 | 0 | 0 | 0 | N/A |
| Security frozen | OWASP Java dev | Skylos | Java | 240 | 0 | 105 | 0 | 15 | 120 | 94.37 |
| Quality frozen | seeded dev | Skylos | Python | 1 | 0 | 0 | 0 | 1 | 1 | 55.0 |
| Agent review frozen | seeded dev | Skylos | Python | 1 | 0 | 1 | 0 | 0 | 1 | 100.0 |

These frozen results already show useful gaps to investigate before any public
claim: the seeded Python quality duplicate-branch case is still missed, and
OWASP Java still has request-wrapper interprocedural, LDAP injection, XPath
injection, and property-driven weak-hash gaps. Frozen dead-code dev is now at
full JavaScript, TypeScript, Go, and Java score; the remaining Python
dead-code residuals are benchmark-label review items around duplicate
dead-class method reporting and an unlabeled genuinely unreachable helper. The
seeded security dev suite is now at full recall with one Python `urljoin`
label-review false positive. Vulture is only comparable on the Python
dead-code subset.

Phase 2 Python security rerun on 2026-04-25 improved frozen `security.dev`
overall from `TP=17 FP=5 FN=3 TN=9 score=78.15` to
`TP=19 FP=2 FN=1 TN=9 score=90.78`. Python moved from
`TP=8 FP=4 FN=2 TN=7 score=72.06` to
`TP=10 FP=1 FN=0 TN=7 score=94.32`. The remaining Python FP is
`seed-python-path-ssrf-redirect`'s fixed-host `urljoin` negative label:
`urljoin("https://cdn.example.com/", f"{user_id}.png")` can still be overridden
by `https://...` or `//...` user input, so the detector keeps flagging it and
the label should be reviewed in the next benchmark version instead of being
suppressed in the analyzer.

Phase 2b TypeScript/Go security rerun on 2026-04-25 improved frozen
`security.dev` overall from `TP=19 FP=2 FN=1 TN=9 score=90.78` to
`TP=20 FP=1 FN=0 TN=10 score=96.52`. TypeScript moved from
`TP=4 FP=0 FN=1 TN=1 score=91.0` to `TP=5 FP=0 FN=0 TN=1 score=100.0`.
Go moved from `TP=5 FP=1 FN=0 TN=1 score=84.17` to
`TP=5 FP=0 FN=0 TN=2 score=100.0`.

Phase 3 Java security rerun on 2026-04-25 improved frozen
`security.owasp-java.dev` from `TP=17 FP=0 FN=103 TN=120 score=61.38` to
`TP=105 FP=0 FN=15 TN=120 score=94.37`. The patch keeps the OWASP Java false
positive count at zero while moving Java servlet security flow to a structured
tree-sitter analyzer with the older regex-heavy scanner retained only as a
failure fallback. Coverage includes cookies, weak randomness, command
execution, SQL, LDAP, XPath, XSS, path traversal, and trust-boundary session
writes. The previous `TP=109` exploratory result used an FP-prone unknown
wrapper accessor shortcut and was rejected. Remaining Java misses are
request-wrapper interprocedural flows, LDAP injection, XPath injection, and
weak-hash algorithms loaded through project properties.

Phase 4 dead-code rerun on 2026-04-26 improved frozen `dead_code.dev` overall
from `TP=26 FP=3 FN=4 TN=17 score=87.38` to
`TP=29 FP=1 FN=1 TN=18 score=96.28`. TypeScript moved from
`TP=5 FP=0 FN=1 TN=3 score=92.5` to `TP=6 FP=0 FN=0 TN=3 score=100.0`;
JavaScript moved from `TP=3 FP=2 FN=0 TN=1 score=72.67` to
`TP=3 FP=0 FN=0 TN=2 score=100.0`; Java moved from
`TP=1 FP=0 FN=1 TN=1 score=77.5` to `TP=2 FP=0 FN=0 TN=1 score=100.0`;
Python moved from `TP=14 FP=1 FN=2 TN=11 score=90.38` to
`TP=15 FP=1 FN=1 TN=11 score=93.33`. The patch keeps duplicate dead-class
methods out of the reported finding set, so the frozen
`dc-py-plugin-removed-method` label should be reviewed rather than forcing
duplicate method output back into the analyzer.

## Benchmark Rules

Checked-in regression benchmarks follow these rules:

- Labels are explicit in manifests.
- Strict dead-code mode counts unlabeled findings as false positives.
- Positive and negative cases are both required for high-risk rules.
- Unsupported scanner/language pairs are skipped, not counted as failures.
- Competitor commands should use documented, reasonable configs.

Independent benchmarks add stricter rules:

- Labels freeze before Skylos runs.
- Corpora come from external sources or real OSS commits, not Skylos output.
- Development, public regression, and holdout splits stay separate.
- Any label change after a run is treated as a benchmark bug and version bump.
- Before/after Skylos results are both recorded before analyzer fixes land.

## Independent Benchmark Design

The independent benchmark should live outside this analyzer repo or in a
separate benchmark repo once it is ready. The analyzer repo can keep fixtures
that protect known behavior, but the credible comparison corpus should not be
tuned while Skylos implementation work is happening.

Recommended layout:

```text
skylos-benchmarks/
  benchmark.lock.json
  manifests/
    dead_code.dev.json
    dead_code.holdout.json
    security.dev.json
    security.holdout.json
    quality.dev.json
    quality.holdout.json
    agent_review.dev.json
    agent_review.holdout.json
  corpora/
  labels/
  runners/
  scorers/
  tool_configs/
  results/
```

### Dead-Code Independence

Use three layers:

- semantic microcases from documented tool/language behavior
- seeded dead-code injections in real OSS repos, with the injection patch saved
  separately from the expected labels
- real cleanup PRs where removed symbols can be validated by commit history,
  package exports, references, tests, or maintainer intent

The minimum useful matrix is Python, TypeScript/JavaScript, Go, and Java across:

- unused files
- unused exports/functions/classes/methods
- unused imports and dependencies
- framework-owned entrypoints that must stay quiet
- dynamic/plugin entrypoints that must stay quiet
- dead-code clusters and mutually recursive unused components
- generated/build/test/config code that should be excluded or separately scoped

Competitors should include Vulture, Ruff/Pyflakes, ESLint/TypeScript
`noUnusedLocals`, staticcheck-style Go checks, and Java unused-code tools where
available. JS/TS comparisons should include Knip-style project graph checks, not
only single-file lint rules.

### Security Independence

Use external corpora and scoring patterns from:

- OWASP Benchmark expected-results style cases
- NIST Juliet/SARD flawed and non-flawed cases
- NIST SATE-style real/injected vulnerability programs
- Semgrep and CodeQL rule tests where licensing allows
- gosec, SpotBugs/FindSecBugs, PMD, Bandit, and Semgrep competitor outputs

Every CWE/category should include vulnerable and safe cases.

The minimum useful matrix is Python, TypeScript/JavaScript, Go, and Java across:

- SQL/code/command injection
- path traversal and archive extraction
- SSRF and open redirect
- XSS/template injection
- unsafe deserialization
- weak crypto/randomness/token verification
- CORS and auth/session misconfiguration
- safe sanitizer variants and constant-only variants

### Quality Independence

Split quality into two tracks:

- static smell detection: complexity, long functions, resource leaks,
  inconsistent returns, broad exceptions, duplicate branches, async blocking
- real bug/fix corpora: Defects4J, BugsInPy/PyBugHive, QuixBugs, Bears, or
  similar reproducible datasets

### Agent-Review Independence

Follow SWE-bench-style evaluation:

- real issue or bug/fix task
- hidden fail-to-pass and pass-to-pass tests for patch tasks
- clean negative tasks for precision
- Docker or otherwise reproducible environments
- record model, prompt hash, retry budget, token cost, runtime, and pass@1

## Research References

These are the external benchmark patterns the golden suite should follow:

- [OWASP Benchmark](https://owasp.org/www-project-benchmark/): executable
  vulnerable and non-vulnerable test cases with expected-results files and
  scorecard tooling.
- [NIST SAMATE/SARD](https://www.nist.gov/itl/ssd/software-quality-group/samate):
  documented weakness corpora and SATE tool-evaluation programs.
- [NIST Juliet](https://www.nist.gov/publications/juliet-11-cc-and-java-test-suite):
  large synthetic C/C++ and Java flaw corpus with known bad and good variants.
- [Semgrep rule tests](https://semgrep.dev/docs/writing-rules/testing-rules):
  positive and negative annotations for false-negative and false-positive
  protection.
- [CodeQL query metadata](https://codeql.github.com/docs/writing-codeql-queries/metadata-for-codeql-queries/):
  precision/severity metadata and path-problem reporting conventions.
- [SWE-bench](https://www.swebench.com/SWE-bench/): real GitHub issue
  evaluation with reproducible environments and pass/fail tests.
- [Defects4J](https://github.com/rjust/defects4j),
  [BugsInPy](https://github.com/soarsmu/BugsInPy), and
  [PyBugHive](https://pybughive.github.io/): real bug/fix corpora for quality
  and agent-review tracks.

## Validation Commands

Current local validation for this benchmark milestone:

```bash
python scripts/dead_code_benchmark.py --strict-labels
python scripts/dead_code_compare_scanners.py
python scripts/dead_code_benchmark.py --target /Users/oha/skylos-demo
python scripts/security_benchmark.py
python scripts/security_compare_scanners.py
python scripts/security_benchmark.py --scanner bandit
python scripts/quality_benchmark.py
python scripts/agent_review_benchmark.py
python -m pytest -q
/opt/homebrew/bin/ruff check skylos/dead_code_benchmark.py skylos/security_benchmark.py skylos/analyzer.py skylos/penalties.py skylos/rules/danger/danger_web/xss_flow.py scripts/dead_code_benchmark.py scripts/dead_code_compare_scanners.py scripts/security_benchmark.py scripts/security_compare_scanners.py test/test_dead_code_benchmark.py test/test_security_benchmark.py test/test_xss_flow.py
git diff --check
```

Latest full test run:

```text
3324 passed, 4 skipped, 3 warnings
```
## Latest Frozen OWASP Java Security Result

Run: `security.owasp-java.dev` with Skylos Java structured flow analyzer as the primary path and legacy request/servlet scanner as failure fallback only. Unknown external request-wrapper accessors are not treated as tainted without a real same-project summary.

| Tool | TP | FP | FN | TN | Score |
| --- | ---: | ---: | ---: | ---: | ---: |
| Skylos | 105 | 0 | 15 | 120 | 94.37 |
