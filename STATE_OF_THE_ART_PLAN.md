# Skylos State Of The Art Plan

## Core Goal

Increase true positives while reducing false positives and false negatives.

This must be measured by domain. Dead-code accuracy, security accuracy, and quality-rule accuracy should not be mixed into one score because their definitions of TP, FP, and FN are different.

## Direction Decision

The benchmark framework should live in this Skylos repo.

The benchmark targets can be split:

- Small deterministic regression fixtures live in this repo.
- Larger realistic demo targets, including `/Users/oha/skylos-demo`, stay external and are referenced by path or config.

Reasoning:

- The runner and schema need to version with Skylos analyzer output.
- CI should be able to gate Skylos without requiring another local repo.
- Small fixtures protect exact analyzer behavior.
- `skylos-demo` is better as a realistic whole-repo target than as the benchmark framework itself.

Recommended shape:

```text
benchmarks/
  agent_review/
  dead_code/
  quality/
  security/

benchmarks/dead_code/
  README.md
  manifest.json
  fixtures/
    fastapi_route_used/
    dynamic_registry_used/
    truly_unused_helper/
  external_targets.json

scripts/
  dead_code_benchmark.py

skylos/
  dead_code_benchmark.py
```

Security now has its own separate harness inside the same umbrella:

```text
benchmarks/security/
  README.md
  manifest.json
  fixtures/
```

## Domain Definitions

### Dead Code

Primary next track.

- TP: a truly unused symbol is reported as unused.
- FP: an actually used symbol is reported as unused.
- FN: a truly unused symbol is missed.
- TN: an actually used symbol stays quiet.

Examples:

- TP: unused helper function is reported.
- FP: FastAPI route handler is reported even though the framework calls it.
- FN: unused schema class is not reported.
- TN: dependency provider or registered callback is not reported.

### Security

Separate later track.

- TP: a real vulnerability pattern is reported.
- FP: safe code is reported as vulnerable.
- FN: a real vulnerability pattern is missed.
- TN: safe code stays quiet.

Examples:

- TP: tainted SQL reaches `cursor.execute`.
- FP: parameterized SQL is reported as SQL injection.
- FN: SSRF through an indirect helper is missed.
- TN: fixed-host URL interpolation stays quiet.

### Quality

Already partially covered by existing `benchmarks/quality/`.

- TP: expected quality issue appears.
- FP: clean pattern is reported.
- FN: expected quality issue is missed.
- TN: clean pattern stays quiet.

## Current Benchmark Assessment

`/Users/oha/skylos-demo` is useful and should be kept in the plan.

Strengths:

- Realistic FastAPI-style Python service.
- Existing dead-code benchmark scripts and ground-truth lists.
- Contains framework, routing, services, DB, schemas, tests, TypeScript, and Go surfaces.
- Good target for whole-repo dead-code comparison.

Limitations:

- Ground truth is hardcoded in Python scripts.
- It is outside the Skylos repo, so it should not be the only CI gate.
- It is good for realistic evaluation, but less good for exact one-case regression tests.

Decision:

- Use `skylos-demo` as the first external dead-code target.
- Build the reusable benchmark runner and manifest schema inside this repo.
- Keep exact regression fixtures inside this repo.

## Execution Track A: Dead-Code Benchmark First

This is the next implementation direction.

### A1. Benchmark Schema

Create a manifest-driven dead-code benchmark.

Each case should declare:

- id
- path
- description
- source metadata
- taxonomy labels
- importance
- expected unused symbols
- expected used symbols
- confidence threshold
- optional runtime budget

Expected symbol fields:

- file
- symbol
- kind: import, function, class, variable, parameter, file
- optional normalized aliases

### A2. Runner

Create a runner that executes Skylos and computes:

- TP
- FP
- FN
- TN
- precision
- recall
- F1
- absence guard
- findings by symbol kind
- findings by taxonomy
- runtime

The runner should support:

```bash
python scripts/dead_code_benchmark.py
python scripts/dead_code_benchmark.py --json
python scripts/dead_code_benchmark.py --case <case-id>
python scripts/dead_code_benchmark.py --target /Users/oha/skylos-demo
python scripts/dead_code_benchmark.py --scanner vulture
```

### A3. Internal Regression Fixtures

Start with small fixtures that protect known hard cases:

- FastAPI route handlers should stay alive.
- FastAPI `Depends` providers should stay alive.
- Flask route handlers should stay alive.
- Dynamic registry handlers should stay alive when registered.
- Event/callback handlers should stay alive when registered.
- SQLAlchemy concrete models should be reportable when sibling models are actively referenced.
- SQLAlchemy declarative base classes and ORM columns should stay quiet.
- Flask blueprint route handlers should stay alive.
- Flask/Click CLI command handlers should stay alive.
- Multi-file service/repository layers should resolve cross-file references.
- Truly unused helpers should be reported.
- Name-collision methods should not be over-rescued.
- Test fixtures should not create noisy dead-code findings.

### A4. External Demo Target

Use `/Users/oha/skylos-demo` as an external whole-repo benchmark.

Migration target:

- Convert current hardcoded `EXPECTED_UNUSED` and `ACTUALLY_USED` lists into a manifest or loadable fixture file.
- Keep compatibility with the existing benchmark behavior while improving structure.
- Compare Skylos output against the same ground truth.

### A5. Acceptance Criteria

Dead-code benchmark is ready when:

- It runs without network or API keys.
- It can run in this repo without requiring `/Users/oha/skylos-demo`.
- It can optionally run against `/Users/oha/skylos-demo`.
- It reports TP/FP/FN/TN clearly.
- It fails non-zero on expectation failures.
- It has tests for the runner itself.

## Execution Track B: Security Benchmark Later

Security should remain separate under `benchmarks/security/`.

The current security harness is useful and now passes, but it is still a separate
domain scorecard. It should not be mixed into dead-code TP/FP/FN numbers.

Future work:

- Keep security source-to-sink benchmarks separate from dead-code benchmarks.
- Add evidence traces for high-impact findings.
- Add interprocedural taint summaries.
- Add framework source/sink/sanitizer models.
- Add sink-specific sanitizer semantics.
- Add confidence levels such as confirmed, likely, heuristic, informational.

## Execution Track C: Quality Benchmark Existing

The repo already has:

- `benchmarks/quality/`
- `benchmarks/agent_review/`
- `corpus/`

Future work:

- Keep quality benchmarks separate from dead-code and security benchmarks.
- Reuse scoring ideas where helpful.
- Avoid merging all domains into one metric.

## Checklist

### Completed

- [x] Researched state-of-the-art static analysis directions: path queries, taint mode, framework models, evidence traces, code property graphs, benchmark gates, and LLM-assisted verification.
- [x] Inspected `/Users/oha/skylos-demo` and confirmed it is strongest as a dead-code benchmark target.
- [x] Inspected existing Skylos benchmark assets: `benchmarks/quality/`, `benchmarks/agent_review/`, `corpus/`, and benchmark scripts.
- [x] Decided the benchmark framework should live in this repo, while `skylos-demo` remains an external target.
- [x] Clarified that dead-code, security, and quality need separate TP/FP/FN scorecards.
- [x] Added this plan as the working checklist for future benchmark and analyzer work.
- [x] Created `benchmarks/dead_code/README.md`.
- [x] Created `benchmarks/dead_code/manifest.json`.
- [x] Created first internal dead-code fixtures.
- [x] Added `skylos/dead_code_benchmark.py`.
- [x] Added `scripts/dead_code_benchmark.py`.
- [x] Added runner tests in `test/test_dead_code_benchmark.py`.
- [x] Added `benchmarks/dead_code/external_targets.json` for `/Users/oha/skylos-demo`.
- [x] Ran the internal benchmark and confirmed baseline TP/FP/FN/TN.
- [x] Ran the optional external benchmark against `/Users/oha/skylos-demo`.
- [x] Used external benchmark failures to prioritize analyzer fixes.
- [x] Fixed stale grep-verifier cache reuse by versioning grep search cache keys.
- [x] Tightened grep verification so generic references ignore dependency/cache folders and string-only references.
- [x] Fixed cross-file import reference propagation so one file's import does not rescue another file's unused import.
- [x] Consolidated benchmark suites under `benchmarks/{dead_code,agent_review,quality,security}`.
- [x] Added stricter dead-code fixtures for SQLAlchemy mixed models, Flask blueprint/CLI entrypoints, and multi-file service/repository layers.
- [x] Reproduced the SQLAlchemy ORM model false negative before changing analyzer behavior.
- [x] Improved SQLAlchemy ORM model liveness so unused concrete models can be reported when sibling models are actively referenced.
- [x] Preserved standalone SQLAlchemy model precision guards through the corpus suite.
- [x] Added optional Vulture comparison mode for the same dead-code manifest labels.
- [x] Ran the parked security benchmark under `benchmarks/security/` and confirmed it passes as a separate scorecard.
- [x] Made benchmark script defaults resolve from the repo root instead of the caller's current working directory.
- [x] Allowed external dead-code target configs to validate even when the optional local target path is absent; running that target still requires the path to exist.

### Parked

- [x] Created an exploratory security benchmark harness during the earlier security interpretation.
- [x] Fixed one SQL false-positive exposed by that exploratory security harness.
- [x] Kept the exploratory security benchmark as `benchmarks/security/`, separate from dead-code scoring.

### Next To Do: Dead-Code Benchmark Framework

- [x] Create `benchmarks/dead_code/README.md`.
- [x] Create `benchmarks/dead_code/manifest.json`.
- [x] Create first internal dead-code fixtures.
- [x] Add `skylos/dead_code_benchmark.py`.
- [x] Add `scripts/dead_code_benchmark.py`.
- [x] Add runner tests in `test/test_dead_code_benchmark.py`.
- [x] Port the useful `skylos-demo` ground truth into a structured external target config.
- [x] Run the internal benchmark and confirm baseline TP/FP/FN/TN.
- [x] Run the optional external benchmark against `/Users/oha/skylos-demo`.
- [x] Use failures to prioritize analyzer fixes.
- [x] Add harder industry-like dead-code fixtures.
- [x] Add optional competitor baseline support with `--scanner vulture`.

### Later To Do: Analyzer Improvements Driven By Dead-Code Benchmark

- [ ] Improve framework implicit-use modeling.
- [ ] Improve dynamic registry and callback recognition.
- [ ] Improve symbol alias normalization.
- [ ] Improve method name-collision handling.
- [ ] Improve confidence calibration by symbol kind.
- [ ] Expand dead-code benchmarks for Django management commands, Celery tasks, pytest fixtures, Pydantic validators, Alembic migrations, importlib/plugin loading, and package entrypoints.
- [ ] Triage external benchmark unlabeled findings and convert confirmed cases into explicit labels.
- [ ] Add benchmark gates once the signal is stable.

## Current Results

Internal dead-code benchmark:

```text
TP=13 FP=0 FN=0 TN=20
precision=1.0 recall=1.0 f1=1.0
score=100.0/100
```

Stricter internal benchmark before the SQLAlchemy ORM liveness fix:

```text
TP=12 FP=0 FN=1 TN=20
precision=1.0 recall=0.9231 f1=0.96
score=96.92/100
```

External `/Users/oha/skylos-demo` benchmark before analyzer fixes:

```text
TP=8 FP=0 FN=4 TN=12
precision=1.0 recall=0.6667 f1=0.8
score=86.67/100
```

External `/Users/oha/skylos-demo` benchmark after analyzer fixes:

```text
TP=11 FP=0 FN=1 TN=12
precision=1.0 recall=0.9167 f1=0.9565
score=96.67/100
```

External `/Users/oha/skylos-demo` benchmark after SQLAlchemy ORM liveness fix:

```text
TP=12 FP=0 FN=0 TN=12
precision=1.0 recall=1.0 f1=1.0
score=100.0/100
```

Vulture baseline on the same internal dead-code labels:

```text
TP=13 FP=6 FN=0 TN=14
precision=0.6842 recall=1.0 f1=0.8125
score=84.53/100
```

Security benchmark under `benchmarks/security/`:

```text
TP=3 FP=0 FN=0 TN=4
precision=1.0 recall=1.0 f1=1.0
score=100.0/100
```

Remaining measured gap:

- No current labeled dead-code benchmark failures.
- The external demo still has unlabeled findings that should be manually triaged before becoming ground truth.

Validation run for this milestone:

```text
python scripts/dead_code_benchmark.py
python scripts/dead_code_benchmark.py --target /Users/oha/skylos-demo
python scripts/dead_code_benchmark.py --scanner vulture
python scripts/security_benchmark.py
python scripts/quality_benchmark.py
pytest -q test/test_dead_code_benchmark.py test/test_grep_verify.py
pytest -q test/test_security_benchmark.py test/test_quality_benchmark.py test/test_agent_review_benchmark.py
pytest -q test/test_constants.py test/test_cli_precommit.py
pytest -q test/test_corpus_ci.py
/opt/homebrew/bin/ruff check skylos/dead_code_benchmark.py scripts/dead_code_benchmark.py skylos/analyzer.py skylos/penalties.py test/test_dead_code_benchmark.py
```

Note: `python scripts/dead_code_benchmark.py --scanner vulture` currently exits
non-zero because Vulture has expected-used false positives. Treat that command
as a comparison report, not a Skylos pass gate.

## Working Protocol For Future Code Changes

Before coding:

- Read this plan.
- Pick one unchecked item.
- State which checklist item is being executed.

During coding:

- Add or update a benchmark case before changing analyzer behavior when practical.
- Run the benchmark before and after the analyzer change.
- Use the benchmark result to classify the change as TP gain, FP reduction, FN reduction, or neutral cleanup.

After coding:

- Mark completed checklist items in this file.
- Add validation commands and results to the final update.
- Do not mix dead-code benchmark changes with security benchmark changes unless explicitly approved.

## Success Metrics

Dead-code first target:

```text
precision must not decrease
recall must increase or stay flat
false positives on actually-used framework symbols must decrease
false negatives on truly-unused symbols must decrease
runtime must stay within budget
```

Practical first milestone:

- A manifest-driven dead-code benchmark exists in this repo.
- It has at least one internal regression fixture.
- It can optionally evaluate `/Users/oha/skylos-demo`.
- It reports TP/FP/FN/TN and precision/recall/F1.
- It becomes the scorecard for the next analyzer improvements.
