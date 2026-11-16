# AI-Code-Defect Benchmark

This benchmark tracks AI-specific code defects that `skylos verify` should catch
inside an agent loop: hallucinated references, incomplete generated code, and
dependency/API hallucinations.

The checked-in manifest intentionally mixes simple single-finding fixtures with
harder cases:

- cross-file repo-local phantom references
- range-scoped and file-scoped verification cases
- clean range scopes that must stay quiet even when later code is defective
- multiple hallucinated helper calls in one generated edit
- multiple unfinished generation patterns in one class/module
- compound edits that mix quality, API, and dependency hallucinations
- compound file-and-range scopes that must report only the selected API defect
- missing npm package and missing npm/Go versions
- nested workspace manifests with dependency hallucinations below the scan root
- clean dependency manifests for package/version precision
- installed-package API member and keyword-argument hallucinations
- local TypeScript named, default, type-only, namespace, re-export, and
  CommonJS API-surface hallucinations, plus a clean precision control
- diff-aware assertion weakening in tests
- JavaScript/TypeScript assertion broadening and retained-assertion controls
- explicit unsupported local-API outcomes for the other source languages
- exact finding-count expectations to catch noisy over-reporting
- a clean generated-code absence guard

Every checked-in case carries an explicit `language` label. Benchmark JSON
reports per-language case counts and language-label coverage under
`metadata.languages`.

Clean cases require a passing verification status, complete coverage, and
passing local-API checks for the source languages present. An empty result,
missing check or incomplete analysis cannot earn absence credit. Cases that
explicitly expect unsupported verification test the reporting contract: their
status stays `incomplete` and they are excluded from accuracy scores. JSON
reports scored and unscored case counts and whether a score is available.

The runner measures static AI-defect verification. Behavior comparison is
disabled unless a case explicitly sets `scan.behavior_comparison` to `true`;
modeled behavior changes are a separate result from a weakened assertion.
Unfinished-body fixtures declare concrete result contracts or explicit pending
implementation. Intentional optional no-op hooks remain clean controls.

Every case runs in a temporary project copy. This keeps the benchmark host's
Git history, configuration and CI workflows out of the result while retaining
files inside the case, including its own security findings. Cases that compare
changes receive the Git baseline declared in the manifest.
The temporary directory must be outside a Git repository; choose a different
`TMPDIR` if needed. Use a temporary directory without inherited Skylos
configuration; explicitly configured operator policy still applies.
Source symlinks remain symlinks, and preparation refuses to
seed baselines or dependency caches through symlinks.

Registry-dependent dependency cases seed Skylos' normal dependency-version cache
inside that copy, so benchmark results do not depend on live npm or Go proxy
availability.

Run it with:

```bash
python scripts/ai_code_defect_benchmark.py
```

Use `--json` for machine-readable output.
