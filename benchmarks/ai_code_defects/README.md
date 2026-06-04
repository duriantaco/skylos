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
- exact finding-count expectations to catch noisy over-reporting
- a clean generated-code absence guard

Registry-dependent dependency cases seed Skylos' normal dependency-version cache
inside a temporary fixture copy, so benchmark results do not depend on live npm
or Go proxy availability.

Run it with:

```bash
python scripts/ai_code_defect_benchmark.py
```

Use `--json` for machine-readable output.
