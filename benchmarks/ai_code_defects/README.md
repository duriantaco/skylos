# AI-Code-Defect Benchmark

This benchmark tracks AI-specific code defects that `skylos verify` should catch
inside an agent loop: hallucinated references, incomplete generated code, and
dependency/API hallucinations.

The checked-in manifest intentionally mixes simple single-finding fixtures with
harder cases:

- cross-file repo-local phantom references
- multiple hallucinated helper calls in one generated edit
- multiple unfinished generation patterns in one class/module
- missing npm package and missing npm/Go versions
- installed-package API member hallucinations
- a clean generated-code absence guard

Registry-dependent dependency cases seed Skylos' normal dependency-version cache
inside a temporary fixture copy, so benchmark results do not depend on live npm
or Go proxy availability.

Run it with:

```bash
python scripts/ai_code_defect_benchmark.py
```

Use `--json` for machine-readable output.
