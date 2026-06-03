# AI-Code-Defect Benchmark

This benchmark tracks AI-specific code defects that `skylos verify` should catch
inside an agent loop: hallucinated references, incomplete generated code, and
dependency/API hallucinations.

Run it with:

```bash
python scripts/ai_code_defect_benchmark.py
```

Use `--json` for machine-readable output.
