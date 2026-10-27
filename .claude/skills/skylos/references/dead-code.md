# Skylos Dead-Code Reference

Use this reference for unused-code findings, false-positive reduction, liveness
analysis, framework entrypoints, traces, and benchmark comparisons.

## Default Commands

```bash
skylos . --format json
skylos . --confidence 80 --format json
skylos . --diff origin/main --format json
python scripts/dead_code_benchmark.py
python scripts/dead_code_compare_scanners.py
```

Use `--confidence` to tune dead-code reporting. Higher confidence reduces
candidate volume. Lower confidence surfaces riskier candidates. Confidence is
capped by the weakest evidence (`skylos/deadcode/confidence.py`, table in
`docs/cli-output.md`): imports/private symbols 100, public Python names 90,
exported-but-unimported 85, public methods/class attributes and unimported
files 80, files imported only by unused files 65, default exports 60,
unused parameters 50 (hidden by default; `--confidence 50`), Rust
(experimental) 40, so parameters and Rust are hidden at the default threshold.

## False-Positive Reduction Ladder

Prefer evidence in this order:

1. Static symbol references and imports.
2. Framework entrypoints and decorators.
3. Package entrypoints and configuration files.
4. Tests and fixtures that legitimately call the symbol.
5. Runtime traces, only when executing the target code is acceptable.
6. Suppressions, whitelist, or baseline for intentionally dynamic patterns.

Do not treat absence of a simple text reference as proof of dead code when the
framework commonly resolves names dynamically.

## Framework Areas

Skylos has framework-aware behavior for patterns such as:

- FastAPI, Flask, and Django routes.
- pytest tests, fixtures, and hooks.
- SQLAlchemy models and metadata.
- Next.js and React entrypoints, including metadata routes (`robots`,
  `sitemap`, `opengraph-image`, ...) gated on a detected Next.js project.
- Tool config files (`next.config.*`, `postcss.config.*`, any
  `<tool>.config.*` next to a `package.json`, `turbo/generators/config.*`) and
  their exports.
- Expo Router routes, React Email templates, Jest `__mocks__`, esbuild entry
  points (including build scripts under excluded folders).
- Blade template references, FQN class strings in PHP, Laravel seeders.
- Flask app factories, call-registered callbacks and their signatures;
  SQLAlchemy/SQLModel declarative fields.
- Django/Wagtail (`skylos/analysis/documented_conventions.py`): `*Field(...)`
  and relation attributes, `Meta`, Wagtail Page/viewset/task attributes and
  hook signatures, CBV/system-check/admin hook signatures, models in `models`
  modules, `register*` class decorators, format files. Template lookups stay
  proof-based (`django_template_liveness.py`); do not add name-only matching.
- Laravel convention classes, each with the evidence Laravel's discovery
  needs (`Command` base, typed listener event, existing model for factories
  and policies), plus Livewire and Blade components, migrations,
  `DatabaseSeeder` and `laravel-vite-plugin` inputs.
- PHP type-position and PHPDoc references to imported classes.
- package entrypoints and plugin hooks.

The full convention table is in `dictionary.md` under "Framework entrypoints".

When adding support, include a minimal positive fixture and a negative fixture
so the analyzer does not simply whitelist too much.

## Trace Mode Caution

`skylos . --trace` and coverage-style checks can execute project code. Only use
them on trusted repositories or when the user explicitly asks for runtime
evidence. Do not use trace mode as the default answer for untrusted PR review.

## Suppression Options

- `# skylos: ignore`: suppress a finding on one line;
  `# skylos: ignore[SKY-D211] reason` suppresses only that rule.
- A bare `# noqa` hides dead-code, quality and LOW/MEDIUM findings, but
  not HIGH/CRITICAL security findings (`SKY-D*`, `SKY-S*`); those stay
  reported with `bare_noqa_ignored: true`. `# noqa: <ruff code>` never
  hides Skylos security/quality findings (F401/F841 only mark the
  matching unused import/variable).
- `# skylos: ignore-start` / `# skylos: ignore-end`: suppress a block.
- `ignore = ["SKY-XXX"]` in `[tool.skylos]`: suppress a rule project-wide.
- `skylos whitelist <pattern>`: manage whitelisted symbols.
  `[tool.skylos.whitelist.temporary]` entries take `expires = "YYYY-MM-DD"`
  (a TOML date works too); once expired, or with an unreadable date, they
  hide nothing and the scan prints a warning naming the entry.
- `skylos baseline .`: store current findings as accepted baseline.

Prefer analyzer improvements or precise suppressions over broad project-wide
ignores.

## Benchmark Expectations

For benchmark changes:

1. Use fixtures where ground truth is clear but not encoded in filenames.
2. Include framework and dynamic-reference patterns that static-only scanners
   commonly struggle with.
3. Compare Skylos against Vulture when relevant.
4. Report score, timing, and examples of true positives and false positives.
5. Keep public benchmark fixtures understandable and non-secret.

Useful files:

- `benchmarks/`
- `corpus/fixtures/`
- `scripts/dead_code_benchmark.py`
- `scripts/dead_code_compare_scanners.py`
- `test/test_dead_code*.py`
- `test/test_framework_aware.py`
