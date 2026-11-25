# Linting with Skylos

## Architecture linting

```bash
skylos lint
```

Skylos checks the current directory with local static analysis. The command
comes with the core install and needs no model or account. Pass a project
directory to check another location.

It reports module import cycles in Python, TypeScript, and JavaScript
(`SKY-CIRC`), cycles between sibling Python packages (`SKY-Q807`), and
configured import layer violations in all three languages (`SKY-Q805`).
Package cycles use resolved top-level imports between packages with
`__init__.py`. Cycle findings list the contributing import sites. Exit codes
are `0` for clean, `1` for findings, and `2` for an error or incomplete analysis.

To include sibling-package cycles in ordinary quality scans and the
cleanup queue, set `check_package_cycles = true` under
`[tool.skylos.architecture]` in `pyproject.toml`. [Cleanup](./cleanup.md)

### In CI

Use `--diff REF` to check changed import lines for cycles and changed source
modules for layer violations. Use `--format json` for structured evidence.

```bash
skylos lint --diff origin/main
skylos lint --format json
```

To record existing architecture debt and check for new findings, run the
baseline command first.

```bash
skylos baseline . --architecture
skylos lint --baseline
```

`skylos baseline . --architecture` replaces `.skylos/baseline.json` with the
architecture findings from the selected directory. Use the same directory
for both commands. Refresh older baselines to record layer violations by
dependency edge.

## Existing Ruff checks

Run Ruff directly with `ruff check .` and pass any existing Ruff options to
`ruff check`.
