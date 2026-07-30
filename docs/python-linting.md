# Python Linting With Ruff

Skylos can run [Ruff](https://docs.astral.sh/ruff/) through the same `skylos`
CLI used for repository analysis. Ruff remains an optional dependency, so the
core Skylos install stays focused on its multi-language analyzers.

## Install

```bash
pip install "skylos[lint]"
```

The `all` extra also includes lint support:

```bash
pip install "skylos[all]"
```

## Run

Lint the current directory:

```bash
skylos lint
```

Pass paths and Ruff `check` options after `lint`:

```bash
skylos lint src test
skylos lint src --select E,F,I
skylos lint . --fix
skylos lint . --diff
```

With no arguments, Skylos invokes `ruff check .`. Other than the top-level
`-h` / `--help` flags, which display Skylos wrapper help, it forwards the
arguments unchanged to `ruff check` using the Python environment that runs
Skylos. It does not use a shell.

## Configuration And Exit Codes

Ruff continues to discover configuration from `pyproject.toml`, `ruff.toml`,
or `.ruff.toml`. Skylos does not translate Ruff rules into `SKY-*` findings or
merge them into Skylos reports.

The command preserves Ruff's output and exit code:

| Exit code | Meaning |
|:---|:---|
| `0` | No lint violations remain |
| `1` | Lint violations were found |
| `2` | Ruff could not run because of invalid options, configuration, or another error |

This means existing CI checks can replace `ruff check ...` with
`skylos lint ...` without changing their pass/fail behavior.

## Relationship To Skylos Analysis

`skylos lint` is a convenience entry point for Ruff's fast Python lint rules.
It is separate from `skylos .` and `skylos . -a`, which cover Skylos dead
code, security, secrets, dependency, quality, and AI-defect analysis across
multiple languages. Installing the `lint` extra does not make Ruff run during
a normal Skylos scan.

For all Ruff options and configuration behavior, see the
[Ruff linter documentation](https://docs.astral.sh/ruff/linter/) and
[Ruff configuration documentation](https://docs.astral.sh/ruff/configuration/).
