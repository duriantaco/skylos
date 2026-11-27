# PostgreSQL benchmark

The [migration, query and script benchmark](depth/README.md) covers eight additional
rules, CTE chains and text dumps. It compares the CLI with Squawk on shared
transaction checks and includes pinned PostgreSQL, DuckDB and Pagila source.

The [coverage expansion benchmark](expanded/README.md) compares the original
CLI with the added checks on new labeled cases and replays the original source
holdout.

The 27 hand-labeled inputs in `cases.json` cover three checks in standalone
PostgreSQL scripts. Each valid input has an exhaustive list of expected rule
and line pairs. The intentionally incomplete final input checks parse-error
reporting. The labels and inputs were frozen before any scanner ran. Their
SHA-256 is `5ab9f1f3fb520cc4cc68f96c0b3910c93bb2aa4ebaa18a88b4175920ab05b87b`.

## Original three-check results

The 2026-11-27 run used pglast 8.9, SQLFluff 4.5.0 and eslint-plugin-postgresql
0.31.0 with ESLint 10.15.0. Each tool accepted all 26 valid inputs and reported
the intentionally malformed input. Each tool had zero unexpected finding lines.

| Check | Skylos catches | Reference catches | Reference rule |
| --- | ---: | ---: | --- |
| Unused read-only CTE | 5/5 | 4/5 | [SQLFluff ST03](https://docs.sqlfluff.com/en/stable/reference/rules/structure.html#st03-structure-unused-cte) |
| Filter comparing a value to NULL | 6/6 | 5/6 | [SQLFluff CV05](https://docs.sqlfluff.com/en/stable/reference/rules/convention.html#cv05-convention-is-null) |
| Privileged function missing a fixed search path | 3/3 | 2/3 | [ESLint PostgreSQL rule](https://baseballyama.github.io/eslint-plugin-postgresql/rules/no-security-definer-without-search-path/) |

The three disagreements were reproducible on individual examples. SQLFluff
missed an unused outer CTE shadowed by an inner CTE and a comparison with
`NULL` on the left. ESLint missed the missing search path when the function
set a different option, `statement_timeout`. Both query tools stayed quiet on
the two unreferenced CTEs that write rows.

These results describe small generated examples with known expected findings.
The security examples use constant-returning functions and measure the missing
configuration. A CLI replay with one and three workers returned the same 14
findings at their expected lines. The [real-project holdout](holdout/README.md)
covers queries, migrations and dialect selection.

## Reproduce

Run these commands at the repository root in an environment with the Skylos
development dependencies and pglast 8.9. The two external tools are installed
in temporary environments. No SQL runs and no database connection is needed.

```bash
bench_dir=$(mktemp -d)
python -m venv "$bench_dir/python"
"$bench_dir/python/bin/python" -m pip install sqlfluff==4.5.0
npm install --prefix "$bench_dir/node" --ignore-scripts --no-audit --no-fund eslint@10.15.0 eslint-plugin-postgresql@0.31.0
python benchmarks/postgresql/compare.py skylos
python benchmarks/postgresql/compare.py sqlfluff --binary "$bench_dir/python/bin/sqlfluff"
python benchmarks/postgresql/compare.py eslint --binary "$bench_dir/node/node_modules/.bin/eslint"
```

The runner checks the frozen hash and writes each case to a numbered filename
for the external tools. Skylos receives the same filename and text through its
PostgreSQL scanner entry point. The JSON report includes each missed or
unexpected line, valid inputs the tool could not read, and the parse-control
outcome. Unparsed valid files are counted separately and excluded from
per-rule scores.
