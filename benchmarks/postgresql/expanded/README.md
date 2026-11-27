# PostgreSQL coverage expansion

We compared the public Skylos CLI at `41b75e08` with the expanded PostgreSQL
checks. Each run used Python 3.13.18, pglast 8.9 and one worker. We fixed the
inputs, line labels and expected coverage before scanning. The [measured
results](results.json) include the manifest digests and the two scanner source
digests for the candidate.

| Frozen cases | Before | After |
| --- | --- | --- |
| Required `NOT IN` filter containing a literal NULL | 0/5 generated positives | 5/5 at the expected line |
| Definer procedure missing a fixed path | 0/2 generated positives | 2/2 at the expected line |
| Existing NULL comparison after a connection directive | File unparsed | Caught at original line 4 |
| Quiet generated controls | 14 quiet, 1 unscored | All 15 quiet |
| Fresh upstream SQL excerpts | 0/1 positive and 17/17 quiet | 1/1 positive and 17/17 quiet |
| Original 31 source scripts or excerpts | 27 checked | 28 checked, all 25 prior labels preserved |

The positive from an upstream project is a query from SQLite's regression suite.
It selects integer keys using a PostgreSQL-compatible `NOT IN (3, null, 8)`
filter. The test records an empty result. Its neighboring positive `IN` test
keeps two rows. We scored both original statements without editing or executing
them. The positive demonstrates detection on a deliberate test query. The
sample has no confirmed production defect. [SQLite source](https://github.com/sqlite/sqlite/blob/bebe2d8be8acfd02592c4972f4ba32c3b4e4a33f/test/in.test#L682-L691)

The PostgreSQL regression tests supply eight projections and four filters using
explicit casts to a custom type with its own comparison operators. Skylos stayed
quiet on all twelve. The full PostgreSQL script remained unparsed because it
uses psql's `\d+` command. Together, the fresh upstream sources provided six
checked excerpts and one unparsed full script. [PostgreSQL source](https://github.com/postgres/postgres/blob/d7ec59a63d745ba74fba0e280bbf85dc6d1caa3e/src/test/regress/sql/expressions.sql)

The new generated suite checked 23 of 25 files. The two expected unparsed files
use an include directive and a connection command inside an unfinished query.
On the original source holdout, the full Chinook PostgreSQL script changed from
unparsed to checked. The intentional syntax error, the MySQL script and the SQL
Server script accounted for the three remaining unchecked files. The checked
files produced no additional `SKY-Q505` findings.

The original 27 generated cases kept their 14 findings at the expected lines
in both CLI builds. SQLFluff 4.5.0 again caught 4/5 unused CTEs and 5/6 NULL
comparisons. eslint-plugin-postgresql 0.31.0 again caught 2/3 privileged
functions. On the five **new procedure** cases, its rule flagged one of the two
positive procedures on the first line of the declaration. Skylos flagged both
on the `SECURITY DEFINER` line. Both tools stayed quiet on all three controls.
The procedure results use generated SQL. The external comparisons cover the
named rules only.

## Replay

Run these commands at the repository root with a Skylos executable that has the
postgres extra. The runner verifies SHA-256 digests for the frozen manifests
and for the upstream data it stores in the cache. Only the generated suite enables danger checks.
Each JSON output includes per-rule counts, unexpected lines, unscored labels and
coverage per input.

```sh
out=$(mktemp -d)
runner=benchmarks/postgresql/holdout/run.py
cases=benchmarks/postgresql/expanded
python "$runner" --manifest "$cases/generated.json" --danger \
  --cache "$out/cache" --output "$out/generated.json"
python "$runner" --manifest "$cases/sources.json" \
  --cache "$out/cache" --output "$out/sources.json"
python "$runner" --cache "$out/cache" --output "$out/original-holdout.json"
```

For the before/after comparison, run the same commands twice, with separate
output directories and `--skylos /path/to/venv/bin/skylos` for each build.
Install both builds with pglast 8.9. The [original benchmark](../README.md)
includes setup and replay commands for SQLFluff and ESLint. To score the new
procedures with the same plugin installation, run the following command.

```sh
python benchmarks/postgresql/compare.py eslint --procedures \
  --binary "$bench_dir/node/node_modules/.bin/eslint"
```
