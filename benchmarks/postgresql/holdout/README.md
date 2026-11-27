# PostgreSQL source holdout

We froze the file list, source digests and 25 expected results before the first
scan. All 16 source files are pinned to commits and Git blob IDs. Their SHA-256
digests are verified on every replay. The manifest includes each selected line
range and the reason for its label. Its SHA-256 digest is
`a04c1e0542837b8f1c2eee00e89c5d23870c4c85acd7db3acb2128d096b8f11f`.

| Tool | Unused read-only CTE | NULL filter | Coverage |
| --- | --- | --- | --- |
| Skylos with pglast 8.9 | 1 caught, 14 correctly quiet | 10 correctly quiet | All 25 labels scored |
| SQLFluff 4.5.0, ST03 and CV05 | 1 missed, 13 correctly quiet, 1 unscored | 10 correctly quiet | 24 of 25 labels scored |

The only positive comes from PostgreSQL's regression suite. An INSERT target
has the same name as a read-only CTE, but PostgreSQL resolves the target as a
physical table. The CTE is unused. The upstream authors deliberately omitted
the physical table to check the resulting catalog error. This exercises name
resolution and does not establish the frequency of this mistake in applications.
The suite has no positive NULL filter label. SQLFluff could not parse the MERGE
sample. Neither tool produced a false alert at the scored sites.

Skylos checked 27 of 31 full scripts or original-source excerpts through its
public CLI, including all 12 River migrations. Two Chinook scripts matched
unsupported MySQL and SQL Server dialects. Two PostgreSQL inputs were unparsed.
One is an intentional syntax error in PostgreSQL's tests. The full Chinook
script contains a psql client command (`\c`) at line 28. Its plain SQL table
definition was also scored as a separate, unchanged excerpt. SQLFluff was
run on the 22 PostgreSQL inputs containing hand-labeled sites. It parsed 21,
reported one parse failure and skipped none. Neither tool timed out.

## Replay

Use a Skylos checkout with the postgres extra installed and SQLFluff 4.5.0
available on PATH. The runner downloads SQL sources into the chosen cache
on first use. It creates a temporary directory with a dialect setting for each
folder, runs the Skylos quality checks, and optionally runs SQLFluff with raw
templates and large-file skipping disabled. It only reads the SQL as text.

```sh
python benchmarks/postgresql/holdout/run.py \
  --cache /tmp/skylos-postgres-holdout-sources \
  --sqlfluff sqlfluff \
  --output /tmp/skylos-postgres-holdout-results.json
```

The bundled results include counts per rule, findings outside labeled sites,
parse failures and each file's coverage status.

The corpus uses [PostgreSQL 17.0 regression queries](https://github.com/postgres/postgres/blob/d7ec59a63d745ba74fba0e280bbf85dc6d1caa3e/src/test/regress/sql/with.sql),
[River v0.20.0 migrations](https://github.com/riverqueue/river/tree/5fedf932b27af30c74f5ade32e2fcc616721fc61/riverdriver/riverpgxv5/migration/main)
and [Chinook v1.4.5 database scripts](https://github.com/lerocha/chinook-database/tree/4a944a942426e1f3263fe539155fb7ef92b04b4a/ChinookDatabase/DataSources).
