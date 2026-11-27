# PostgreSQL migration, query and script benchmark

We froze the SQL, rule IDs, original line numbers and expected parser outcomes
before the scans. We compared commit `55b4fd4e` with the expanded analyzer
through the public CLI. Each run used pglast 8.9 and one worker. The generated
suite enables quality and security checks. The upstream suite enables quality
only. No SQL or upstream test code ran.

| Frozen suite | Previous CLI | Expanded CLI |
| --- | --- | --- |
| 40 generated scripts | 2/26 expected findings, 29/31 quiet sites, 34 checked | 25/26 expected findings, 31/31 quiet sites, 37 checked |
| 21 upstream files and excerpts | 0/6 expected findings, 72/74 quiet sites, 16 checked | 6/6 expected findings, 74/74 quiet sites, all 21 checked |
| 1 independently pinned large dump | Unparsed | Checked |

These denominators include labels in unread files. The previous CLI left six
generated labels and two upstream labels unscored. The expanded CLI scored all
137 labels and produced zero findings outside their ranges. Its single miss
was a repeated `tab.id IS NULL` CASE arm. Without catalog information, a
qualified reference can invoke a volatile function on a composite value. The rule
takes the conservative path, and we kept the original positive label.

## What the inputs test

| Area | Generated positives | Generated quiet sites | Upstream positives | Upstream quiet sites |
| --- | ---: | ---: | ---: | ---: |
| Unreachable CTE chains (Q503) | 4 | 5 | 0 | 3 |
| NULL filters and COPY boundaries (Q504) | 3 | 1 | 0 | 2 |
| Concurrent index in an explicit transaction (Q506) | 3 | 2 | 3 | 12 |
| Invalid concurrent index removal (Q507) | 2 | 4 | 1 | 8 |
| Foreign-key column counts (Q508) | 2 | 2 | 2 | 43 |
| Unreachable CASE arms (Q509) | 3 | 3 | 0 | 6 |
| COUNT with a non-null CASE result on every branch (Q510) | 2 | 4 | 0 | 0 |
| PUBLIC schema creation, login with BYPASSRLS, PUBLIC table writes (D418–D420) | 7 | 10 | 0 | 0 |

PostgreSQL's regression suite deliberately puts concurrent index commands inside
explicit transactions and attempts to drop two indexes concurrently. Its expected
output records the database errors. DuckDB's regression suite includes two
PostgreSQL-compatible table definitions with different numbers of child and
parent columns. Four neighboring examples have matching column counts, including
three with unrelated errors. The six upstream positives are deliberate regression
tests. They establish detection of these particular conditions. [PostgreSQL SQL](https://github.com/postgres/postgres/blob/d7ec59a63d745ba74fba0e280bbf85dc6d1caa3e/src/test/regress/sql/create_index.sql#L483-L574) · [PostgreSQL expected output](https://github.com/postgres/postgres/blob/d7ec59a63d745ba74fba0e280bbf85dc6d1caa3e/src/test/regress/expected/create_index.out#L1412-L1508) · [DuckDB foreign-key fixtures](https://github.com/duckdb/duckdb/blob/0b83e5d2f68bc02dfefde74b846bd039f078affa/test/sql/constraints/foreignkey/test_foreignkey.test#L11-L33)

The upstream inputs also cover Pagila's full schema with 37 labeled foreign keys,
its temporal migration, a partition maintenance setup and two text COPY excerpts.
The first candidate checked 20 of 21 inputs and skipped the full
13,074,106-byte Pagila data dump. After that result, the scanner gained a
16 MB limit for text dumps while retaining its 4 MB SQL budget. It now checks
the whole dump. The frozen source manifest still expects the old skip and the
runner records this coverage change. The generated parse controls cover a
truncated COPY, CSV input and mismatched dump guards. Privilege rules and
conditional counts have generated positives only. [Pagila database fixtures](https://github.com/devrimgunduz/pagila/tree/6ea53f812254c91a602f61c0ef62beca3fa676b1)

We preserved the Pagila result as a retest of a known gap. Before running the
revised parser, we separately pinned Neon's 12,962,616-byte Lego dump with the
expected outcome of `checked`. Its eight text COPY sections have exact terminators.
The headers, framing and remaining SQL total 7,797 bytes. The revised CLI checked
the complete dump with zero quality findings. This holdout measures file coverage
only. [Frozen parser case](large-dump.json) · [Neon source](https://github.com/neondatabase/postgres-sample-dbs/blob/b54cb67534bf20775803b181b7a1c6f573422161/lego.sql)

## Comparison tools

On the same seven transaction inputs, Skylos and Squawk 2.74.0 each caught all
six concurrent-index positives at their expected lines and stayed quiet at all
14 control sites. Squawk used PostgreSQL 18 semantics and explicit transactions.
We compared its `ban-concurrent-index-creation-in-transaction` rule. [Squawk rule](https://squawkhq.com/docs/ban-concurrent-index-creation-in-transaction)

SQLFluff 4.5.0 scored ST03 and CV05 on the six generated files carrying a CTE
or ordinary NULL-comparison label. It parsed three files, caught all three
scored NULL comparisons and stayed quiet at the three scored control sites.
The three CTE files using PostgreSQL's `TABLE` shorthand returned parser
errors, leaving seven CTE labels unscored. It also emitted one partial CTE
finding in an unparsed file. [SQLFluff ST03](https://docs.sqlfluff.com/en/stable/reference/rules/structure.html#st03-structure-unused-cte) · [SQLFluff CV05](https://docs.sqlfluff.com/en/stable/reference/rules/convention.html#cv05-convention-is-null)

## Earlier frozen suites

The original 27 generated fixtures retained all 14 expected findings and the
malformed-input result. The original 31 source files or excerpts retained
all 25 labeled results and 28 checked files. The previous expansion's 25
generated inputs retained all eight expected findings and all 15 quiet sites.
Its seven-source suite retained one finding and 17 quiet sites, and now checks
all seven inputs. The newly readable file is PostgreSQL's full
`expressions.sql`, which uses psql metadata commands. The frozen expectation
still records its earlier unparsed status. The eight newly introduced rule IDs
emitted zero additional lines on these four historical suites.

## Replay

Run from the repository root with the `postgres` extra installed. Install
Squawk 2.74.0 and SQLFluff 4.5.0 to repeat the optional comparisons. This
runner verifies the manifests and cached upstream bytes before analysis.

```sh
out=$(mktemp -d)
runner=benchmarks/postgresql/holdout/run.py
python "$runner" --manifest benchmarks/postgresql/depth/generated.json --danger \
  --squawk squawk --sqlfluff sqlfluff --cache "$out/cache" --output "$out/generated.json"
python "$runner" --manifest benchmarks/postgresql/depth/sources.json \
  --squawk squawk --cache "$out/cache" --output "$out/sources.json"
python "$runner" --manifest benchmarks/postgresql/depth/large-dump.json \
  --cache "$out/cache" --output "$out/large-dump.json"
```

To compare builds, supply `--skylos /absolute/path/to/skylos` from a separate
environment for each revision. Each output retains per-rule counts, unexpected
lines, and cases the tool could not read. The
[measured results](results.json) record both revisions, tool outcomes and file
fingerprints. The [generated labels](generated.json) and [source manifest](sources.json)
contain the frozen input definitions.
