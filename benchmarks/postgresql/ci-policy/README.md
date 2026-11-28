# PostgreSQL CI policy replay

The 24 cases in `cases.json` were labeled before implementing the CI changes.
Five cover reporting, 17 cover production policy decisions, and two check that
unrelated security and quality findings still produce annotations. The SHA-256
of the frozen file is
`803138622957edc65d756b46a2156a16169dc22ea70a075060d809a2aec08d2e`.

Across the original policy cases and both supplemental suites, the final
gate blocked all 25 changes labeled to fail and allowed all 26 labeled to
pass. That gives zero missed blocks and zero false blocks in these fixtures.
Two of the required blocks were for missing analysis coverage. The other
seven original cases measure GitHub feedback separately. These counts do
not estimate the share of real vulnerabilities found in deployed databases.

Each SQL case creates a temporary Git repository with a base commit and a head
commit. The runner uses the scanner's CLI, captures its Actions annotations,
and intercepts the GitHub CLI to record the PR summary and inline comment
payloads locally. The scanner reads the fixture SQL as text.
Raw finding counts refer to the SQL migration in each reporting case.
Repository hygiene findings on the scaffold are outside those counts.

| Expected behavior | Baseline matches | Candidate matches |
| --- | ---: | ---: |
| Reporting | 3/5 | 5/5 |
| Allow a change | 9/9 | 9/9 |
| Block a change | 0/8 | 8/8 |
| Preserve unrelated annotations | 2/2 | 2/2 |

The baseline is `aa521a20` using its existing `cicd gate --advisory`. The
candidate uses `cicd postgres-check` with `db/production` explicitly protected
in the base revision. These count policy decisions. A failed coverage check
means a changed protected file could not be checked. A prohibited grant
means the migration conflicts with the configured repository policy. Confirming
an exploitable vulnerability requires additional deployment context.

Both runs retained all 14 labeled SQL security findings in JSON. Twelve grants
in one migration produced one Actions notice and one PR summary group.
An intentional backup role with `BYPASSRLS` also stayed visible as one review
group. Two SQL quality findings moved out of inline comments and annotations.
The candidate blocked two incomplete checks and six disallowed grant changes.
All nine expected passes remained green, including an existing grant on a moved
line and an exact approved grant. The scores measure these labeled CI scenarios.
Vulnerability recall across deployed PostgreSQL applications remains unmeasured.

A follow-up review caught two false blocks outside the frozen suite. An
unrelated timeout setting and removing a table from an existing grant could
both cause a new warning. The dedicated policy tests now cover those cases
and check that adding a table still fails. They are separate from the 24
original labels.

## Replay

Use Python with Skylos dependencies and `pglast==8.9`. From the project root,
run the candidate and optionally compare the original code.

```bash
python benchmarks/postgresql/ci-policy/run.py --scanner-root . --output /tmp/pg-ci-candidate.json
baseline=$(mktemp -d)
git archive aa521a20 | tar -xf - -C "$baseline"
python benchmarks/postgresql/ci-policy/run.py --scanner-root "$baseline" --legacy-advisory --output /tmp/pg-ci-baseline.json
```

The checked-in `baseline.json` and `candidate.json` record every decision and
reporting count. The runner also records each PR summary's grouped security
rule IDs. The two unrelated controls exercise the annotation renderer directly
with a report containing a non-SQL finding.

## Pinned migration replay

We labeled [19 files from the existing source corpus](pinned-files.json) for parser coverage
before running the production check. All 18 valid files passed when first
added and after a comment-only edit. The PostgreSQL regression script
contains deliberate syntax errors and failed on line 1674. These files
measure noise and coverage. They contain no labeled prohibited table write.

| Project | Pinned commit | Files |
| --- | --- | ---: |
| riverqueue/river | `5fedf932b27af30c74f5ade32e2fcc616721fc61` | 12 |
| devrimgunduz/pagila | `6ea53f812254c91a602f61c0ef62beca3fa676b1` | 4 |
| neondatabase/postgres-sample-dbs | `b54cb67534bf20775803b181b7a1c6f573422161` | 1 |
| lerocha/chinook-database | `4a944a942426e1f3263fe539155fb7ef92b04b4a` | 1 |
| postgres/postgres | `d7ec59a63d745ba74fba0e280bbf85dc6d1caa3e` | 1 |

## Runtime role controls

`role-access.json` records six expectations for a disposable two-tenant
table. Both readers saw only their own tenant. The read-only tenant could
not insert. The writer could insert its own row and was denied for the other
tenant. A backup role with SELECT and BYPASSRLS saw all three rows. All six
matched on PostgreSQL 19.0 through PGlite 0.6.1. This exercises the fixture's
permissions independently of static analysis. Use the application's real
roles and migrations to measure its own access.

```bash
role_env=$(mktemp -d)
cp benchmarks/postgresql/ci-policy/{role-access.json,transactions.json,check-role-access.mjs} "$role_env/"
npm install --prefix "$role_env" --ignore-scripts --no-audit --no-fund @electric-sql/pglite@0.6.1
node "$role_env/check-role-access.mjs"
```

## Transactions and revocations

[The 18 transaction cases](transactions.json) were labeled after review exposed
two places where the policy treated an unchanged grant as new. The labels were
frozen before changing the comparison. They cover committed grants, rollbacks,
savepoints, unrelated revocations and restoring previously revoked write
access to individual privileges, tables and columns. Their SHA-256 is
`ff043f70fdfe21265656fa16ec193c78efa3049d0b2997f3935cef3f669fe993`.

PostgreSQL 19.0 through PGlite 0.6.1 confirmed all 18 expectations by comparing
the write privileges of a role with no direct grants. The script above submits
one SQL statement at a time, so each statement outside an explicit transaction
commits separately. A client that submits multiple statements in a single
simple-query message can give them a different implicit transaction scope.

The [pre-fix CLI](transactions-before.json) matched 7 of 18 decisions. The
[updated CLI](transactions-after.json) matched all 18. The pre-fix version was
an intermediate implementation of the production policy. The frozen 24-case
benchmark above uses the earlier advisory gate as its baseline. For this
replay, the runner creates a temporary Git base and head for each case, invokes
`cicd postgres-check`, and checks the exit status, violation count and file
coverage. It records the SHA-256 of the grant comparison and policy modules.

```bash
python benchmarks/postgresql/ci-policy/run_transactions.py --scanner-root . --output /tmp/pg-transaction-checks.json
```

## Regrouping an existing grant

[Sixteen additional labels](regroup.json) cover changes that split one grant
into several statements or combine several into one. The labels were frozen
before implementing this comparison (SHA-256
`d6079aea376fd551a103a0a1d27ebadba70490befc15dcaf878b8411aead20f2`).
They check table and column names together with their individual privileges,
repeated statements, and the path and statement covered by an exact exception.
Existing permission on table A cannot authorize the same privilege on table B.
An extra copy of an explicit grant needs its own approval under this policy.

The [previous CLI](regroup-before.json) matched 9 of 16 decisions. The
[updated CLI](regroup-after.json) matched all 16. These are repository policy
decisions, including deliberate checks on statement count and exact exceptions.

```bash
python benchmarks/postgresql/ci-policy/run_transactions.py --suite regroup --scanner-root . --output /tmp/pg-grant-regroup.json
```
