# Languages Skylos reads

Depth differs by language. Python, TypeScript/JavaScript and Java get the
most: dead code, security and quality, with framework conventions. Other
languages get a subset, as this table shows. Each rule page also lists the
languages that rule covers.

| Language | Files | Dead code | Security | Quality | Read with |
|:--|:--|:--|:--|:--|:--|
| Python | `.py .pyi .pyw` | Yes | Yes | Yes | Python's `ast` |
| TypeScript, JavaScript | `.ts .tsx .js .jsx .mts .cts .mjs .cjs` | Yes | Yes | Yes | tree-sitter |
| Java | `.java` | Yes | Yes | Yes | tree-sitter |
| Go | `.go` | Yes | Partial | Partial | the `skylos-go` engine; tree-sitter for quality |
| PHP | `.php`, Drupal `.module .install .inc .theme .profile .engine` | Yes | Yes | No | tree-sitter |
| Rust | `.rs` | Experimental | Partial | Partial | tree-sitter |
| Ruby | `.rb` | Partial | Partial | No | tree-sitter |
| Dart | `.dart` | Yes | Partial | No | tree-sitter, with the `skylos[dart]` extra |
| C# | `.cs` | Partial | Partial | Partial | Skylos's own lexer |
| C++ | `.cpp .cc .cxx`, headers for references | Partial | No | No | tree-sitter |
| Kotlin | `.kt .kts` | Partial | Partial | No | Skylos's own lexer |
| Swift | `.swift` | Partial | No | No | tree-sitter |
| PostgreSQL | `.sql` | Unused CTE chains and unreachable CASE arms | Grants, login roles, routine search paths | Query logic and migration DDL | PostgreSQL parser via `skylos[postgres]` |
| Shell | `.sh .bash .zsh .ksh .bats` | No | Partial | No | Skylos's own reader |

Secrets are checked in the supported source extensions listed in the secrets guide (except Drupal's `.module`-style
PHP files) and in configuration,
`.env`, Dockerfile, Terraform, HTML and key files (see "Secret detection").
CI workflows, agent settings, Docker Compose, systemd, Kubernetes and
Terraform files have their own rules.

## Where "Partial" comes from

- **Go** needs the `skylos-go` engine. It ships in the platform wheels for
  Linux, macOS and Windows; elsewhere `skylos doctor` prints the command that
  builds it. Without it, Go files are listed as not analysed and only the Go
  quality checks run.
- **Rust** dead code is experimental: its findings are capped at confidence
  40, below the default threshold of 60, so they appear only with
  `--confidence 40` or lower.
- **Kotlin** dead code reports only `private` declarations and unused
  imports; every non-private declaration counts as used.
- **C#** security checks follow ASP.NET Core Minimal API registrations to
  inline handlers and uniquely identified static handlers in another file
  of the same SDK project. Scan the project directory so Skylos sees the
  registration and the handler. The reported line is the call that uses
  request data, such as an HTTP client call. Versioned route groups are
  supported when the project references `Asp.Versioning.Http` directly.
  Ambiguous overloads, conditional registrations and custom build inputs
  limit matching.
- **C++** dead code reports only unused file-local functions.
- **Dart** needs `pip install "skylos[dart]"`, which compiles a parser and so
  needs a C compiler. Without it, `.dart` files are listed as not analysed.

## Checking PostgreSQL scripts

Install `pip install "skylos[postgres]"` and run
`skylos . --quality --danger --format json` from the project root. For a
PostgreSQL folder, set the following in its `skylos.toml`:

```toml
[sql]
dialect = "postgresql"
```

In `pyproject.toml`, use `[tool.skylos.sql]`. A Prisma
`migrations/migration_lock.toml` can also establish the provider for that
directory and its children. Give each database's folder its own setting
in a mixed repository. An unknown dialect, an unsupported dialect or
conflicting settings appear in `analysis_summary.sql_analysis`. This
section also records parse failures and missing parser installations.

| Flag | Finding | Example to review |
| --- | --- | --- |
| `--quality` | SKY-Q503 | An unused read-only SELECT CTE or a chain feeding only unused CTEs |
| `--quality` | SKY-Q504 | `WHERE deleted_at = NULL` |
| `--quality` | SKY-Q505 | `WHERE status NOT IN ('closed', NULL)` |
| `--quality` | SKY-Q506 | Creating or dropping a concurrent index inside an explicit transaction |
| `--quality` | SKY-Q507 | A concurrent index drop with multiple index names or CASCADE |
| `--quality` | SKY-Q508 | An explicit foreign key with different column counts on each side |
| `--quality` | SKY-Q509 | An unreachable CASE arm |
| `--quality` | SKY-Q510 | COUNT of a CASE whose branches and ELSE all return non-null literals |
| `--danger` | SKY-D417 | A SECURITY DEFINER function or procedure without a fixed local search path |
| `--danger` | SKY-D418 | A schema CREATE grant to PUBLIC |
| `--danger` | SKY-D419 | A login role configured with BYPASSRLS |
| `--danger` | SKY-D420 | A table write grant to PUBLIC, including default privileges |

If the query should keep orders with a known status other than 'closed',
use `WHERE status <> 'closed'`. To also keep orders whose status is missing,
use `WHERE status IS DISTINCT FROM 'closed'`. With ordinary equality, the
original `NOT IN` filter keeps neither group.

Skylos can read a script that switches databases with a literal `\c dbname`
or `\connect dbname` on its own line between complete statements. It
parses each SQL session locally. It reads text COPY input through a line
containing only `\.`, paired dump guards (`\restrict` and `\unrestrict`),
and standalone `\d`, `\d+`, `\dt` and `\dt+` commands with simple names.
COPY rows are data. Includes, conditionals, CSV or binary COPY input and
incomplete blocks leave the file unchecked. A text dump can be up to
16,000,000 bytes provided the SQL remaining after COPY data is removed fits
the 4,000,000-byte parser limit. Look at each file's `status`
in the SQL analysis summary. An `unparsed` entry also gives a `reason`.

The eight quality checks stay in the full report. GitHub groups the four
security checks by rule and keeps individual locations in the report.
All twelve findings are advisory in the normal findings gate. Strict coverage
can still fail when a file could not be checked.

### Require checks for production migrations

In the repository's root `pyproject.toml`, name the directories that actually
ship to production. Use this example only if `db/production` is one of them.

```toml
[tool.skylos.sql.production]
directories = ["db/production"]
forbid_public_writes = true
```

Run `skylos cicd postgres-check --base "$BASE_SHA" --head "$HEAD_SHA"` from
the repository root with full Git commit IDs. The base supplies the policy.
The check reads changed SQL from Git and fails when a protected migration
cannot be parsed, including when the parser is missing. Omit
`forbid_public_writes` to require coverage only. When enabled, it also fails
on a newly introduced PUBLIC table write grant, including a grant on future
tables. A PUBLIC read grant or an existing write grant shifting lines passes.
The write check covers explicit INSERT, UPDATE, DELETE, TRUNCATE and ALL
table grants. Dynamic SQL, role membership and privileges established in a
different migration can also affect who has access. The check follows explicit
transactions and savepoints within the file and assumes autocommit between
them. A write that becomes public at a commit can be blocked even if a later
transaction revokes it. Unresolved or two-phase transactions involving these
writes fail the check. Use your migration runner for role tests if it wraps
or batches SQL.

Splitting or combining ordinary grants passes when the same tables and columns
keep the same rights. For very large rewrites the check limits this comparison
and can flag an equivalent change for review.

For an intentional grant, review its file and the fingerprint printed by the
check. Add one `{ path = "...", fingerprint = "..." }` entry to
`allow_public_writes` in the same base policy. A PR cannot approve itself.
For the reusable GitHub Action, use `fetch-depth: 0`, enable
`postgres-policy: 'true'` in gate or review mode, and pin the action to a
trusted commit. Require the job in your branch rules to prevent merging on
failure and require owner review for policy and workflow edits.

Runtime access depends on the deployed schema, grants and row policies. Test
role access on a disposable database with the intended app roles. A scan
cannot establish which rows a deployed login can read or write.

## Checking Rust security

Run `skylos . --danger` from the crate or workspace root. Rust security
checks use the default confidence setting. To review a finding, start at the
reported line and trace the value back to where it came from.

- **Database queries (SKY-D211).** Check whether request text becomes part
  of an executed SQL statement. Skylos follows supported calls in rusqlite,
  SQLx, mysql and mysql_async. In SQLx, building a query or dropping its
  future leaves it unexecuted. For a PostgreSQL name lookup, keep the SQL
  fixed and pass the name with `.bind(name)`.

```rust
let rows = sqlx::query("SELECT id FROM users WHERE name = $1")
    .bind(name)
    .fetch_all(pool)
    .await?;
```

- **Credentials in HTTP requests (SKY-D356 and SKY-D391).** Check the
  destination and where the credential goes. Sending a bearer token over
  plain HTTP exposes it in transit. Putting an exposed `SecretString` in a
  URL can also expose it in logs, even over HTTPS. For a bearer token, use
  HTTPS and the request's `.bearer_auth(...)` method.
- **Session cookies (SKY-D252).** Check that the outgoing session cookie
  has its `Secure` flag set. Skylos recognizes selected session cookie
  names and issuing APIs. If your application uses a custom name for its
  session, check the code that sends it.

Coverage depends on the crate and call path. Custom wrappers, macro-generated
code and calls across crates can hide how a value is used. The Rust checks
also leave unsafe pointer lifetimes and pointer validity unmeasured.

## Swift

Swift support is new. It reports unused `private` and `fileprivate`
functions, methods, properties and types; every `internal`, `public` or
`open` declaration counts as used, because Skylos cannot see every caller.

Skylos builds a graph of declarations and the references between them, and
also counts as used:

- code marked for the runtime, such as `@objc`, `@IBAction`, `@IBOutlet`,
  `@main`, `@Test` and `@NSManaged`;
- `override` and `dynamic` members, `NSObject` subclasses and `@objcMembers`
  classes;
- properties with a wrapper, such as `@State` or `@Published`, and members
  that `Codable`, `Equatable` or `Hashable` use;
- protocol requirements, code inside conditional compilation, anything
  behind an attribute it does not know, and every declaration in a file
  that uses a macro.

It does not expand macros, follow build configurations or infer general
types. A Swift file over 2 MB, or one too large for its internal limits, is
listed as not analysed, and a file that does not parse is listed with the
parse error. Swift findings use the usual dead-code IDs: SKY-U001 for
functions and methods, SKY-U003 for variables, SKY-U004 for types. Inline
`// skylos: ignore[...]` markers work on the reported line.
