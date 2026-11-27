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
| PostgreSQL | `.sql` | Unused SELECT CTEs with `--quality` | Partial | Partial | PostgreSQL parser via `skylos[postgres]` |
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

The initial reviews cover an unused read-only common table expression,
an ordinary comparison against NULL in a filter, and a privileged function
that inherits its search path. The checks operate on parsed SQL files.
Database contents, schema permissions and dynamically built SQL are outside
their scope. Findings are report-only.

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
