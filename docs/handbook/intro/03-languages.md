# Languages Skylos reads

Depth differs by language. Python, TypeScript/JavaScript and Java get the
most: dead code, security and quality, with framework conventions. Other
languages get a subset, as this table shows. Each rule page also lists the
languages that rule covers.

| Language | Files | Dead code | Security | Quality | Read with |
|:--|:--|:--|:--|:--|:--|
| Python | `.py` | Yes | Yes | Yes | Python's `ast` |
| TypeScript, JavaScript | `.ts .tsx .js .jsx .mts .cts .mjs .cjs` | Yes | Yes | Yes | tree-sitter |
| Java | `.java` | Yes | Yes | Yes | tree-sitter |
| Go | `.go` | Yes | Partial | Partial | the `skylos-go` engine; tree-sitter for quality |
| PHP | `.php`, Drupal `.module .install .inc .theme` | Yes | Yes | No | tree-sitter |
| Rust | `.rs` | Experimental | Partial | Partial | tree-sitter |
| Ruby | `.rb` | Partial | Partial | No | tree-sitter |
| Dart | `.dart` | Yes | Partial | No | tree-sitter, with the `skylos[dart]` extra |
| C# | `.cs` | Partial | Partial | Partial | Skylos's own lexer |
| C++ | `.cpp .cc .cxx`, headers for references | Partial | No | No | tree-sitter |
| Kotlin | `.kt .kts` | Partial | Partial | No | Skylos's own lexer |
| Swift | `.swift` | Partial | No | No | tree-sitter |
| Shell | `.sh .bash .zsh .ksh .bats` | No | Partial | No | Skylos's own reader |

Secrets are checked in all of these source files and in configuration,
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
- **C++** dead code reports only unused file-local functions.
- **Dart** needs `pip install "skylos[dart]"`, which compiles a parser and so
  needs a C compiler. Without it, `.dart` files are listed as not analysed.

## Swift

Swift support is new. It reports unused `private` and `fileprivate`
functions, methods, properties and types; every `internal`, `public` or
`open` declaration counts as used, because other modules can reach it.

Skylos builds a graph of declarations and the references between them, and
also counts as used:

- code marked for the runtime, such as `@objc`, `@IBAction`, `@IBOutlet`,
  `@main`, `@Test` and `@NSManaged`;
- `override` and `dynamic` members, `NSObject` subclasses and `@objcMembers`
  classes;
- properties with a wrapper, such as `@State` or `@Published`, and members
  that `Codable`, `Equatable` or `Hashable` use;
- protocol requirements, code inside conditional compilation, and anything
  behind an attribute or macro it does not know.

It does not expand macros, follow build configurations or infer general
types. A Swift file over 2 MB, or one too large for its internal limits, is
listed as not analysed, and a file that does not parse is listed with the
parse error. Swift findings use the usual dead-code IDs: SKY-U001 for
functions and methods, SKY-U003 for variables, SKY-U004 for types. Inline
`// skylos: ignore[...]` markers work on the reported line.
