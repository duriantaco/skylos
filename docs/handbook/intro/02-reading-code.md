# How Skylos reads code without running it

Skylos is a static analyser: it reads source files and never runs your
project's code to decide a finding. That makes it safe to point at a
project you have not reviewed, and fast enough to run on every pull
request.

## Parsing

Most files are turned into a syntax tree, a structured view of the code in
which a function call, a string or an `if` block is a node Skylos can
inspect.

| Files | How they are read |
|:--|:--|
| Python | Python's own `ast` module, in the interpreter running Skylos (3.11 or newer) |
| TypeScript and JavaScript | tree-sitter, with the TypeScript and TSX grammars |
| Java, PHP, Rust, Ruby, Swift, C++, Dart | tree-sitter grammars (Dart needs the `skylos[dart]` extra) |
| C#, Kotlin, Shell | Skylos's own lexers, which split the code into tokens rather than a full tree |
| Go | `skylos-go`, a Go program that uses Go's own parser and type checker. It ships in the platform wheels; otherwise build it or put it on `PATH` (`skylos doctor` says whether it is found). Go quality checks use tree-sitter. |
| YAML, TOML, Terraform | PyYAML's safe loader, `tomllib`, `python-hcl2` |

In Python, TypeScript/JavaScript, Rust, Ruby, Swift and C++, a file that
cannot be parsed, for example because it uses newer syntax than the interpreter knows,
is listed as not analysed, and so are Go files when the Go engine is
missing. Parse errors in Java, PHP, Kotlin and C# files are not reported
yet.

## Following names and values

On top of the syntax tree, rules work out what the code means:

- **Where a name comes from.** `text()` only counts as SQLAlchemy's `text()`
  when it is imported from SQLAlchemy and not redefined.
- **Where a value comes from.** Security rules follow values from a
  *source*, such as a web request, a command-line argument or the
  environment, to a *sink*, a call that is dangerous with outside data, such
  as `cursor.execute()`. This is called taint tracking. A value is safe again
  once it passes a known safe form, such as a bound query parameter.
- **Who uses what.** Dead-code rules build a list of every definition and
  every reference across the project, then report definitions nothing
  reaches. Before reporting an unused name they also search the project's
  text for it (grep verification), to catch uses a parser cannot see. Ruby
  and Swift are the exception: their analysers only report private names,
  which they resolve themselves.

## What does run

The default scan starts only `git` and the bundled Go engine; the text
search uses `rg` when it is installed and runs inside Skylos otherwise.
Running project code is always something you ask for:

- `skylos done` runs your test command, and so does `skylos cloud` outside
  CI when the project has a committed `[tool.skylos.done]` table;
- `--type-check` runs the project's installed type checker (mypy, pyright,
  pyrefly or tsc, taken from the project's `.venv/bin`, `venv/bin` or
  `node_modules/.bin` first), including any plugins it is configured with;
- `--trace` runs pytest under a call tracer;
- `--coverage` runs your tests only with `--allow-coverage-execution`;
- `--pytest-fixtures` runs pytest.

One more thing to know: to check calls against real library APIs,
`--ai-defects` imports a few installed third-party packages into the Skylos
process (by default `requests`, `pandas`, `boto3`, `openai` and `jwt`), and
the scanned project's configuration can change that list.

Because Skylos does not run the code, it can miss behaviour that only exists
at run time, such as a function called by a name built from a string. Each
rule page lists such cases under "When it can misfire".
