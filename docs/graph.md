# Codebase graph (`skylos graph`)

`skylos graph` maps every function, method and class in a repository: what
calls what, what each one does in plain English, which tests reach it, and
what answers those tests expect. When code changes, it marks every changed
function and says whether its logic is still the same.

It is built for two readers:

- **you**, in a local browser view (`skylos graph open`)
- **your coding agent**, through `--format json` and MCP tools, so it can look
  up callers and impact before it edits code

```bash
skylos graph                     # build or update .skylos/graph/, compare with HEAD
skylos graph open                # explore it in your browser (127.0.0.1 only)
skylos graph --since origin/main # mark everything this branch changed
skylos graph show load_config    # one function: what it does, callers, tests
skylos graph impact load_config  # everything that depends on it
skylos graph areas               # the codebase split into areas that work together
skylos graph relevant app/billing.py   # what else matters to the file you are changing
skylos graph changes --base origin/main --format json
```

The graph covers Python, TypeScript and JavaScript fully, and Go, Java, Rust
and PHP as a first pass (see [Other languages](#other-languages-first-pass)).
Links between functions are computed from the code, not guessed by a model.
Building the graph runs none of the project's code and makes no network
requests.

## Building and updating

The first build parses every file. Later builds reuse every file whose size
and modification time did not change, so an update takes a second or two:

| Repository | Files | Links | First build | Update |
|---|---|---|---|---|
| pre-commit | 134 | 2,183 | 1.0 s | 0.7 s |
| skylos-cloud (TypeScript) | 1,427 | 9,371 | 3.9 s | 0.5 s |
| skylos | 2,254 | 69,487 | 16.5 s | 2.5 s, up to 6 s when areas are regrouped |

Measured on an 8-core laptop, 2 and 3 November 2026.

`skylos graph open` keeps watching the repository and rebuilds when a file
changes. An open browser tab reloads by itself, so you can watch an agent's
edits appear.

## The viewer

`skylos graph open` prints a link with a one-time token and opens it. The
server listens on 127.0.0.1 only, refuses requests without the token, and
refuses requests whose `Host` header is not 127.0.0.1 or localhost.

- **Map**: where to start (entry points nothing else calls, ranked by how much
  code they reach), the most-used functions, and how much is described.
- **Areas**: the codebase split into areas (see below); open one to see its
  members, most important first, and the areas it talks to.
- **Changes**: every changed function and class in the same four sections as
  the [change map](./change-map.md): read first, read, skim, and skip (proven
  same logic), with how many changed lines are left to read.
- **Pipeline**: every `skylos done` run in this repository, newest first, as
  a row of stage boxes (tests, tests not gamed, checks not silenced, security,
  changed lines tested, unused code, review, verdict). Click a box for what it
  found; a failed run has **Copy fix brief** for your coding agent. See the
  [workflow guide](./workflow.md#6-the-pipeline-every-check-run-by-run).
- **A function or class**: the code that calls it above, the code it uses
  below (one or two steps), and a card with its plain-English description,
  what changed, expected outputs from tests, callers, callees, tests that
  reach it and its source.

Press `/` to search. You can edit any description in the card; your edit is
saved to `.skylos/graph/notes.json` and is never overwritten by a model.

## Areas

`skylos graph areas` splits the codebase into areas: groups of functions and
classes that work together. Each area is named after its folder and the member
the rest of the code depends on most (a function first, then a class, so an
exception everyone raises never names an area), and lists its folders, its size and how
tightly it holds together.

```bash
skylos graph areas          # every area, largest first
skylos graph areas 12       # one area: members, most important first, and linked areas
```

Areas start from your folders: code in different folders is never put in the
same area, and a folder with only one or two functions joins its parent
folder. A folder with a handful of functions and classes stays one area for
each connected piece; a larger folder is split by how strongly its code is
linked (inheriting counts most, "uses the type" least, links matched by name
half), with each file holding its own code together. The split uses networkx
community detection with a fixed seed, so the same code gives the same areas.
Folders whose code and links did not change keep their areas on a rebuild,
and area ids follow their members. Methods stay with their class, and every
function belongs to an area even if nothing calls it. Test code is left out.

## Most important and most relevant code

The graph ranks every function and class by four counts over its links, each
step away worth half the step before: how much code leads into it, how often
entry points reach it, how much code it reaches, and how many tests reach it.
Credit from tests never counts for more than the rest, so a helper only tests
use cannot outrank a real entry point, and test code itself is not ranked. The
viewer's Map shows the top of that list, and descriptions are written most
important first.

`skylos graph relevant FILE...` answers "what else should I read before I
change these files?": the code elsewhere in the repository that matters most
to them, most important first, cut to a token budget (`--budget`, default
2,000) so it fits in an agent's context. It follows the code the files use and
the code that uses them, up to three steps away, and says which for each item.

## Other languages (first pass)

Go, Java, Rust and PHP functions, methods and classes are mapped, and their
calls are linked **by name**: a call looks in the enclosing type, then the
file, the package or module and the imports, and is linked only when exactly
one definition there has that name and takes that many arguments. Parameter,
local variable, field and return types pick the right type's method, and calls
into packages outside the repository (such as `fmt.Println` or a
`*sync.Pool`) are never linked. Production code is never linked to test code.
These links are shown as "possibly used by" and "possibly uses", and never
count as callers in `impact`, in tests that reach code, or in the change map.
On go-chi/chi (479 functions, methods and types, 961 name links), all 10 name
links in a random sample were right.

## Is the logic still the same?

For each changed function or class, `skylos graph` gives one verdict:

| Verdict | When |
|---|---|
| Same logic: moved | The same code moved to another file or class, and every call still reaches the same function |
| Same logic: renamed | Only local variable names changed. Parameters, globals, attributes, constants and calls are identical |
| Same logic: docstring | Only the docstring changed |
| Logic changed | Anything else, with the reasons it could prove: a breaking signature, calls added or removed, a removed security check, a changed setting |
| Needs a look | A change the [change map](./change-map.md) flags, such as a removed auth check or a breaking signature with callers left behind, or code that reads the same but now calls a different function |
| New / Removed | Added or deleted code. Removed code that something still calls says so |

"Same logic" is only shown when it is proven. Renaming a parameter, swapping
one global for another, renaming a local so it hides a global, or renaming
anything in a function that reads its own local names (`locals()`, `eval`,
frames) or holds a nested function, class or lambda is reported as "logic
changed". Same-logic checks for renames and docstrings cover Python;
TypeScript and JavaScript changes get "moved" or "logic changed".

The verdicts come from the same engine as the [change map](./change-map.md),
which also sorts each change into read first, read, skim or skip.
`skylos graph changes` prints those four sections; skip holds only proven
same logic, and a docstring that may be read while the program runs is never
skipped.

Each changed function also lists what its tests say:

- **Tests now expect `scale(2, 3)` to give `7` (was `6`)** when the change also
  edited a test's expected answer.
- How many test checks with fixed answers cover it and were not edited, so you
  know which tests to run.
- **No test reaches this code** when nothing in the tests calls it within three
  calls.

Tests are read, not run.

## Plain-English descriptions

Descriptions are optional, cached per function, and only rewritten when that
function's code changes. There are three ways to write them.

**Your coding agent, no key needed.** The agent reads what still needs a
description and writes the descriptions itself:

```bash
skylos graph pending --format json      # code that needs a description, with its source
skylos graph import descriptions.json   # {"items": [{"id": ..., "summary": ...}]}
skylos graph pending --changes --base origin/main --format json   # changed code to explain
```

Over MCP, the same flow is `graph_pending` then `graph_describe`.

**Your own model key.** Uses the key you saved with `skylos key`, or a local
model:

```bash
skylos graph describe                        # picks claude-haiku-5-5 or gpt-5-mini from your saved key
skylos graph describe --model ollama/llama3.1
skylos graph describe --dry-run              # how many items and tokens, then stop
skylos graph describe --changes              # explain changed code: before, after, same behaviour?
```

Only the code being described is sent, with the names of its callers and
callees. A 10,000-function repository is about 9 million input tokens the
first time; with a Haiku-class model that is roughly a dollar.

**Skylos, for credits (not live in Skylos Cloud yet).** Skylos writes them with its own model key. You need
`skylos login`; nothing else to set up:

```bash
skylos graph describe --via skylos --dry-run   # how many credits, then stop
skylos graph describe --via skylos             # 1 credit per 100 functions
skylos graph describe --via skylos --changes   # 1 credit per 20 changed functions
```

The same material is sent as with your own key. If a batch comes back empty,
its credit is refunded.

**A person.** Edit the description in the viewer card.

Change explanations written by a model are shown as "AI's reading · not
proof" and never replace the verdict above.

## For coding agents

Every command takes `--format json`:

| Command | Answers |
|---|---|
| `skylos graph --format json` | Overview, entry points, and the change verdicts |
| `skylos graph find NAME` | Functions and classes matching a name |
| `skylos graph show NAME` | Description, signature, callers, callees, tests, expected outputs, change verdict; `--code` adds the source |
| `skylos graph impact NAME` | Every caller up to `--depth` calls away, the tests that reach it, and possible callers matched by name |
| `skylos graph areas [ID]` | The areas of the codebase, or one area's members and linked areas |
| `skylos graph relevant FILE...` | The code that matters most to these files, within `--budget` tokens |
| `skylos graph changes --base REF` | Every changed function with its verdict, evidence and review section (read first, read, skim, skip) |
| `skylos graph report --base REF` | The report Skylos Cloud stores: verdicts and reasons, no source code |

MCP tools: `graph_find`, `graph_show`, `graph_impact`, `graph_areas`,
`graph_relevant`, `graph_pending` and `graph_describe`, plus `change_map` for
the verdicts and review sections of a change. `graph_pending` with `changes=true` and a `base` compares first, then
lists the changed code to explain. These tools need no Skylos API key, have no
daily limit and use no credits: they read the repository on your machine.

## Pull requests in Skylos Cloud

Not live in Skylos Cloud yet: until it ships, Cloud does not accept these reports.

Skylos Cloud can keep a logic-change report for every pull request and post
one comment on it: which functions changed, which need a look, and which kept
the same logic.

1. In Skylos Cloud, open the project, then **More → Logic changes**, and click
   **Turn on reports**. Each pull request costs 1 credit, however many times it
   is pushed. The member who turns it on is shown as the payer.
2. Update the Skylos workflow from the project's Settings page. The PR scan job
   maps the changes without any upload credential; the publish job sends the
   report with GitHub OIDC. Cloud checks the run belongs to the pull request's
   current head before it stores the report or comments.

Only verdicts, reasons, names and line numbers are sent, never source code.
The report is information for reviewers; it does not change the quality gate.

Outside GitHub Actions, send a report yourself after committing:

```bash
skylos graph --since origin/main --upload        # uses your skylos login
skylos graph report --base origin/main --output graph-report.json   # build only
```

## Files

`.skylos/graph/` holds:

- `graph.json`: functions, classes, links and expected outputs
- `cache.json`: per-file parse results for fast updates
- `changes.json`: the latest comparison
- `areas.json`: the areas, reused while the graph is unchanged
- `notes.json`: descriptions and change explanations

The folder's own `.gitignore` ignores everything except `notes.json`. Commit
`notes.json` so your team shares descriptions instead of writing them again.

## Limits

- Calls through dynamic dispatch, callbacks passed as values, `getattr`,
  dependency injection and string-based routing are not linked. A function
  reached only that way shows "nothing calls this".
- Calls on an untyped local whose class is not known are not linked; calls on
  `self`, constructors, annotated parameters and inherited methods are. A
  class that is only named in a type hint or `isinstance` check gets a weaker
  "uses the type" link instead of "creates".
- Go, Java, Rust and PHP links are matched by name only (see above). A call
  on a value whose type is not written down nearby (for example a value
  returned by code outside the repository) is linked only when one method in
  the same file or package fits, so it can still point at the wrong method;
  calls through interfaces and traits are not followed to their
  implementations.
- Kotlin, Dart, C, C++, C#, Ruby and Swift files are counted and listed as not
  mapped yet.
- "Same logic" verdicts and the review sections cover Python, TypeScript and
  JavaScript.
- Files over 1.5 MB are skipped and listed.

On 240 randomly chosen functions in the Skylos repository (three samples of
80), the graph found all 534 callers that the change map's caller search found.
It found 3 more, all real constructor calls that search did not open.
