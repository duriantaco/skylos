# Python behavior comparison

Python behavior comparison runs automatically with the normal verification
command:

```bash
skylos verify app.py
skylos verify .
```

The [integration plan](behavior-integration-plan.md) tracks rollout into existing
comprehensive scans and branch review. Its first step provides a shared
`compare_source_changes` service for prepared `SourceSnapshot` inputs and a
`ComparisonScope`. The current Git adapter calls that service; Git loading,
terminal rendering and command exit policy remain outside source comparison.

Skylos compares affected Python functions in Git HEAD with the current working
tree, alongside the existing AI-code checks. The path selects a file or project;
Skylos selects the functions and baseline. Changed local helpers can affect a
function even when that function's own source is unchanged.

The selected path must exist. A missing file or project directory is an input
error (exit code 2), including when using `--file` with `--project-context`.

In a terminal, the command explains each difference with its location, before
and after behavior, possible impact on callers, and a review prompt. For example:

```text
app.py:1 — run
  Callback result discarded
  Before: Returned the result of callback(value).
  After: Returns None.
  Impact: Callers that use the returned value now receive None and may break.
```

Pipes, redirected output, `--stdin`, and `--output` keep machine-readable JSON.
The same explanation is included in each difference's `explanation` object.
No extra formatting flag is needed. This comparison runs through `skylos verify`;
the ordinary `skylos <path>` scan retains its existing analysis/reporting.

A modeled difference needs review. It may be an intentional feature change or
a regression; the command cannot infer that intent. Differences are reported as
incomplete verification rather than being labeled proven product bugs.

The behavior comparison is experimental and bounded. It reads source as data
without importing the project, executing its functions, checking out the base
revision, invoking an LLM, or contacting a package registry. Existing AI-code
checks retain their own behavior, including configured dependency checks.

## What is compared

The Python interpreter model compares ordered outgoing calls and their
arguments, returned values, propagated exceptions, and cleanup effects. It
also requires the selected function's declared parameter names and kinds to
stay the same. It follows supported helper functions in the same file and statically resolvable
repository imports. A helper extraction can preserve these observations even
though the source structure changes:

```python
# Base
def run(callback, value):
    return callback(value)

# Working tree
def apply(transform, item):
    return transform(item)

def run(callback, value):
    return apply(callback, value)
```

Changing the argument to `callback`, dropping its call, dropping its returned
value, swallowing its exception, or changing cleanup order can produce a
modeled difference. Changes to a resolved imported helper are included even
when the selected file itself is unchanged.

Import resolution initially uses repository-root module names. Imports that
could refer to a local file through an undeclared source root, such as `src/`,
`lib/`, or `python/`, are incomplete. Package binding conflicts are also
incomplete.

## Status and evidence

The normal `verify_change` JSON response includes a `behavior` object with the
baseline, source evidence, and individual function comparisons.

| `behavior.status` | Meaning | Effect on an otherwise passing result |
| :--- | :--- | :--- |
| `equivalent` | The affected functions have equal observations within the supported model and its assumptions | Remains `pass` |
| `different` | At least one function has a modeled difference that needs review | Becomes `incomplete` |
| `unknown` | The comparison cannot establish equivalence | Becomes `incomplete` |
| `unchanged` | No statically identified Python change in the selected scope needs comparison | Remains `pass` |
| `unavailable` | No Git HEAD baseline is available, or the selected file is not Python | Remains `pass`; behavior was not compared |

Existing verified AI-code findings still produce `fail`, including when behavior
comparison needs review. Overall exit codes remain 0 for `pass`, 1 for `fail`,
and 2 for `incomplete`. `--no-fail` changes only the exit code.

The behavior evidence records:

- The resolved immutable HEAD commit.
- SHA-256 hashes of the Python sources and recognized dependency/environment
  manifests read from the baseline and working tree.
- Individual function comparisons, including the model version, symbol ranges,
  differences, reasons for incompleteness, and assumptions.
- The selected function/helper scope and comparison budgets.

These hashes identify the inputs to the comparison. They do not establish
semantic correctness independently of the model. Working-tree reads are not an
atomic filesystem transaction; rerun after further edits. Evidence is from the
static model, not an executed runtime witness.

## Supported boundary

The initial subset covers synchronous module-level functions, simple local
assignments, supported literal and parameter values, statically bound helper
calls, opaque callback/imported calls, and supported `try`/`except`/`finally`
control flow. Unsupported operations in an affected function produce `unknown`
even if that function's source text is identical in both versions.

The model assumes that names have their declared source/import bindings after
successful module initialization, and that these bindings and external
dependencies remain stable. Import hooks and initialization-time rebinding are
excluded. Opaque calls are observed through their arguments, order, result,
active exception context, and exception outcome. This allows arbitrary return
and exception outcomes; a difference involving a fixed
external API may need validation against that API's actual contract. The report
does not contain an executed runtime witness. It cannot establish equivalence
for callbacks that inspect frames or tracebacks,
monkey-patching, timing, memory consumption, or arbitrary runtime environments.

Conditionals, loops, recursion, async functions, generators, decorators, defaults,
annotations, dynamic object operations, and unsupported exception matching are
outside the initial subset. Ordinary Python arithmetic can invoke user-defined
methods, so arbitrary arithmetic is not treated as a pure mathematical
operation. This mode does not certify arbitrary Python programs or whole
repositories.

The default budgets are 128 affected functions, 64 modeled paths per function,
and helper depth 8. Exhausting a budget
produces `incomplete`. Snapshot reads are bounded to 4,096 inputs, 1 MiB per file,
and 16 MiB total; exceeding a bound, decoding failures, or source symlinks also
prevent certification. Unchanged Git submodules are treated as external
dependencies; a changed submodule commit or dirty submodule prevents comparison.

Snapshots include tracked and unignored Python files across the Git repository,
plus recognized dependency manifests. Newly created unignored helper files are
included. Ignored dependencies and the external environment are assumed stable.
A change to a recognized dependency/environment manifest (such as
`requirements.txt`, `pyproject.toml`, or a Python lockfile) produces `incomplete`.

The command discovers affected functions within the selected path. Comparisons
cover whole functions and supported helpers. Discovery follows static imports
and name references; dynamic loading and runtime rebinding are outside this
initial selection model. Existing file/range selection,
project context, AI contracts, analyzer confidence, dependency-check settings,
and folder exclusions remain available for ordinary verification; they do not
expand the behavior model's supported semantics. Stdin verification runs its
existing checks without a Git behavior comparison.

## How the verifier is tested

The regression suite checks pairs that should preserve behavior (including
helper extraction) and deliberately changed pairs (arguments, call order,
returns, exceptions, and cleanup). Independent tests also check cases that
must remain incomplete: unsupported syntax, changed bindings, ambiguous
imports, exhausted budgets, and escaping local callables. Git/CLI integration
tests exercise actual base revisions, working edits, helper changes, source
hashes, and exit statuses. Test snippets are source data, not executed targets.

These tests protect the implemented subset. Broader claims require expanded
semantics, a representative labeled change corpus, and measured false-pass,
false-failure, and incompleteness rates.
