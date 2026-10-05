# Done gate (`skylos done`)

`skylos done` decides whether a change is finished, with evidence. It runs
the tests itself, compares the tests and test settings with the base, looks
for edits to Skylos's own settings and for added secrets and made-up imports,
then writes a receipt.

It gives no opinions and writes no style comments: each check passes or
fails with evidence, the way CI does.

```bash
skylos done                     # uncommitted changes, compared with HEAD
skylos done --session SESSION   # all changes since the agent session began
skylos done --base origin/main  # a pull request, compared with its merge base
skylos done receipt             # print the latest receipt again
```

Exit codes: `0` pass, `1` a blocking check failed or did not finish, `2`
Skylos could not run (for example, the base is not fetched).

## Checks

| Check | Rules | Blocks by default | What it checks |
|:--|:--|:--|:--|
| Tests pass when Skylos runs them | SKY-A113 | yes | Skylos runs `test_command` and reads the JUnit XML. A test that fails twice fails the check; one that fails once and then passes is reported as flaky. Running out of `test_budget_seconds` is "unfinished", never "pass". An expected Python test producing no results is "unfinished" unless the trusted base's collection settings explain its exclusion. |
| No tests deleted, skipped or weakened | SKY-A110, SKY-A111, SKY-A112, SKY-A101 (advice) | yes | Python and JavaScript/TypeScript tests. A test that existed at the base is gone (a moved, renamed or rewritten test is not; a pasted copy of a test that is still there is), lost parametrize or `.each` cases, is left with no countable assertion, or gained skip/xfail (`.skip`, `.todo`, `.fixme`, `skipIf` and the like for JS/TS); a JS/TS test file gained a focus (`.only`, `fit`, `fdescribe`). Test settings loosened: pytest `-k`/`-m`/`--deselect`/`--ignore`/`--lf`/`-p no:`, `norecursedirs`, `testpaths`, `conftest.py` hooks that can drop tests or rewrite results, `collect_ignore`, lower coverage floors, Jest/Vitest settings that stop running existing test files, `passWithNoTests`, lower Jest/Vitest coverage thresholds, package.json test scripts that filter tests, may now fail or no longer run a runner, and CI test steps that may now fail. Advice: weakened assertions (SKY-A101), tests renamed or rewritten with a different body, fewer countable assertions, a new `return` before assertions. |
| Skylos settings and hooks left alone | SKY-A114 | yes | Edits to `protected_paths`, to `[tool.skylos]` in pyproject.toml, or to a CI workflow that runs Skylos. |
| No secrets added | SKY-S101 | yes | Secrets on added lines. A suppression comment added in the same change does not count. |
| Every package and import is real | SKY-D222, SKY-D225, SKY-D223 (advice) | advise | Added imports and dependencies resolve to real, declared packages. Names that only cannot be tied to a declared package are advice. |
| Tests check the changed lines | SKY-A120 | advise | Each changed line in non-test Python code is run by a test, and a test fails when Skylos changes that line on purpose. Lines that fail either are listed on the receipt as unverified. See below. |

A deleted test that directly references a deleted production module is
reported as a feature removal (advice). Renaming a module or deleting an
unrelated module does not qualify.

**How a base test is matched at head.** By the same id (file, class or
`describe` blocks, name); else, once each, by a new test with the same body
(after normalisation: comments, formatting and quote style do not count),
which is a move or rename and is not reported. Every other pairing is
reported as advice ("renamed ... and edited", "moved ... and was edited",
"rewritten in place ...; check that it still tests the same behaviour"):

1. renamed and edited: a new test in the same class or `describe` whose
   title shares at least half its words (or 60% of its characters) with the
   deleted test's title and whose body is at least 60% similar;
2. the same name under a class or `describe` that was renamed, when the
   block name or the body is at least 35% similar;
3. rewritten in place: same file, in the gap between the same surviving
   neighbours, same class or `describe` (or across one that was renamed or
   newly written), title or body at least 35% similar.

A new test is never paired with a deleted one when it copies a test that is
still there: a body identical to a surviving test anywhere, or at least 90%
like one in the same file and closer to it than to the deleted test. So
deleting a failing test and pasting a passing sibling under a similar name,
in its place or anywhere else, is still a deletion. Passes 2 and 3 never
pair a test with one that has no countable assertion. A new test with an
unrelated title written somewhere else in the file is not paired either:
the deleted test blocks.

**Assertions.** Every test records how many assertions can run: Python
`assert` statements, `self.assert*`/`assert_*()` calls,
`pytest.raises`/`warns`/`fail`, `raise AssertionError`; JS/TS `expect(...)`
with a matcher, `assert`/`assert.*`, assertions on the test context
(`t.is`), `expect.assertions`, should.js and Chai property assertions,
throwing Testing Library queries; in both languages calls to helpers named
`assert*`/`check*`/`verify*`/`expect*`/`validate*`/`ensure*`/`should*` and
to functions in the same file that assert or raise/throw. Not counted:

- tautologies: `assert True`, `assert 1 == 1`, `assert x == x`,
  `assert (x, "message")`, `self.assertEqual(x, x)`,
  `expect(true).toBe(true)`, `expect(Number(1)).toBe(1)` (a built-in called
  on literals), `expect(r).toBe(r)`, `assert.equal(x, x)`, `assert(x === x)`;
- a helper named like an assertion that is defined in the same file and
  neither asserts nor raises (`function checkResult(r) { return r; }`);
- code that cannot run: after `return`/`raise`/`throw` (also inside
  `if True:`/`if (true)`), under a constant false condition (`if False:`,
  `if (1 > 2)`), in a `try` whose `except AssertionError`/`except
  Exception`/bare `except` (or JS `catch`) neither re-raises nor fails the
  test, under `contextlib.suppress(AssertionError)`, and in a nested
  function or `const f = () => ...` that is never called.

A matched test that had countable assertions at the base and has none now
blocks (SKY-A110): it may no longer be able to fail. Fewer countable
assertions ("now has 1 countable assertion(s), had 5") and a new `return`
with assertions after it (`if (process.env.CI) return;`, `if not data:
return`) are advice. Exception assertions that stop checking the error
(`toThrow("message")` to `toThrow()`, `toThrow(/./)` or `not.toThrow()`,
`pytest.raises(X, match=...)` without `match=` or widened to `Exception`,
`assertRaisesRegex` to `assertRaises`) are SKY-A101 advice.

**What still gets past.** The count is static, so a test can still be
weakened without losing a countable assertion:

- tautologies the counter cannot see: `const r = 1; expect(r).toBe(1)`,
  a value compared with a copy of itself, `expect(x).toBeDefined()` on
  something that is always defined;
- assertions on mocks or stubs of the code under test instead of the code;
- changed expected values (`toBe(400)` to `toBe(200)`): SKY-A101 advice
  when its patterns match, otherwise only the rewrite advice when the test
  was also renamed;
- failures swallowed in ways the counter does not follow: a promise
  `.catch(() => {})`, an error handler passed as a callback, a helper in
  another file;
- an assertion made only through a helper imported from another file with
  another kind of name is not seen (the test may then read as having none).

**Accepting a deliberate test removal.** The local CLI has no per-change
override, on purpose: anything the change itself could set (a comment, a
config edit in the same change) an agent could set too, and `[tool.skylos.done]`
is read from the base, never from the change. A human who means to remove a
test has these options:

- Skylos Cloud: on a failed scan whose done receipt blocks, "Merge anyway"
  with a reason (3 to 1,000 characters) by someone with the `override:gates`
  permission (Pro plan). The override is audited and lifts the failed
  receipt in Cloud's verdict and GitHub check; agent policy rules still
  block.
- Lower the policy at the base: set `test_tampering = "advise"` in
  `[tool.skylos.done.checks]` and commit it to the base branch first. It
  applies to every change until it is set back.
- Outside Skylos: whoever can bypass the required status check in branch
  protection.

Python inventories include unchanged test files. Base marker and name
selectors are evaluated against the matched base test's metadata, so adding
a marker or renaming a test cannot newly excuse its absence. Runtime
deselection by a hook is insufficient evidence of a trusted exclusion;
unexplained missing tests produce an unfinished result.

## JavaScript and TypeScript tests

Jest, Vitest, Mocha, node:test and Playwright Test files are inventoried
statically with the same tree-sitter grammars Skylos uses for TypeScript, so
comments and strings never count. Test files are `*.test.*` and `*.spec.*`
files and files under `__tests__/` (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`,
`.cjs`, `.mts`, `.cts`; not `node_modules/`). A Mocha suite that names its
files only by living in `test/` is not inventoried.

- **Identity.** A test is its file, the titles of the `describe` blocks
  around it (also `context`, `suite`, `test.describe`) and its own title.
  Only string-literal titles count: a test titled with a template literal
  that has `${...}`, a variable or any other expression is skipped and never
  reported. A test moved to another file, under a renamed `describe` or to
  a renamed file, with the same body (ignoring comments, quote style,
  semicolons and trailing commas), is not a deletion; renamed, edited and
  rewritten tests are matched as described above. Deleting an `it.todo`
  deletes nothing. node:test subtests (`t.test(title, fn)` and
  `await t.test(...)` on the test's first parameter) are tests too,
  identified under their parent test's title; a subtest of a skipped test
  is skipped. Their `{ only: true }` is not recorded as focus.
- **Feature removal (advice).** A deleted test is a feature removal when the
  code it runs (its callback, the `beforeEach`/`beforeAll` hooks around it
  and the file's own functions it calls) uses a value imported from a module
  this change deleted, or one its module no longer defines (a function moved
  under a new name with a similar body is a rename, not a removal); reads a
  file this change deleted (`readFileSync("src/x.tsx")`, also through a
  top-level string constant); or opens a route whose Next.js `page`/`route`
  file (app or pages router) this change deleted (`page.goto("/x")`).
  Type-only imports never count. Exports are read from `export`
  statements, from `module.exports = {...}` (also through a top-level
  constant: `const codes = {...}; module.exports = codes`) and
  `exports.x =`, and through `export * from` barrels into local modules. A
  package of this repository imported by name (`import * as z from
  "zod/v4"`) is resolved through its package.json `exports` (or `main`) to
  a file in the repository. A module that re-exports an outside package, or
  that the grammar cannot parse cleanly, is never evaluated: the deletion
  blocks.
- **Skips.** `it.skip`/`test.skip`/`describe.skip`, `xit`/`xtest`/
  `xdescribe`, `.todo` (or a test left without a callback), Playwright
  `test.fixme(...)` and `test.skip()`/`test.fixme()`/`test.fail()` called in
  a test, `describe` or file, Vitest `skipIf`/`runIf`, Jest `.failing`,
  Vitest `.fails`, node:test `{ skip }`/`{ todo }` options and `t.skip()`,
  Vitest `ctx.skip()`, and Mocha `this.skip()`. A skip on a `describe` or
  file applies to every test in it.
- **Focus.** A newly added `.only` (`it.only`, `test.only`, `describe.only`,
  `test.describe.only`), `fit`, `fdescribe` or `{ only: true }` is reported
  even on a new test: it silently stops the other tests in the file from
  running (in Mocha, in the whole run).
- **Cases.** `.each` (and Vitest `.for`) tables with a literal array or a
  tagged-template table are counted; fewer cases is a deletion.
- **Unreadable and unparseable files.** A changed test file that cannot be
  read (not UTF-8, or over the 2 MB source limit) on either side, or that
  parsed at the base and no longer does, leaves the check unfinished. An
  unchanged unreadable file, or a file that does not parse on either side
  (Flow, syntax the grammar lacks), is left out and reported as advice.

Jest and Vitest settings are read from `jest.config.*` or the package.json
`jest` key, and from the `test` block of `vitest.config.*` (or
`vite.config.*` when there is no Vitest config), compared per directory, so
moving settings between those files is not a change. Reported (SKY-A112):

- Settings that stop running test files that exist at the base: new
  `testPathIgnorePatterns`/`modulePathIgnorePatterns` (Jest) or `exclude`
  (Vitest) entries, and narrower `testMatch`/`testRegex`/`roots`/`rootDir`
  (Jest) or `include`/`dir`/`root` (Vitest). Skylos evaluates the patterns
  against the repository's files, as the runner would, and names one file
  that no longer runs. A pattern that drops no existing test file, drops
  only Playwright specs (files importing `@playwright/test`, which a unit
  runner never ran) or only build output (`dist/`, `build/`, `.next/`,
  `node_modules/`, ...) is not reported. A setting Skylos cannot evaluate
  (an unsupported glob such as `!(...)`, or `projects`) is compared as a
  list instead, like pytest `testpaths`: newly set or with entries removed
  is reported. Entries removed from Jest or Vitest `projects` are reported.
- `passWithNoTests` turned on, and lowered or removed coverage thresholds
  (`coverageThreshold`, `coverage.thresholds`; the pre-1.0 Vitest
  `coverage.lines` keys count as `coverage.thresholds.lines`, so moving a
  threshold there is not a removal).
- A package.json `test` (or existing `test:*`) script, followed through
  `npm run`/`pnpm`/`yarn`/`run-s`/`run-p` into the scripts it runs, that
  gains `--passWithNoTests`; a test filter its runner did not have, the
  counterpart of pytest `-k`/`--deselect`/`--lf` (Jest `-t`/
  `--testNamePattern`/`--testPathPattern`/`--onlyChanged`/
  `--findRelatedTests`/`--shard`/`--selectProjects`, Vitest `-t`/`--project`/
  `--changed`/`--shard`/`related`, Mocha `--grep`/`--fgrep`, node:test
  `--test-name-pattern`/`--test-only`, Playwright `--grep`/`--project`/
  `--last-failed`, ava `--match`); test-path arguments where it had none, or
  fewer of them; `|| true` or any new `||` fallback (`|| exit 1` keeps a
  failure a failure); or that no longer runs a test runner at all (for
  example `echo ok`; a script that runs an unknown command such as
  `node scripts/test.js` is given the benefit of the doubt).

A config exported as a function, spread from another object or built from
values that cannot be resolved statically is skipped, never guessed. A
package added in this change has nothing to loosen.

Skylos does not start JavaScript runners on its own. Set `test_command` and
have the runner write JUnit XML to `junit_xml`, for example
`npx vitest run --reporter=default --reporter=junit --outputFile.junit=reports/junit.xml`
or Jest with the `jest-junit` reporter. Without a `test_command`, a project
whose only tests are JavaScript/TypeScript gets an unfinished tests check that
says so, instead of an automatic pytest run; the static checks above still
run. When pytest runs automatically in a repository that also has JS/TS
tests, the receipt notes that those tests were not run.

## Settings

Settings live in `[tool.skylos.done]` and are read from the **base commit**,
never from the working tree: for `--base origin/main` from the tip of
`origin/main`; for `--session` from HEAD when the session began; otherwise
from current HEAD. A session cannot loosen its own gate by committing new settings.

```toml
[tool.skylos.done]
test_command = "pytest -q"        # run without a shell; default: pytest, if found
test_budget_seconds = 300         # 10 to 3600
max_stop_blocks = 3               # 1 to 10; local loop escape, never a passing verdict
protected_paths = [                # default: Skylos settings and agent hook files
  ".skylos/", ".claude/settings.json", ".claude/settings.local.json",
  ".codex/hooks.json", ".codex/config.toml", ".cursor/hooks.json",
]
# junit_xml = "reports/junit.xml" # for non-pytest commands that write JUnit

[tool.skylos.done.checks]
tests_pass = "block"              # block | advise | shadow | off
test_tampering = "block"
gate_tampering = "block"
secrets = "block"
unknown_imports = "advise"
changed_lines_checked = "advise"
```

`changed_lines_budget_seconds` (default 120, 10 to 1800) bounds the
changed-lines check separately from `test_budget_seconds`.

Modes: `block` decides the verdict; `advise` is shown but never blocks;
`shadow` is recorded on the receipt but not shown; `off` does not run.

Skipping a check configured to block, including `--no-tests`, produces an
`incomplete` verdict. Turn a check off in the trusted base configuration to
disable it intentionally. A skipped or unfinished blocking check cannot pass.

For pytest, Skylos adds its own `--junitxml` and removes `PYTEST_ADDOPTS` and
`PYTEST_PLUGINS` from the test environment. Blocking test checks for other
commands require `junit_xml`: exit zero alone is insufficient evidence that
tests ran. Known blocking static findings stop the expensive test run until
the agent fixes them.

## In the agent loop

Commit the Done configuration before starting the agent, then install hooks:

```bash
skylos agent install-hooks --claude --project
# Or --codex / --cursor. Reinstall to add the prompt baseline to older hooks.
```

1. On prompt submission, `skylos hook session-start` captures the starting
   checkout, including staged, unstaged and nonignored untracked files. Earlier
   user changes become the baseline rather than changes blamed on the agent.
2. Existing post-edit checks provide feedback on each edit. The session baseline
   remains fixed across later prompts and commits made by the agent.
3. At Stop, Done compares the entire current tree with that baseline. Shell
   edits and committed edits count even if no post-edit hook saw them. It runs
   cheap tampering and secret checks before the configured tests.
4. A failed or incomplete check returns up to ten reasons and a recheck command.
   After `max_stop_blocks` on the same checkout and policy, the local hook lets
   the agent stop with a warning. The receipt stays failed or incomplete and
   another unchanged Stop does not rerun the tests. Changed source earns a new
   retry budget.

Only a committed `[tool.skylos.done]` table enables Done test execution in
hooks. Repositories without it keep their existing hook behavior. A first
pre-read or pre-bash event can also capture the baseline; a first post-edit or
Stop event is too late to prove full-session coverage and produces an
incomplete result. Missing or corrupt baselines never silently reset.

Capture leaves HEAD, refs, the user's index and working files unchanged. It
stores local dangling Git objects and schema-version-2 session state in
`.skylos/agent-session.json`. The objects can contain initial uncommitted file
contents; ignored untracked files are excluded. Normal Git garbage collection
can prune them, requiring a new session. This is local feedback evidence;
an agent with filesystem access can modify local state. Required CI is the
independent check that decides the merge.

Snapshots read actual bytes rather than trusting Git status or timestamps.
They refuse unreadable files, symlink parents and nonregular files, and do
not execute repository Git filters or hooks. Current limits are 50,000 files
and 256 MB read per snapshot, with at most 1,000 changed files totaling 32 MB
and 2 MB per changed file. Submodule contents are unsupported. Exceeding a
limit is unfinished verification. Files changing during verification cannot
receive a verdict for the earlier tree.

CRLF checkout normalization can remain clean when repository text/eol
attributes or local `core.autocrlf` explain it. Raw differences still count
toward snapshot limits. Custom filters, ident and encoding transforms are
not executed and transformed checkouts can remain dirty. Global Git settings
are disabled by the existing safe Git context; use repository attributes for
portable line-ending settings.

Internal hook errors let the agent stop with a warning and replace or
invalidate the latest receipt when it can safely write. Escaping a hook error
or a retry loop never means verification passed. Named receipts remain history.
The manual Done command exits 2 if verification or receipt publication fails
and invalidates the latest receipt when it can safely write.

The current Stop check runs the full configured test command within its
budget. Automatic test selection and passing-result caching are not yet
implemented; slow suites still need a deliberate command and budget.

Stop also rechecks unresolved findings recorded by the existing post-edit
security and opted-in standards guards. These appear separately as
`agent_edits` on its receipt; unresolved blocking findings postpone the tests.
Use `skylos hook recheck --session` for those recorded edits. The core
`skylos done --session ID` command checks the Done rules listed above. Neither
is a complete SAST scan: retain the required CI static-analysis job as well
as the required Done job.

Cursor also limits this hook to ten automatic follow-ups across the whole
conversation. Done's `max_stop_blocks` applies to an unchanged working tree;
editing the tree gives Done a fresh retry budget but does not reset Cursor's
conversation counter. After Cursor reaches its limit, continue manually or
start a new conversation. Reaching that limit never makes the receipt pass.

## Tests check the changed lines (SKY-A120)

AI agents often write tests that pass without checking anything the change
does. This check asks two questions about every changed, executable line in
non-test Python code:

1. **Does any test run it?** The `tests_pass` run is traced (`sys.monitoring`
   on Python 3.12+, `sys.settrace` before that), mapping each changed line to
   the tests that execute it. A line no test runs is reported, grouped per
   function: `No test runs shop/billing.py:26-28 (in refund).`
2. **Does any test notice if it is wrong?** Skylos makes one deliberate change
   to the line, chosen by what the line does: flip a comparison (`>` to `>=`),
   swap `and`/`or`, negate a condition, return a default value, change an
   integer by one, swap `+`/`-`, pass `None` for a changed argument, assign
   `None`, or remove a call. It reruns only the tests that run the line. If
   they all still pass: `No test fails if shop/billing.py:14 changes > to >=.
   Add an assertion that would.`

The changed code is loaded in memory inside the test process. The working
tree is never modified and no bytecode is written. Only code on the lines the
change touched is mutated, so a long statement with one changed argument is
judged on that argument.

Skipped on purpose: logging and `print` calls, imports, docstrings, type
hints, module-level and class-level code, `raise NotImplementedError`, the
messages passed to exceptions, `if TYPE_CHECKING:`, `if __name__ ==
"__main__":`, test files and `migrations/`.

Limits, reported and never counted as passing:

- At most 20 mutants run, within `changed_lines_budget_seconds`; each mutant
  times out at twice its tests' normal time plus 15 seconds. A hung run counts
  as caught. Lines past either limit are "not checked".
- A line that only runs while modules are imported, a file the tests import
  from somewhere else (an installed copy), or a line no mutation applies to is
  not judged.
- Needs pytest. Code run in a subprocess (a CLI started by a test) is not
  traced, so those lines can be reported as not run.
- Runs only when the test run finished with every test passing.

Some lines are not worth a test, so the check advises by default. Its
findings are suggestions for the agent, and the receipt's `unverified` list
tells a reviewer where to look.

## Receipt

Each run writes `.skylos/receipts/<head>-<base>.json` and
`.skylos/receipts/latest.json` (the directory ignores itself in Git). In
GitHub Actions the receipt is also appended to the job summary.

To store it in Skylos Cloud, attach it to a code-scan upload of the same
commit:

```bash
skylos done --base origin/main
skylos . --upload --done-receipt .skylos/receipts/latest.json
```

The upload refuses a receipt for another commit, one that includes
uncommitted changes, or one whose checkout changed after it was written.
The checkout is checked again when the upload payload is prepared.

Scan attribution uses the checked-out commit before the CI event's SHA,
which can refer to a merge commit in a pull-request workflow. The event SHA
remains in CI metadata. An explicit `SKYLOS_COMMIT` override still wins and
must match the receipt.

Cloud records these results as claims from the uploading CLI. A Cloud
signature authenticates the stored report and uploader identity; it does
not prove that the reported test execution happened. GitHub OIDC identifies
the uploading workflow separately from the receipt's claimed check results.

The done receipt contains check summaries and finding locations, without
source snippets. The code scan attached to it can include finding snippets
under the existing scan upload contract.

## In CI

```yaml
on: pull_request            # never pull_request_target: the tests run PR code
jobs:
  done:
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0    # the merge base must be available
          ref: ${{ github.event.pull_request.head.sha }} # receipt names the PR head
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install trusted verifier
        run: |
          python -m venv "$RUNNER_TEMP/skylos-verifier"
          "$RUNNER_TEMP/skylos-verifier/bin/pip" install skylos
      - name: Install project tests separately
        run: |
          python -m venv "$RUNNER_TEMP/project-tests"
          "$RUNNER_TEMP/project-tests/bin/pip" install -e . pytest
      - run: |
          export PATH="$RUNNER_TEMP/project-tests/bin:$PATH"
          "$RUNNER_TEMP/skylos-verifier/bin/skylos" done --base origin/${{ github.base_ref }}
```

Make the job a required status check so agents without hooks are covered too.
Skylos Cloud's generated scan/upload workflow does not currently install this
Done job. Add it separately; test execution belongs in the unprivileged
`pull_request` job, separate from any trusted upload publisher.

Pin the verifier to a reviewed release that includes Done. Keep project
dependencies out of the verifier's environment, and protect the required
workflow itself. Separate Python environments prevent package collisions;
they do not isolate processes running under the same user. Skylos currently
runs ordinary subprocesses: enforcing filesystem, credential and network
boundaries needs the CI runner or an external sandbox.

## Not yet

- Per-test accounting for JavaScript/TypeScript runs is only as good as the
  JUnit XML the runner writes: Skylos does not add its own reporter to a
  Jest or Vitest command, check that every inventoried JS/TS test reported a
  result, or trace changed JS/TS lines (SKY-A120 is Python-only).
- JS/TS tests generated in loops or shared helper functions count once, as
  written; skips on tests with computed titles are not reported.
- A test rewritten beyond recognition in the same place (title and body less
  than 35% similar) is still reported as deleted; a different, passing test
  written in the exact place of a deleted one, or under a similar title with
  a similar body, is accepted as its rewrite with advice, not blocked.
- Weakened assertions (`toBe` to `toBeTruthy`, fewer assertions, a new early
  `return`) are advice, including on renamed or rewritten tests; only a test
  left with no countable assertion blocks. See "What still gets past" above.
- `skylos done init`, automatic test selection and passing-result caching.
- Authenticated organization-policy sync into local Done checks and automatic
  session-receipt upload to Cloud.
- Rerunning a failing test on the base to call it pre-existing.
- Counting computed parametrize cases, and excluding individual parameter
  cases. Literal lists, tuples and simple module-level constant aliases are
  counted. A computed case list is trusted while the change leaves alone
  everything that builds it: the test's parametrize decorators, its class
  attributes, the repository code those reach and, for lists read from files,
  tracked repository inputs when the reader paths cannot be proven. Opaque
  readers also remain unfinished when any tracked input changes, including
  Python files used as data. Reader names are not proof of input independence:
  only restricted closed expressions and resolved pure repository factories
  can ignore unrelated inputs. Reflection, external calls, local imports and
  complex control flow remain opaque. Additions,
  renames and Python files count too: a new sentinel or changed enumeration can
  narrow the cases. Such changes leave the test check unfinished. An opaque
  base case list changed to a literal singleton or an ordinary test also stays
  unfinished; removing a known parametrization reports the missing cases.
