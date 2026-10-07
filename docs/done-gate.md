# Done gate (`skylos done`)

`skylos done` decides whether a change is finished, with evidence. It runs
the tests itself, compares the tests and test settings with the base, looks
for edits to Skylos's own settings, for added secrets and made-up imports, for
code written to pass particular tests instead of being right, and for
linters, type checkers, scanners and CI checks the change silenced, then
writes a receipt.

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
| No tests deleted, skipped or weakened | SKY-A110, SKY-A111, SKY-A112, SKY-A101 (advice) | yes | Python and JavaScript/TypeScript tests. A test that existed at the base is gone (a moved, renamed or rewritten test is not; a pasted copy of a test that is still there is), lost parametrize or `.each` cases, is left with no countable assertion, or gained skip/xfail (`.skip`, `.todo`, `.fixme`, `skipIf` and the like for JS/TS); a JS/TS test file gained a focus (`.only`, `fit`, `fdescribe`). Test settings loosened: pytest `-k`/`-m`/`--deselect`/`--ignore`/`--lf`/`-p no:`, `norecursedirs`, `testpaths`, `conftest.py` hooks that can drop tests or rewrite results, `collect_ignore`, lower coverage floors, Jest/Vitest settings that stop running existing test files, `passWithNoTests`, lower Jest/Vitest coverage thresholds, package.json test scripts that filter tests, may now fail or no longer run a runner, and CI test steps that may now fail (an unrelated command's `|| true` in the same step does not count). A test overwritten in place by a test of something else, while the code the old test exercised is still there, blocks. Not reported: a deleted test whose feature the change removed (see below), and settings that leave out no test that existed (a brand-new pytest config, a project's first `test` script, an ignore pattern that matches no existing test or whose tests run in their own CI step, a new advisory CI step). Advice: weakened assertions (SKY-A101), tests renamed, merged or rewritten with a different body, fewer countable assertions, a new `return` before assertions, deletions that are feature removals. |
| Skylos settings and hooks left alone | SKY-A114 | yes | Edits to `protected_paths`, to `[tool.skylos]` in pyproject.toml, or to a CI workflow that runs Skylos. |
| No secrets added | SKY-S101 | yes | Secrets on added lines. A suppression comment added in the same change does not count. Values that are public by structure are not secrets: hex digests that name their algorithm, public keys and certificates, contract addresses, document ids in share URLs, references to secrets stored elsewhere (`${{ secrets.X }}`), URL slugs; see [dictionary.md](../dictionary.md) (S101). |
| Every package and import is real | SKY-D222, SKY-D225, SKY-D223 (advice) | advise | Added imports and dependencies resolve to real, declared packages. Names that only cannot be tied to a declared package are advice. |
| Tests check the changed lines | SKY-A120 | advise | Each changed line in non-test Python code is run by a test, and a test fails when Skylos changes that line on purpose. Lines that fail either are listed on the receipt as unverified. See below. |
| Code doesn't special-case the tests | SKY-A115, SKY-A116, SKY-A117 | yes | Added non-test Python and JS/TS code that answers a test's exact input with that test's expected value, asks whether a test runner is running it, reads the tests' own files, or rigs a comparison so it always passes. Weaker signals are advice. See below. |
| Linters, type checkers, scanners and CI not silenced | SKY-A119, SKY-A121, SKY-A118 | advise | Linter, type-checker and scanner settings weakened (rules ignored or turned off, source paths excluded, `strict` off, secrets allow-listed), CI lint, type-check, scan and test steps that may now fail or no longer run, and inline suppressions added to code (`# noqa`, `@ts-ignore`, `//nolint`, ...). With `block`, settings and CI findings block; inline suppressions stay advice. See below. |

**Feature removal (advice).** A deleted test is a feature removal, reported
as advice instead of a deletion, when the change removed what it tested:

- a production module the test references directly was deleted;
- (Python) a function, method, class, instance attribute or module-level
  name the test uses was defined in changed non-test code at the base, is
  defined in no changed file at head, appears in no non-test file at head
  (`git grep -w`), and was not renamed (no definition with an 80%-similar
  body was added under another name);
- (JS/TS) see [JavaScript and TypeScript tests](#javascript-and-typescript-tests);
- (both) text the test checks (a string, regular expression or static
  template of 12 or more characters: UI copy, an error code, a prompt
  section) was in changed non-test code at the base and is in no non-test
  file at head, and the line that held it was removed rather than reworded
  (`throw new Error("old message")` becoming `throw new Error("new
  message")` is a reword: the deletion blocks).

Renaming a module or a function, deleting an unrelated module, or rewording a
message does not qualify. A deleted test whose code is still there blocks,
even when other tests still call the same function.

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
   newly written), title or body at least 35% similar;
4. merged: further deleted tests in such a gap, each at least 35% similar
   to a new test written there, when that new test makes at least as many
   countable assertions as all the tests it replaces together ("merged
   into ...").

**Overwritten by a test of something else (blocks).** A test rewritten in
place stops being advice when its subject is gone from the tests but not
from the code. The two titles must name different things (they share fewer
than half of the shorter title's words). The old test's subject is the
identifiers and strings its body uses that no other base test uses (at
least two of them); when no head test uses any of them, and a non-test file
at head still contains one that names code
(camelCase, `snake_case`, `AWS::EC2::VPCEndpoint`-style qualified names, 8+
characters), the old test was overwritten, as when a conflict resolution
replaces a sibling's test with a new one:
`test_cfn_vpc_endpoint ... was overwritten in place by test_cfn_appsync ...,
which tests something else`. When that code was removed too, it is a
feature removal (advice).

A new test is never paired with a deleted one when it copies a test that is
still there: a body identical to a surviving test anywhere, or at least 90%
like one in the same file and closer to it than to the deleted test (one as
close to the deleted test as to the survivor, such as the deleted test's
input with a sibling's expected value, is an edit of the deleted test). So
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

**pytest settings (SKY-A112).** An existing `pyproject.toml`, `pytest.ini`,
`tox.ini` or `setup.cfg` is compared setting by setting: newly set or
narrowed `testpaths`, new `norecursedirs` entries, new `--ignore`/`-k`/`-m`
options and changed `python_files` are reported. A brand-new config file
(a new project, or a sub-project's own `pytest.ini`) can only leave out
tests that already existed, so its `testpaths`, `norecursedirs`,
`--ignore`/`--ignore-glob` and `python_files` are checked against the
`test_*.py`/`*_test.py` files under its directory at the base, and reported
only when one of them would no longer be collected. Name and marker
selection (`-k`, `-m`) in a new config is still reported.

**CI test steps (SKY-A112).** A test step (or job) that can now fail
without failing the build (`continue-on-error`, `|| true`) is reported when
it already ran at the base. A step the base did not have, whose commands
are new and next to which every test step the job ran before still runs, is
a new advisory step, not a loosened one. Renaming an existing step and
making it quiet is still reported.

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
  is skipped. Their `{ only: true }` is not recorded as focus. A
  hand-written runner counts too: a top-level `function t(name, fn)` (or
  `const t = (name, fn) => ...`) that calls its second parameter makes
  each `t("title", () => ...)` a test, so porting Jest tests to a plain
  `node:assert` script is not a deletion. A runner that catches failures
  counts only when the file sets the exit code (`process.exit(...)`):
  otherwise a failing test could not fail the run.
- **Feature removal (advice).** A deleted test is a feature removal when the
  code it runs (its callback, the `beforeEach`/`beforeAll` hooks around it
  and the file's own functions it calls) uses a value imported from a module
  this change deleted, or one its module no longer defines (a function moved
  under a new name with a similar body is a rename, not a removal); uses a
  member of a value imported by name (`api.getLiveness()`,
  `COPY.mapHint`) when that module mentioned the member at the base and
  does not mention it at all at head; checks text the change removed (see
  above); reads a file this change deleted (`readFileSync("src/x.tsx")`,
  also through a top-level string constant or a top-level
  `const form = await readFile(new URL("../src/Form.tsx", ...))`); uses or
  reads a module whose last use the change removed (a component no longer
  rendered: a changed non-test file named it at the base and no non-test
  file but the module itself names it at head; names shorter than five
  characters never count); or opens a route whose Next.js `page`/`route`
  file (app or pages router) this change deleted (`page.goto("/x")`). The `@/` alias resolves to the repository's `src/`,
  its root, or the `src/` directory of the importing file's package.
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
- A package.json `test` (or `test:*`) script that existed at the base,
  followed through
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
  `node scripts/test.js` is given the benefit of the doubt). Path filters
  are evaluated against the test files that existed at the base, as for
  the config settings above (Jest `--testPathIgnorePatterns`/
  `--testPathPattern`/test paths as regular expressions, Vitest `--exclude`
  as a glob and test paths as substrings, Mocha `--ignore`/`--exclude`/spec
  paths as globs): one that leaves out no existing test file is not
  reported. An ignore pattern whose files another package.json script
  selects (`"test:integration": "jest --testPathPattern=integration"`) is
  not reported when a CI workflow at head runs that script: the tests moved
  to their own step. A `test` script the base did not have ran nothing
  before, so it loosens nothing.

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
test_special_casing = "block"
silenced_checks = "advise"
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

## Code doesn't special-case the tests (SKY-A115, A116, A117)

An agent that cannot make a test pass can change the tests (the checks above)
or change the code so that it recognises the test instead of doing the work.
Frontier models increasingly do the second. This check reads only lines the
change added to non-test Python and JavaScript/TypeScript files; code that
was already there at the base, including code moved between the changed
files, never counts.

**Hard-coded test answers (SKY-A115).** An added `if`/`elif`, conditional
expression, `match` or `switch` case, or lookup table (`{3: 6}[n]`,
`TABLE.get(n)`, `new Map([[3, 6]]).get(n)`, also through a key built just
before: `key = (n, k); TABLE[key]`) that compares an input with a literal
and returns, prints or assigns a literal (`a, m = 2, 7` answers "2 7" to a
program whose output is checked). Skylos reads the
assertions of the tests: `assert f(3) == 6`, `self.assertEqual`, pytest
`parametrize` rows and `for` loops over literal rows, `expect(f(3)).toBe(6)`
and its `toEqual`/`toStrictEqual`/Chai forms, `assert.equal`/`strictEqual`/
`deepEqual`, `t.is`, `.each` tables, a result first stored in a local, and
helpers like `def check(candidate)` called as `check(f)`. JSON test data with
`input` and `output` strings (programs fed on stdin, or one JSON value per
argument) counts too. Conversions in the comparison are followed:
`str(xs) == "[1, 2, 3]"`, `JSON.stringify(xs) === "[1,2,3]"`, `.lower()`.

It blocks only when all of these hold, and is advice otherwise:

- the input and the answer come from the **same assertion**;
- the test calls the function (or its class), imports its module, or is the
  runner of the program's test data;
- that assertion was already there at the base: a test written in the same
  change may simply have been written for this code;
- the function also works its answer out some other way: a function that is
  nothing but a table keyed by one value (a status-code map) is advice. A
  table keyed by several inputs or by a whole list is a table of test cases
  and blocks either way;
- an input is test data: a number other than 0, 1 or -1, a collection, or a
  string that is not a single word. A single word (`"warn"`, `"active"`) is
  usually a keyword or an enum value: advice. An ID with digits
  (`"AB-1234"`, `"u_9f3a"`) is data, not a word;
- the pair is too particular to be a natural edge case: a number of two or
  more digits, a collection or text that is not one word on either side, or
  two or more inputs compared. `if n == 2: print("No")` is advice;
  `if n == 5: return 121` blocks;
- no string involved already appears, quoted, in a non-test file at the base
  (a documented keyword, a shared constant). Text the change itself adds does
  not count: the change cannot vouch for itself;
- the file is not generated (`@generated`, "do not edit", `_pb2.py`,
  `dist/`), and is not a new script nothing imports or runs: agents write
  `verify.py`-style helpers and scratch copies of the solution that read the
  test data on purpose. A new file counts once something at the base, a
  file the change edits or a test imports it or names it.

Never reported: comparisons with trivial values only (0, 1, -1, empty, None,
booleans), so `if n == 0: return 1` base cases and singular wording pass;
answers that are trivial values; answers that restate the input (`"90"` to
`90`); tests whose expected value comes from the code
(`assert clamp(9) == MAX_SIZE`). Also advice: a new branch returning a
literal for an input a test passes with a different expected value, and a
result that depends on a module-level call count (`_calls[x] == 2`), which
can tell repeated test calls apart.

Message: `factorial() returns 121 when n == 5, the exact input and answer of
tests/test_math.py::test_factorial: this special-cases the test instead of
computing the answer` (the location is the finding's file and line).

**Test detection (SKY-A116).** Added production code that asks whether a
test runner is running it: the variables pytest sets while it runs
(`PYTEST_CURRENT_TEST`, `PYTEST_VERSION`, `PYTEST_XDIST_WORKER`; not
settings such as `PYTEST_ADDOPTS` that a tool starting pytest reads),
`"pytest" in sys.modules`, `sys.modules.get("pytest")`, `sys.argv` checked
for pytest or unittest, `sys._called_from_test`, the call stack inspected
for a test; `process.env.JEST_WORKER_ID`, `VITEST`, `VITEST_WORKER_ID`,
`VITEST_POOL_ID`, `NODE_TEST_CONTEXT` and Playwright's `TEST_WORKER_INDEX`/
`TEST_PARALLEL_INDEX`, `typeof jest`/`vi`/`mocha`/`jasmine`,
`globalThis.jest`/`vi`/`describe` and the like (`typeof describe` alone is
too common a name to count), and `import.meta.vitest` outside a Vitest
in-source test block. Production code that opens the tests' own files
(`open("test_cases.json")`, `readFileSync("tests/cases.test.json")`,
`Path(...) / "test_x.py"`, also through a constant) blocks too. The tests'
files include golden output and fixtures of any type under a test folder
(`tests/data/expected_report.txt`, `__snapshots__/*.snap`), and joined paths
count (`Path(__file__).parent / "tests" / "data" / "x.txt"`,
`os.path.join(..., "tests", "x.txt")`, `join(__dirname, "..", "test", "x.md")`)
as long as the path goes through a test folder; from a new
script nothing imports or runs (a local checker the agent wrote) it is
advice, and so it is from repository tooling that checks the tests: a file
under `scripts/`, `script/`, `tools/`, `tooling/`, `bin/`, `.github/`,
`ci/`, `.ci/` or `hack/`, or named `validate-*`/`check-*`/`verify-*`/
`lint-*`/`audit-*`, that no non-test, non-tooling source file imports or
names (a validator that confirms a test file still has its required
titles). Tooling that production code imports blocks like production code. `NODE_ENV === "test"`, `import.meta.env.MODE === "test"` and
environment variables compared with `"test"` are advice: many applications
switch on them on purpose. Left out: test files and directories,
`conftest.py`, setup files (`setupTests.*`, `*.setup.*`), config files
(`*.config.*`, `settings.py`, `config/`, `setup.py`, `noxfile.py`), pytest
plugins (files that import pytest or define `pytest_*` hooks), files that
import a test framework, and writing a file (`open(path, "w")`).

**Rigged comparisons (SKY-A117).** An added `__eq__` that always returns True
or never looks at the other value, `__ne__` that always returns False,
`__contains__` that always returns True (also set as a lambda or patched on
a class later); JavaScript `equals()`/`isEqual()` that always returns true or
ignores its argument, `compareTo()` that always returns 0, `valueOf()` or
`[Symbol.toPrimitive]` returning a constant. Advice: ordering methods that
return a constant (fine for a sentinel that sorts last), a constant
`__hash__`, a constant `__str__`/`__repr__`/`toString()`/`toJSON()` equal to
a string a test expects, and classes named like a wildcard (`ANY`,
`_AnyValue`, `Wildcard`, `Matcher`). `__eq__` returning `NotImplemented` or
comparing fields is never reported.

**What still gets past.** The check is static and literal:

- inputs recognised in a roundabout way (`if sum(xs) == 6`,
  `if len(s) == 5`, a hash of the input);
- special cases deep in the call stack whose literals differ from the test's
  (the test passes a string the code parses);
- tests whose inputs or answers are built at run time (fixtures, factories,
  files the test reads);
- small pairs (`if n == 3: return 7`) and a whole function replaced by a
  table of the tests' answers keyed by one value are advice, since they
  cannot be told apart from a real edge case or lookup table;
- recorded call state is advice and only for module-level counters; state on
  `self` or in closures is not followed;
- test detection through a variable the project defines itself (`TESTING`),
  or through an imported helper.

**When it blocks real code.** A function written test-first whose
specification is itself a particular literal mapping (the test at the base
says `label("Untitled document") == "New doc"` and nothing else in the code
or docs mentions that text) looks exactly like a special case. Quote the
text in the docs or a constant at the base first, or set
`test_special_casing = "advise"` (or `"off"`) in `[tool.skylos.done.checks]`
at the base.

## Linters, type checkers, scanners and CI not silenced (SKY-A118, A119, A121)

The tests are one gate; linters, type checkers and scanners are others. An
agent that cannot make one of them pass can tell it to look away instead of
fixing the code: an inline `# noqa`, a rule turned off, a directory
excluded, `strict` turned off, `|| true` on the CI step. This check compares
the base and the head the same way for every tool. Only the change counts:
added lines for inline suppressions, changed settings and CI files for the
rest.

The check advises by default. In a study of 450 merged pull requests by five
coding agents, none silenced a check deliberately: every suppression,
`continue-on-error`, coverage pragma and exclude had a visible reason or was
conventional. Over those 450 pull requests it lists something for 51
(0.34 findings per pull request, at most 20, almost all inline
suppressions); over 160 recent commits of three projects, for 3. A team that
wants the gate can set `silenced_checks = "block"` at the base: weakened
settings (SKY-A119) and CI (SKY-A121) then block, and inline suppressions
(SKY-A118) stay advice. At most 20 findings are listed; the rest are
counted.

**Settings weakened (SKY-A119).** Each tool's settings are read from
every file it reads in one directory and compared as a whole, so moving
settings between those files (`setup.cfg` to `pyproject.toml`, `mypy.ini` to
`[tool.mypy]`, `.eslintrc.json` to `eslint.config.js`) is not a change.
Reported:

- a rule newly ignored or disabled: ruff, flake8 and pylint ignores and
  per-file ignores, mypy `disable_error_code`, bandit `skips`,
  golangci-lint `disable`; a rule dropped from ruff `select`, pylint
  `enable`, mypy `enable_error_code`, golangci-lint `enable`, bandit
  `tests`. Ignoring a ruff code no selected rule covers changes nothing and
  is not reported; replacing a rule with a broader one (`I001` with `I`) is
  not either;
- a rule turned off or lowered (`error` to `warn`, `deny` to `allow`) in
  ESLint (legacy and flat config, also per `files` block), Biome, pyright
  `report*` settings and Cargo `[lints]`, and an ESLint preset dropped
  (`plugin:x/recommended`, `tseslint.configs.recommended`; swapping it for
  another preset of the same plugin is not reported);
- strictness turned off: TypeScript `strict` and the flags it implies
  (`noImplicitAny`, `strictNullChecks`, ...), `noUncheckedIndexedAccess`,
  `noImplicitReturns`, `checkJs` and the like, followed through local
  `extends`; `allowUnreachableCode` and other flags that stop checks turned
  on; mypy `strict` and its flags, `ignore_errors` (also per module),
  `follow_imports = skip`; pyright `typeCheckingMode` lowered; pylint
  `fail-under` lowered; Biome's linter or recommended rules turned off;
  golangci-lint `disable-all`, `default: none` or `issues.new`; SonarQube
  `sonar.qualitygate.wait` turned off; CodeQL default queries disabled;
  `skipLibCheck` is not a weakening, and `strict` going off is reported
  once, not once per implied flag;
- a path newly excluded or ignored (ruff, flake8, pylint, mypy, pyright,
  bandit, tsconfig `exclude` and a narrower `include`, ESLint `ignores`/
  `ignorePatterns`/`.eslintignore`, Biome, `sonar.exclusions` and
  `sonar.coverage.exclusions`, `.semgrepignore`, CodeQL `paths-ignore`,
  Snyk, golangci-lint, pre-commit `exclude`). Skylos matches the pattern
  against the repository's files and names one that the tool no longer
  checks. A pattern that matches nothing the tool checks, or only build
  output, dependencies, generated or vendored files (`dist/`,
  `node_modules/`, `*.min.js`, `*.d.ts`, `migrations/`, ...), is not
  reported; one that matches only test files is advice;
- a finding or secret allow-listed: a new line in `.gitleaksignore` or
  `.trivyignore`, a new `[allowlist]` entry in `.gitleaks.toml`, a new secret
  in detect-secrets' `.secrets.baseline` (keyed by its hash, so a known
  secret on another line is not new), Snyk and OSV-Scanner ignores, SonarQube
  `sonar.issue.ignore.*` criteria, CodeQL `query-filters` excludes,
  golangci-lint exclusion rules, Checkstyle and SpotBugs suppression files,
  pre-commit hooks removed or moved to `stages: [manual]`.

Settings Skylos cannot read with confidence contribute nothing: a config
exported as a function, built from a spread or from values it cannot
resolve, or a file that does not parse. A value inherited from a package
(`"extends": "@tsconfig/strictest"`) is never assumed. A tool's settings
appearing in a directory that had none apply only to files that existed
there at the base, and a rule a new config leaves off was never on; a new
package (a directory with no code at the base) and its first settings
weaken nothing.

**CI weakened (SKY-A121).** In changed GitHub Actions workflows and
GitLab CI files, a step is a check when it runs a linter, type checker,
format check or scanner directly (`ruff`, `eslint`, `mypy`, `tsc`, `prettier
--check`, `cargo clippy`, `golangci-lint`, `semgrep`, `gitleaks`, `npm
audit`, ...), through a wrapper (`npx`, `uv run`, `poetry run`, `python
-m`), through a script or target named for a check (`npm run lint`, `pnpm
typecheck`, `make lint`, `just lint`, `tox -e lint`, `turbo run lint`, `nx
run-many -t lint`, `deno task lint`, any `<tool> run <script>`; scripts of
the root package.json are followed to the tools they run), or through a
known action
(`github/codeql-action/analyze`, `golangci/golangci-lint-action`,
`astral-sh/ruff-action`, `pre-commit/action`, SonarQube, Snyk, Trivy,
gitleaks, ...). A step that also runs tests is a test step (SKY-A112).
Reported:

- a check that can now fail without failing the build:
  `continue-on-error: true` on the step or its job, the failure swallowed in
  the script (`|| true`, `|| echo ...`, `; true`, `; exit 0`, `set +e`; an
  unrelated command's `|| true` in the same step does not count),
  `--exit-zero`, `--exit-code 0`, `--issues-exit-code=0`, `--max-warnings`
  raised or dropped, `semgrep --error` dropped, a higher `npm audit` level,
  new `--ignore`/`--skip` options, action inputs such as `fail-on-error:
  false` or `soft_fail: true`; GitLab `allow_failure` and `when: manual`. A
  check that is new in the change was never required, so adding it quietly
  is not a weakening;
- a check that no longer runs: its step or job removed, unless the same tool
  still runs in any workflow, composite action or GitLab file at head (a
  renamed step, a step moved to another workflow, a switch of package
  manager and a check moved into a root package.json script are not
  removals); `if: false` or `when: never`;
- a workflow with checks that no longer runs on pull requests (or, without
  pull-request triggers, on pushes);
- an aggregate job (one that checks out no code, such as a single required
  "all green" job) that no longer `needs` a job running checks.

Only workflows that can decide a merge count: those that run on
`pull_request`, `pull_request_target`, `merge_group`, `push` or
`workflow_call`, plus composite actions. A scheduled or manual workflow
(`schedule`, `workflow_dispatch`) never gated a change, so removing or
quieting its steps is not reported, and its steps do not count as still
running a check that left a gate. A step that cannot fail
(`continue-on-error`, `|| true`) does not count as still running it either.

Test steps get the same treatment here, as SKY-A121: removed, disabled, no
longer triggered, no longer needed, and GitLab test jobs that may fail. A
GitHub test step that may now fail stays SKY-A112 (test settings loosened,
which blocks by default). A workflow that runs Skylos is also gate
tampering (SKY-A114).

**Inline suppressions (SKY-A118, advice).** A comment or attribute on an
added line of non-test code that tells a tool to look away: `# noqa`,
`# ruff: noqa`, `# type: ignore` (at the top of a module: the whole file),
`# pyright: ignore`, `# mypy: ignore-errors`, `# pylint: disable`,
`# nosec`, `NOSONAR`, `# pragma: no cover`, `nosemgrep`, `gitleaks:allow`,
`pragma: allowlist secret`, `# skylos: ignore`; `eslint-disable`,
`eslint-disable-line`, `eslint-disable-next-line`, `oxlint-disable`,
`@ts-ignore`, `@ts-expect-error`, `@ts-nocheck`, `istanbul`/`c8`/`v8
ignore`, `biome-ignore`; Go `//nolint`, `//lint:ignore`, `#nosec`; Rust
`#[allow(...)]`/`#![allow(...)]`/`#[expect(...)]`; Java/Kotlin
`@SuppressWarnings`, `@Suppress`, `@SuppressFBWarnings`, `NOPMD`,
`CHECKSTYLE:OFF`; C# `#pragma warning disable`, `[SuppressMessage]`.
Comments are read with Python's tokenizer, the TypeScript grammar, or a
string-aware scanner for the other languages, so text in strings never
counts. A suppression is new only when the file holds more of
it (same directive, same rules) than at the base: moved, reindented and
edited lines that keep their suppression are not reported. The finding says
whether a reason is given (text after the directive, ESLint's `-- why`,
Biome's `: why`, Rust `reason = "..."`, SpotBugs `justification`, or a plain
comment on the line above; a placeholder such as `<explanation>` or `TODO`
is no reason) and whether it covers a whole file. `# pragma: no cover` on
`if TYPE_CHECKING:`, `if __name__ == "__main__":`, `raise
NotImplementedError` and similar lines is how coverage is told about code
that never runs, and is not reported. Also advice: `_ = x` (Python) and
`void x;` (JS/TS) added where that is the only use of the variable, which
hides an unused-variable warning instead of removing it.

Inline suppressions are advice, with or without a reason: replayed on
real projects' history, people add them routinely and mostly for good
reasons (`void _scans;` after destructuring a field away,
`eslint-disable-next-line @next/next/no-img-element` for a `data:` URL),
and blocking them would block ordinary commits. The receipt counts them
(`suppressions_added`, `suppressions_no_reason`, `suppressions_whole_file`)
so a reviewer or Cloud policy can watch the trend.

**Test files.** Suppressions in test files (the same test files as above,
plus Go `_test.go`) are counted (`suppressions_in_tests`) but not listed:
tests pass wrong types on purpose (`@ts-expect-error` is an assertion
there), pytest fixtures trip linters, and a test that is weakened is the
test checks' business. Settings and CI changes that exclude only test files
are advice.

**What still gets past.**

- a suppression added while an identical one elsewhere in the same file is
  removed (the count stays the same);
- settings Skylos cannot read (see above), tools not listed here (detekt,
  Psalm, PHPStan and RuboCop settings, `clippy.toml`, `.markdownlint`),
  threshold settings (`max-line-length`, `max-complexity`, `max-args`), and
  values inherited from a package;
- a removed ESLint rule entry, which falls back to whatever a preset says
  (only turning it off or lowering it is reported);
- CI other than GitHub Actions and GitLab CI, composite actions' own steps
  being weakened, matrix or expression values (`continue-on-error: ${{
  matrix.experimental }}`), `paths`/`paths-ignore` filters on triggers, and
  required status checks changed in branch protection (not in the
  repository);
- code written to dodge a rule without a suppression (renaming a variable to
  `_unused`, `foo.accessed = 1`): only `_ = x` and `void x;` are recognised.

**Known false alarms.** A lint step replaced by a command that Skylos cannot
tie to the same tool (a script name the root package.json does not define,
a wrapper it does not know) reads as the check being removed. Turning a
rule off or excluding a directory on purpose is reported too: it is a
policy change, and under `block` a person should make it (commit it to the
base first, or use Skylos Cloud's "Merge anyway").

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
