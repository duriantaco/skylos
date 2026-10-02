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
| No tests deleted, skipped or weakened | SKY-A110, SKY-A111, SKY-A112, SKY-A101 (advice) | yes | A test that existed at the base is gone (a moved or renamed test is not), lost parametrize cases, or gained skip/xfail. Test settings loosened: pytest `-k`/`-m`/`--deselect`/`--ignore`/`--lf`/`-p no:`, `norecursedirs`, `testpaths`, `conftest.py` hooks that can drop tests or rewrite results, `collect_ignore`, lower coverage floors, CI test steps that may now fail. Weakened assertions (SKY-A101) are shown as advice. |
| Skylos settings and hooks left alone | SKY-A114 | yes | Edits to `protected_paths`, to `[tool.skylos]` in pyproject.toml, or to a CI workflow that runs Skylos. |
| No secrets added | SKY-S101 | yes | Secrets on added lines. A suppression comment added in the same change does not count. |
| Every package and import is real | SKY-D222, SKY-D225, SKY-D223 (advice) | advise | Added imports and dependencies resolve to real, declared packages. Names that only cannot be tied to a declared package are advice. |

A deleted test that directly references a deleted production module is
reported as a feature removal (advice). Renaming a module or deleting an
unrelated module does not qualify.

Python inventories include unchanged test files. Base marker and name
selectors are evaluated against the matched base test's metadata, so adding
a marker or renaming a test cannot newly excuse its absence. Runtime
deselection by a hook is insufficient evidence of a trusted exclusion;
unexplained missing tests produce an unfinished result.

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
```

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

- JavaScript/TypeScript test inventories (Jest, Vitest, Mocha).
- `skylos done init`, automatic test selection and passing-result caching.
- Authenticated organization-policy sync into local Done checks and automatic
  session-receipt upload to Cloud.
- Rerunning a failing test on the base to call it pre-existing.
- Complete inventory of computed parametrization and exclusions of individual
  parameter cases. These produce an unfinished test check when Skylos cannot
  prove the expected case total. Literal lists, tuples and simple module-level
  constant aliases are supported.
