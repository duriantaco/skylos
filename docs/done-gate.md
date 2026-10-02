# Done gate (`skylos done`)

`skylos done` decides whether a change is finished, with evidence. It runs
the tests itself, compares the tests and test settings with the base, looks
for edits to Skylos's own settings and for added secrets and made-up imports,
then writes a receipt.

It gives no opinions and writes no style comments: each check passes or
fails with evidence, the way CI does.

```bash
skylos done                     # uncommitted changes, compared with HEAD
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
`origin/main`, otherwise from HEAD. A change cannot loosen its own gate.

```toml
[tool.skylos.done]
test_command = "pytest -q"        # run without a shell; default: pytest, if found
test_budget_seconds = 300         # 10 to 3600
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
`PYTEST_PLUGINS` from the test environment. Other commands are judged by their
exit code unless `junit_xml` names the file they write.

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
      - run: pip install skylos -e .
      - run: skylos done --base origin/${{ github.base_ref }}
```

Make the job a required status check so agents without hooks are covered too.

## Not yet

- JavaScript/TypeScript test inventories (Jest, Vitest, Mocha).
- The agent stop hook and session base; `skylos done init`.
- Rerunning a failing test on the base to call it pre-existing.
- Complete inventory of computed parametrization and exclusions of individual
  parameter cases. These produce an unfinished test check when Skylos cannot
  prove the expected case total. Literal lists, tuples and simple module-level
  constant aliases are supported.
