# Regression replay and agent test grading

Skylos runs the same submitted test against fixed and buggy code. A useful
regression test passes on the fixed code and repeatedly fails at the expected
assertion on the buggy code. Setup errors and inconsistent attempts are
inconclusive. Add independently validated correct alternatives to check whether
a test relies on implementation details.

In Skylos Cloud, open **Coding agents → Test grading** from the dashboard
sidebar. The workspace opens with no results until you select a JSON file.
For a worked example, open **Benchmarks → Agent test grading**, then choose
**Open example report**. **Scanner regression evidence** links to the same
public example from its page.

Use this to evaluate one committed pytest case against a fix and specific
production-code variants. Every run starts from a fresh archive of the fixed
commit. Skylos keeps its tests, fixtures, and settings, then substitutes only
the Python source files you name. This supports new tests that did not exist at
the buggy revision. Choose files that capture the entire behavior change you
want to replay.

Use a Skylos build whose `skylos done replay --help` shows the replay-specific
flags. Install pytest and the target project's dependencies in the same
Python environment. Run from the target repository, or pass `--repo PATH`.
Use a trusted repo because the test processes run with your local permissions.

```bash
skylos done replay \
  --fixed 7372b5f2 --buggy '7372b5f2^' \
  --source skylos/reporting/result_builder.py \
  --test test/test_typescript_expanded.py::TestMixedRepoIntegration::test_project_ignore_suppresses_e004 \
  --expect-assertion 1520 --allow-local-execution
```

Use `--repo PATH` for another Git repository. Repeat `--source` for a fix
spread across Python files, `--buggy` for other known-bad variants, and
`--correct` for independently validated alternative implementations. For a
parametrized test, select one concrete pytest case, including its `[case-id]`.

Every variant is tested twice. The JSON receipt records the exact commits,
test digest, results, and the source line and message of any qualifying
assertion failure.

| Verdict | Meaning |
| --- | --- |
| `DETECTED` | The fixed revision and any supplied correct variants pass, and every buggy variant fails at an `assert` in the selected test file. If you supplied an assertion line, each failure occurs there. |
| `BUG_SURVIVED` | A supplied buggy variant passes the selected test. |
| `REJECTED_CORRECT_VARIANT` | The test fails an assertion against a supplied correct variant. |
| `REFERENCE_FAILED` | The test fails an assertion on the fixed revision. |
| `UNEXPECTED_ASSERTION` | The test fails on the buggy variant at an assertion other than the supplied line. |
| `INCONCLUSIVE` | The runner could not establish a result, such as when setup or collection fails, the test skips, or the two runs disagree. |

Exit status is 0 for `DETECTED`, 2 for `INCONCLUSIVE`, and 1 for the other
verdicts. Replay expects ordinary Python `assert` statements in the
selected test file. Other forms of failure, including an exception raised
directly by production code, produce an inconclusive result. It uses
committed regular files and installed dependencies. Changes that require a
different fixture, dependency, config, or file layout are outside its scope.

Variant labels are supplied by the caller. The receipt shows what this
particular test did on those variants. Measuring whether the proposed test
adds detection beyond the existing suite would require a separate baseline
suite run. Replay reports its own verdict separately from the Done gate.

## Replay on a pull request in Skylos Cloud

This opt-in preview needs the updated Cloud-generated GitHub workflow and a
CLI build that includes `skylos done replay`. Start with one repository-root
Python project whose **Skylos Done** job already runs pytest and uploads a
receipt. Merge a reviewed `.skylos/regression-replay.json` into the default
branch before opening the fix PR. This plan selects a test for a sorting fix.

```json
{
  "schema_version": 1,
  "test": "tests/test_sorter.py::test_unsorted_input",
  "source_files": ["src/sorter.py"]
}
```

Name one concrete pytest case and up to five regular Python production files
that exist at both revisions. Use the optional `expected_assertion` field
to specify a positive line number in the PR's test file. The test can be
added by the PR because both versions use the PR's test and fixtures. Choose
files that cover the whole regression you want to check. If the old behavior
needs a different dependency, fixture or file layout, try a curated local
replay with compatible variants.

When the PR changes any selected source file, CI runs the case twice on the PR
commit and twice with the listed files restored from the Git merge base. Open
the PR's result in **Agent checks** and look for **Regression replay**. The
card shows which versions ran, what each attempt did and the GitHub Actions
run that reported it. A passing replay means the test repeatedly caught
the restored behavior in this case. The result is advisory.

If the card is absent, confirm the workflow and CLI versions, verify the
plan is on the PR's base branch, and check the current GitHub Actions run.
The workflow can skip replay if the required Done checks used most of the
publication time budget.
Open [Test grading](https://skylos.dev/benchmarks/agent-tests) to inspect
manually saved benchmark reports in the browser.

## Compare two tests

Add `--baseline-test FILE::TEST` to compare a committed baseline test with
the candidate selected by `--test`. Both use the same fixed snapshot, pinned
variants, and number of attempts. Each buggy variant reports whether both
tests caught it, both missed it, or exactly one caught it. A failure on a
known-correct control invalidates the comparison.

`IMPROVED` means the candidate catches an additional variant and retains
each detection made by the selected baseline case. `REGRESSED` means it
loses a detection without adding one. `MIXED` means both happened.
`NO_CHANGE` means both cases caught the same variants. The paired invocation
exits 0 for `IMPROVED`, 2 for `INCONCLUSIVE`, and 1 otherwise. The receipt
includes both arms and their per-variant comparison. The baseline is one
selected case, so this result measures the difference between those two cases.

## Grade submitted tests

The grader uses a reviewer-owned manifest with full commit IDs and explicit
source paths. Each case requires a passing fixed control and at least one
known-buggy variant. Add independently validated alternative fixes to the
case's `correct` array when available. The submission selects a test per case
without controlling those variants. For a new agent-written test, use
`{"test": "tests/test_new.py::test_behavior", "revision": "<commit>"}` as the
selection. Only that new test file is read from the submission commit.
A string selects an existing test from the fixed snapshot for a reference run.

```bash
python -m skylos.done.replay_grade \
  --manifest benchmarks/regression_replay/manifest.json \
  --submission benchmarks/regression_replay/reference-submission.json \
  --allow-local-execution > agent-test-grade.json
```

The report counts every assigned case, including omitted tests and
inconclusive runs. It grades the submitted tests for these reviewed cases.
The reference submission contains historical maintainer tests. It supplies
a control for the grader before measuring agent performance.

Open the JSON report in Skylos Cloud at `/benchmarks/agent-tests`. The page
renders local files in the browser. An opened file carries no Cloud
verification or commit attestation.

### Read a report

1. Check the submission label and the counts. **Passed** means the test
   caught the assigned buggy variants and accepted the supplied correct
   code. **Failed**, **Inconclusive**, and **Missing** stay visible in the
   totals.
2. Read what the test sets up, what it asserts, the buggy behavior, and
   what the fix changes. These descriptions come from the case's optional
   `context` in the reviewer-owned manifest. Use `test_setup`, `assertion`,
   `buggy_behavior`, and `fix` for those four fields.
3. Compare the fixed and buggy commit rows. A failed assertion on buggy
   code is the expected outcome when the same test passes on fixed code.
   A baseline column, when present, shows the selected baseline test's
   result on those same revisions.
4. Expand **Test, changed files, and run details** to inspect the test ID,
   the source paths swapped in the replay, full commit IDs, and both
   attempts with their assertion lines and messages.

**Where it fits.** Test grading evaluates submitted tests on reviewed cases.
Agent Checks handles pull request checks and merge policy. Scanner regression
evidence measures the scanner on its own fixtures. The same Cloud report viewer
serves the workspace and the public benchmark page.
