# The quality gate in Skylos Cloud

The quality gate answers one question for every uploaded scan: can this
change merge? This chapter says what PASS and FAIL mean, how the result
reaches a pull request, and what to do when you need to merge anyway.

Chapter 6 covers the gate the CLI runs on your machine (`skylos . --gate`).
The Cloud gate is decided by Cloud, from the workspace policy, when a scan is
uploaded.

## What PASS and FAIL mean

**For:** knowing why a scan failed before you start fixing.

Cloud checks an uploaded scan in this order:

1. If the gate is switched off in Policy, or the scan was merged anyway, the
   scan passes.
2. Any critical security issue that is not marked "Not fixing" fails the
   scan. This counts all code in the scan, old issues included.
3. With the default rule, **Block any new issue**, any new issue fails the
   scan. Existing issues do not.
4. With one of the "Allow a set number" rules, the scan fails when new issues
   go over a limit you set per category, per severity, or both.
5. Extra conditions you turned on in Policy can also fail it: exposed
   secrets, required scan coverage, and AI-code issues.

A pass means the scan is within your policy. It does not mean the code has
no issues.

![The gate result on a project's Overview. The conditions table lists each condition, its limit and what this scan had.](img/cloud/gate-fail-overview.png)

### New issues and existing issues

An issue is **new** when:

- the scan is of a pull request and the issue is on a line the pull request
  changed; or
- the scan has no pull request diff and the baseline scan has no issue with
  the same rule in the same file.

The **baseline** is the newest scan on the same branch that passed (or was
merged anyway). When the branch has none, Cloud uses the newest one on the
default branch.

### What a first scan does

A first scan has no baseline, so nothing in it is new. It can only fail on
the conditions that count all code: critical security issues, required
coverage and agent rules. The scan page says "First gate result on this
branch".

This also holds until a scan passes. A branch whose scans have all failed
has no baseline yet.

> A scan uploaded from a laptop with `skylos cloud` is an **unverified
> upload**. Cloud shows its result on the scan page only. It does not count
> for gate history, the GitHub check, trends or compliance reports. See
> "Get a first scan" for how to upload from CI.

## Read a failed gate

**For:** finding the issues that block a merge.

**Who:** any member of the workspace, on any plan.

1. Open **Home**. A failing repository is listed under **Needs action** with
   the number of blocking issues.
2. Select the repository. The **Quality gate** card shows FAIL, the branch
   and commit, and the **Quality gate conditions** table.
3. Select **Open the first blocking issue**, or pick one under
   **Blocking issues**.
4. Fix the issues, push, and let CI upload again. The next scan replaces the
   result.

![A failed pull request scan. (1) The result. (2) The failed condition. (3) Jump to the blocking issues.](img/cloud/gate-fail-scan.png)

**Gate history** on the project Overview shows how long the default branch
has been passing or failing.

## The check on pull requests

**For:** stopping a merge on GitHub while the gate fails.

**Who:** an owner or admin connects GitHub. The check works on every plan.

Cloud publishes a GitHub check named **Skylos Quality Gate** on the commit
of each scan uploaded from CI. It needs:

- the Skylos GitHub App installed on the repository (Project **Settings**,
  **Connect GitHub**); and
- a scan uploaded from CI, with OIDC or a CI project token. Unverified
  uploads never publish a check.

The check blocks a merge only when GitHub requires it. Project **Settings**
has a four-step **Merge blocking on GitHub** list that ends with a ruleset
named "Skylos Quality Gate" for the default branch. Until that is done, Home
and the Pull requests page say "Turn on merge blocking".

![Project Settings: the four steps. (1) Start with Connect GitHub.](img/cloud/gate-merge-blocking-steps.png)

### Comments on the pull request

On the Workspace plan, a scan uploaded with GitHub OIDC also gets:

- one summary comment, updated on each upload: the result, the conditions
  table, up to three blocking issues and a link to the scan;
- up to ten review comments on changed lines that have a new issue.

A scan uploaded with a CI project token gets the check but no comments.
Free workspaces get the check and its annotations, not the comments.

## Merge anyway

**For:** letting one failed scan merge, with a recorded reason. For example
a hotfix during an outage.

**Who:** an owner or admin, on the Workspace plan. The scan must have failed.

1. Open the failed scan.
2. Open **More actions** under the conditions and select **Merge anyway**.
3. Type the reason under "Why should this merge with a failed gate?" (at
   least 3 characters). It is kept for audit.
4. Select **Merge anyway** again to confirm.

![Merge anyway. (1) More actions. (2) The reason. (3) Merge anyway.](img/cloud/gate-merge-anyway.png)

![The same scan afterwards.](img/cloud/gate-merged-anyway.png)

**What happens next:** the scan's result changes to **OVERRIDDEN**, with
"Merged anyway · issues remain open". If the project is linked to the Skylos GitHub
App, the Skylos check on GitHub turns green, unless an agent rule still
blocks it. The issues stay open. A later upload of the same commit keeps the
override. The reason, the person and the time are listed under **Not
fixing**, **Merged anyway**, and in the audit log.

You can also reach it from a single issue: **Not fixing this**, then **Let
this merge anyway**.

**Common problems**

- **The button is missing.** You are a member or viewer, the workspace is on
  Free, or the scan did not fail.
- **The summary comment on the pull request still says failed.** The comment
  is only rewritten on the next upload. The check itself is updated at once.

## Free and Workspace

| | Free | Workspace, Growth, Enterprise |
|:--|:--|:--|
| Gate result on every uploaded scan | Yes | Yes |
| GitHub check and annotations | Yes | Yes |
| Rule for new issues | Block any new issue (fixed) | Any of the four rules |
| Change Policy | No | Yes |
| Merge anyway | No | Yes |
| Summary and review comments on pull requests | No | Yes |
| Scans kept per project | 10 | 500 (Enterprise 10,000) |
