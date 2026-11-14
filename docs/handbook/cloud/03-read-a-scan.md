# Read a scan

A scan is one run of Skylos on one commit. This chapter walks from the
project's Overview to a single issue and the reason it was flagged.

**Who:** every member, including viewers, on every plan. Downloading the
issues needs the Workspace plan.

## The project Overview

Open **Home** and select a repository.

The **Can we ship?** card answers in one line, for the latest trusted scan
of the default branch: "Safe to merge: gate passed" or "Not safe to merge:
4 blocking issues". Under it:

- **Top risks:** the issues to fix first. Select one to open it.
- **Issues in this scan:** the count by type. Select a number to open that
  list. "More advice, not counted" are suggestions that never block.
- **What wasn't checked:** a check that did not finish, for example a
  dependency lookup. The scan is judged on what was checked.

![The top of a project's Overview.](img/cloud/scan-project-overview.png)

The tabs across the top are **Overview**, **Issues**, **Pull requests**,
**Scans**, **Settings** and **More**. The branch menu under the project
name switches between branches and pull requests that have a scan.

## The quality gate result

Every scan page starts with the gate result: **PASS**, **FAIL**,
**OVERRIDDEN** (merged anyway) or **UNVERIFIED**. Next to it are the
project, branch, commit and time, then the **Quality gate conditions**
table. The next chapter explains the result.

## The issue list

Below the result, **All issues** lists what the scan found, grouped by
file.

1. Type in **Search message, file, or rule** to narrow the list.
2. Select a type to filter: **All**, **Security**, **Quality**, **Dead
   code**, **Dependencies**. The number is the count in this scan.
3. Select an issue to open it on the right.

![The issue list. (1) Search. (2) Filter by type. (3) An issue that blocks the merge.](img/cloud/scan-issue-list.png)

Each row shows the rule ID, the severity, the message and the line. A tag
on the right says how the gate treats it:

| Tag | Meaning |
|:--|:--|
| Blocks merge | This issue counts toward a failed condition. |
| NEW | New in this scan, compared with the baseline. |
| FIRST SCAN | Found in the first scan of the branch. Nothing to compare with, so it is not "new". |
| NOT NEW | It was already in the baseline scan. It does not block. |
| NOT FIXING | Someone decided not to fix it. It stays in the list. |

The button at the top right of the list filters by status. **Show all
advice** adds the suggestions that are measured but not counted.

> Selecting a file name folds that file's group. Select the message line to
> open an issue.

## Why an issue was flagged

Select an issue. The right side shows:

- a banner when it **blocks the merge**, with the condition it counts
  toward;
- the severity, rule ID, title, file and line;
- **Why this was flagged:** the rule, what the scanner reported, what the
  rule checks, why it matters, the weakness type (CWE) and the function it
  is in;
- **How to fix it** and what to avoid, for the language of the file.

![An open issue. (1) Fix. (2) Not fixing this. (3) This looks wrong.](img/cloud/scan-finding-why.png)

The buttons at the top:

| Button | What it does |
|:--|:--|
| Similar issues | Other issues from the same rule. |
| Fix | A fix brief, or an AI fix pull request. See "Fix pull requests and cleanup". |
| View flow | The path the data took, for security issues that have one. |
| Not fixing this | Record a decision. See "Decide on issues". |
| This looks wrong | Tell Skylos the scanner is wrong. It does not change the scan. |
| Issue history | Every scan this issue was seen in. |

## Source, evidence and flow steps

For a security issue found by following data through the code, **Security
evidence** names the **Source** (where untrusted input enters), the
**Sink** (where it does harm), the number of steps between them, the guards
the scanner saw and the guards that are missing.

**Source** shows the flagged line with a few lines around it.

1. Select **View flow** to see every step: "Untrusted input", each "Passes
   through", and "Reaches". Each step names the file and line.
2. Select **Show more of this file** to load 30 lines above and below.

![Security evidence and source. (1) View flow. (2) Show more of this file.](img/cloud/scan-finding-evidence.png)

![The flow of a SQL injection: from the request, through two functions, to the query.](img/cloud/scan-flow.png)

**Open in editor** opens the file and line in your own editor. **Open this
line on GitHub** opens it on GitHub.

**Common problems**

- **"Code not shown: Install the Skylos GitHub App on this repository to
  load more of this file."** Skylos stores only the few lines the CLI
  uploaded. More of the file, and the code of flow steps, is read from
  GitHub when you ask. That needs the GitHub App on the repository.
- **No "View flow" button.** The rule matched a pattern on one line. No
  data path was recorded.

## Download or share a scan

**Who:** downloading needs the Workspace plan. Sharing a link needs an
owner or admin.

At the bottom of the scan page, under **Download or share**:

1. Select **Download issues**, then **Download JSON** or **Download CSV**.
2. Or select **Share a read-only link** to make a link that shows this scan
   without signing in.

**Share with your CTO** on the Overview opens a one-page summary of the
project made for sharing.
