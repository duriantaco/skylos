# Pull requests, Issues, Supply chain and the AI pages

These are the pages a team opens every day. All of them read from trusted
scans, so they stay empty until CI uploads.

**Who:** every member can read these pages, on every plan. Where a step
needs a role or a plan, the task says so.

## Pull requests

**For:** seeing which changes can merge, and why the others cannot.

Open **Pull requests**. Three views show the same pull requests:

- **List:** one row per pull request, grouped by repository, with the gate
  result and the number of new issues.
- **Board:** one column per state.
- **Pipeline:** each pull request's path from scan to merge.

The filters **All**, **Failing** and **Needs my team's approval** narrow
any view. **All uploads** (top right) lists every scan ever uploaded, with
who or what uploaded it.

The board's columns:

| Column | Meaning |
|:--|:--|
| Scanning | Skylos is checking the newest commit. |
| Needs fixes | The author's turn: the gate or a check failed. |
| Needs approval | The gate passed. A team must sign off (protected paths in agent rules). |
| Ready to merge | The Skylos check is green on GitHub. |
| Merged | Merged in the last 7 days. |

![The board. A failed pull request waits under Needs fixes.](img/cloud/work-prs-board.png)

The pipeline shows, for each pull request, the stages **Scan**, **Tests**,
**Review**, **AI review**, **Approval** and **Merge**. Select a stage to
open its scan, report or checks. A stage that has no data says why, for
example "Not uploaded: upload it with `--done-receipt`".

![The pipeline view.](img/cloud/work-prs-pipeline.png)

Select a pull request to open its scan. The page is the same as any scan
page, with "Pull request #45" in the header.

**Common problems**

- **"Skylos couldn't confirm merge blocking for this repository, so GitHub
  may still allow the merge."** The check exists but GitHub does not
  require it. Select **Turn on merge blocking** and finish the four steps.
- **A pull request is missing.** Only pull requests with a trusted scan are
  listed. A scan from a laptop does not add one.
- **Titles and states look old.** Pull request titles, authors and merged
  states come from GitHub through the Skylos GitHub App.

## Issues

**For:** one list of what is open across every repository, and who owns it.

An issue is a problem that scans keep finding in the same place. It is
**fixed** only when a newer trusted scan of the default branch no longer
finds it. Nobody can mark an issue fixed by hand.

1. Open **Issues**.
2. Search, or filter by **Severity**, **Type**, **AI review**,
   **Repository**, **Status** (Open, Fixed, Not fixing) and **Owner**
   (Everyone, Assigned to me, Changed by me).
3. Select an issue to open it. **History** on a row shows every scan it
   appeared in.

![Issues. (1) Search. (2) Status. (3) Owner.](img/cloud/work-issues.png)

The issue page has **How to fix it** with the code, a command to check the
fix on your machine, the **Evidence**, **Why it matters**, **Where it was
found** (every branch and scan) and **Comments**.

On the right:

- **Owner:** the team that owns it. "Automatic" follows the repository's
  CODEOWNERS file, which Skylos reads through the GitHub App. **Assignee**
  picks one person.
- **Not fixing:** the same choices as on a scan, plus "Not a problem in any
  repository?" for owners and admins.
- **Jira:** create or link a Jira ticket, once Jira is connected.
- **Details:** when it was first and last seen.

![An issue. (1) Owner and assignee. (2) Not fixing.](img/cloud/work-issue-detail.png)

Comments, assignees and team owners need the Workspace plan. The number
next to **Issues** in the sidebar counts open issues assigned to you.

## Supply chain

**For:** knowing whether your packages and your install steps are safe.

**Who:** everyone can read it. An owner or admin sets the policy. The
exposure tools need the Workspace plan. Nothing here uses credits.

Open **Supply chain**. The line under the title sums it up, for example
"No malicious packages · 4 of 4 repositories send package lists · 2
repositories fail install checks".

![Supply chain. (1) Set supply-chain policy.](img/cloud/work-supply-chain.png)

The page has four parts:

- **Dependency vulnerability monitoring.** Between scans, Skylos checks the
  exact npm and PyPI versions in your latest uploaded package lists against
  public advisories. A new advisory for a package you already use raises an
  alert without a new scan. It covers public registry packages only. If
  the panel says monitoring is "paused by the service operator", it is not
  running on your service yet.
- **Malicious packages.** Skylos checks your latest package lists against
  the public malware advisories every hour. **Check a package or GitHub
  Action that is not in the feed yet** lets you ask about one by name.
- **Install safety by repository.** Six checks per repository: lockfile
  committed, CI installs from the lockfile, install scripts off, waits
  before new releases, Actions pinned to a commit, and no
  `pull_request_target` checkout. Each is PASS, FAIL or N/A.
- **Exposure** (Workspace plan). When a package turns out to be malicious:
  "Show what it reached and what to rotate" lists the repositories, jobs
  and secrets it could touch.

Package lists come from scans. Upload again when dependencies change.

**Alerts** go to the project's Slack or Discord channel and to webhooks.
There is no email for supply-chain alerts today.

**Set supply-chain policy** opens the Supply chain part of Policy.

## Coding agents and agent checks

**For:** seeing what AI coding agents write and how often their pull
requests are blocked.

**Coding agents** appears in the sidebar where the Skylos service has agent
checks switched on. It needs pull request scans from the Skylos workflow:
the workflow's `done` job runs your tests, compares the branch with its
base and reports which commits credit an AI agent.

Once pull requests are scanned, the page shows, for a period of 4, 12 or 26
weeks: how many agent pull requests were checked, how many were blocked,
and which checks blocked them. **Agent checks** lists each check result.
**Choose which checks block** opens the agent rules in Policy.

Repositories that run Skylos in their own CI can send the same data:

```bash
skylos done --base origin/main
skylos cloud --done-receipt <path it prints>
```

![Coding agents before the first agent pull request. The page says what to connect.](img/cloud/work-coding-agents.png)

> The screenshot shows the empty state. The local copy of Cloud used for
> this guide has no GitHub App, so no pull request could be tied to an
> agent.

## AI app safety

**For:** checking that the AI features in your own code (calls to language
models) have safeguards: input checks, output checks, limits, logging.

**Who:** a member, admin or owner uploads. Everyone can read.

1. In the repository, run `skylos defend . --upload`. Or add it to CI with
   `skylos cicd init --defend`, so every push to the default branch updates
   the page.
2. Open **AI app safety**. Each checked repository has a score, the number
   of checks passed and the number of AI features found.
3. Select a repository for the detail.

The detail page shows the **AI app safety score**, the **Ops score**, the
integrations found, coverage against the OWASP Top 10 for LLM applications,
and two lists: **Missing safeguards** and **Safeguards in place**.

![The top of the detail page for one repository: the AI app safety score, the Ops score and the AI integrations found.](img/cloud/work-ai-app-safety-detail.png)

`skylos discover` lists the AI integrations in a codebase on your machine.
It has no upload. Only `skylos defend --upload` sends results to this page.
Repositories without AI features never show here.

## Deep scans

**Deep scans** is an AI security review of a whole repository. It appears
in the sidebar only where the Skylos service has it switched on. It needs
the Skylos GitHub App, your workspace's own Anthropic API key (**Settings**,
**API & keys**, **API keys**) and 10 credits per scan, refunded when a scan
produces no report. You pick a spending limit for each scan. The page lists
every run with its cost and findings.

## Trends and the codebase views

- **Home**, **Last 12 weeks:** the quality gate on default branches, issues
  opened and fixed, and agent pull requests blocked. Each chart has **Show
  as a table**.
- **Trends:** per project, findings over time for each check. Reach it from
  the project's **More** menu, or **All uploads**, then **See trends over
  time**. It appears after 3 scans of a branch.
- **Compare two scans:** on **All uploads**. Shows what is new and what is
  gone between two scans.
- **Coverage details** (Home, **Which repos are scanned**): scanned
  projects, failing gates, open critical and high issues, overdue issues
  and the median time to fix.

A project's **More** menu also has **Code attribution** (which code AI
tools wrote), **Agent PR log**, **Logic changes** (a report of behaviour
changes per pull request, 1 credit per pull request once turned on),
**Technical debt**, **Investigate** and **Required controls**.
