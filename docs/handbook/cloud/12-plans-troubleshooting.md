# Which plan do I need, and troubleshooting

## Which plan do I need for X

"Workspace" below also means Growth, Enterprise and the 14-day trial.
Credits are bought separately and work on every plan.

| I want to | Plan | Role | Credits |
|:--|:--|:--|:--|
| Upload scans from CI or a laptop | Free | Member | 0 |
| See the gate result, issues and why each was flagged | Free | Viewer | 0 |
| Get the Skylos check on pull requests | Free | Admin connects GitHub | 0 |
| Scan more than 1 project | Workspace (10), Growth (50) | Member | 0 |
| Keep more than the newest 10 scans of a project | Workspace | | 0 |
| Change Policy, the rule for new issues, fix deadlines | Workspace | Admin | 0 |
| Give one project its own policy | Workspace | Admin | 0 |
| Get summary and review comments on pull requests | Workspace, with GitHub OIDC uploads | | 0 |
| Merge anyway on a failed gate | Workspace | Admin | 0 |
| Mark an issue "Not fixing" | Free (hidden at once, end date needed) | Member | 0 |
| Have "Not fixing" approved by a second person | Workspace | Admin approves | 0 |
| Hide one kind of issue in every repository | Workspace | Admin | 0 |
| Invite people, create teams, assign and comment on issues | Workspace | Admin invites | 0 |
| Slack, Discord, Jira, new webhooks | Workspace | Admin | 0 |
| Connect a whole GitHub organization | Workspace | Admin | 0 |
| Download issues, decisions and audit events (CSV, JSON) | Workspace | | 0 |
| See what a malicious package could reach (exposure) | Workspace | | 0 |
| Write custom rules | Free (3 pattern rules), Workspace (50) | Admin | 0 |
| Open an automatic fix pull request | Free | Admin | 3 each |
| Turn on weekly cleanup pull requests | Free | Admin | 3 each |
| Run a deep scan (where available) | Free | Member | 10 each, plus your own Anthropic usage |
| Generate a compliance report | Free | Member | 500 each |
| Download a report already generated, open its verify page | Free | Viewer | 0 |
| Create read-only API tokens | Free | Admin | 0 |
| Require two-factor for everyone | Free | Owner | 0 |
| Single sign-on (SAML) | Growth or Enterprise | Owner | 0 |
| Buy a plan or credits, manage renewal | | Owner | |

Two notes on compliance reports and plans:

- A report works on Free, but Free keeps only the newest 10 scans of a
  project. A report for a period can only test what still has a stored
  scan, and the page warns you before you pay.
- A report only counts trusted scans: from CI or run by Skylos.

## Troubleshooting

Each entry starts with what the screen says.

### Scans and uploads

**"UNVERIFIED" in place of PASS or FAIL, or "Unverified upload".** The
scan was uploaded with a token that is not marked for CI, usually from a
laptop. It is shown on its own page only. Upload from CI: see "Get a first
scan". If the upload did come from CI, open the project's **Settings**,
**Project tokens**, and select **Mark for CI** on the token.

**"First gate result on this branch" and nothing is marked new.** There is
no earlier passing scan to compare with. Only the conditions that count
all code can fail. This ends after the first scan that passes.

**"No earlier passing scan to compare with".** Same cause, shown on an
issue. The issue cannot count as new yet.

**"Dependencies: didn't finish" under "What wasn't checked".** The
dependency lookup did not complete in that run. The scan is judged on the
rest. To make an unfinished dependency scan fail the gate, turn on
**Require a completed dependency scan** in Policy.

**A project shows fewer scans than you uploaded.** The plan keeps the
newest 10 scans per project on Free and 500 on Workspace. Older ones are
removed when a new scan is uploaded.

**Grey places in the sidebar: "After your first scan".** They only show
scan results. Upload one scan and they open.

### GitHub

These all mean the Skylos GitHub App is not installed on the repository,
or cannot see it. Fix: the project's **Settings**, **Connect GitHub**; on
GitHub pick the repository and select **Save**.

- "Skylos couldn't confirm merge blocking for this repository, so GitHub
  may still allow the merge."
- "Merge blocking is off. Next: Connect GitHub."
- "Code not shown: Install the Skylos GitHub App on this repository to
  load more of this file."
- "Connect this project's GitHub App so AI can open pull requests."
- "Cleanup PRs are opened through the Skylos GitHub App."
- "CODEOWNERS is read only for repositories connected through the Skylos
  GitHub App."
- "No scan can be tied to an agent yet."

**The check is green or red on GitHub but a failing pull request can still
merge.** Installing the App does not protect merges. Finish step 4 of
**Merge blocking on GitHub**: require the "Skylos Quality Gate" check in
GitHub's branch rules.

**A pull request has the check but no Skylos comment.** Comments need the
Workspace plan and an upload through GitHub OIDC (the Skylos workflow). A
CI project token gives the check only.

**After Merge anyway the comment still says failed.** The check is updated
at once. The comment is rewritten on the next upload.

### Roles and plans

**A button is missing or grey.** Either your role or the plan does not
allow it. Skylos usually says which next to the control, for example
"Unavailable: Only admins can override a failed gate." The table at the top
of this chapter lists the role and plan for each task.

**"Your workspace trial has ended. Shared workspace features are paused;
your data is safe."** The workspace is on Free. Scans, the gate and your
credits keep working. An owner can start the Workspace plan in Billing.

**"Skylos hasn't turned on webhooks yet" or "Skylos hasn't turned on Jira
yet".** That integration is not available on your Skylos service. There is
nothing to set up on your side.

### Credits and buying

**"A report costs 500 credits, about $65. You have 50 credits."** The
balance is too low. Nothing was charged. An owner buys a credit pack with
the button next to the message, or in **Billing**.

**"Buying is paused while we finish setting up payments".** Checkout is
not open. No card is charged. Use the link in the banner to ask.

**"Email the founder to start".** Card checkout for a yearly plan is not
open yet. The button opens an email; Skylos answers with a payment link.

**"Only an owner can buy".** Ask a workspace owner. Admins and members
cannot start a checkout.

**A weekly cleanup pull request did not arrive.** Check, in this order:
the badge says **On** and not **Paused**; the balance has 3 credits; no
earlier cleanup pull request is still open; the default branch has a
trusted scan with unused Python functions.

## Not available yet

These exist in Skylos Cloud's code or screens but cannot be used today.
They are listed so that nobody goes looking for them.

| Feature | State |
|:--|:--|
| AI pull request review | Switched off. The pipeline view shows its stage as "Not run". |
| Bot approvals (a guard on approvals given by bots) | Hidden. Not shown on the Policy page. |
| Workspace settings for hooks on developer machines | The Policy page says they are coming. The CLI uses its built-in settings. |
| Scanner proof page | Switched off and not linked from any page. |
| Email for supply-chain alerts | Not sent. Use Slack, Discord or webhooks. |
| Card checkout for the yearly plans | May show "Email the founder to start" until checkout opens. |

Some places depend on how the Skylos service is set up, and the screen
says so when they are off: **Coding agents**, **Deep scans**, **Let Skylos
scan it**, dependency vulnerability monitoring, webhooks, Jira, and the
GitLab, Bitbucket and Azure DevOps connections.
