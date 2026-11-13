# Policy

Policy is where a workspace says what it enforces: what fails the quality
gate, which checks run, how long an issue may stay open, and what AI coding
agents may change.

**Who:** an owner or admin can change Policy, on the Workspace plan (the
trial counts). Everyone can read it. On the Free plan the default policy
applies and cannot be changed.

## Where Policy lives

Open **Policy** in the sidebar. The page has five parts, with links to each
at the top: **Quality gate**, **Coding agents**, **Supply chain**, **Custom
rules** and **History**.

The **Conditions** table is a summary of what the gate requires today. It is
the policy, not a scan result.

![The Policy page. (1) Edit conditions opens the editor.](img/cloud/policy-overview.png)

## Set what always blocks

**For:** the conditions that fail a scan whatever else is set.

1. Open **Policy** and select **Edit conditions**.
2. Under **Always block**, set the switches in the table below.
3. Under **Required scan coverage**, tick what a scan must contain to pass:
   **Require a completed dependency scan**, **Require resolved dependency
   versions**, **Require workspace custom-rule checks**. All are off by
   default.
4. Select **Save policy** at the bottom of the page.

| Setting | Default | What it does |
|:--|:--|:--|
| Quality gate on | On | Untick it and no issue blocks a merge. |
| Always block exposed secrets | Off | Any new secret fails the scan, even when your rule for new issues would allow some. |
| Critical security issues | Always on | Cannot be turned off while the gate is on. Counts all code in the scan, not only new code. |
| Fail on AI-code issues | Critical | Critical, Critical and high, or Off. |

![Always block and Required scan coverage, in the editor.](img/cloud/policy-always-block.png)

## Choose the rule for new issues

**For:** deciding how strict the gate is about new issues.

1. In the editor, open **Other new issues**.
2. Pick one **Rule for new issues**:

| Rule | A scan fails when |
|:--|:--|
| Block any new issue (default) | it has any new issue |
| Allow a set number of new issues per category | new issues in a category go over that category's limit |
| Allow a set number of new issues per severity | new issues at a severity go over that severity's limit |
| Allow a set number per category and per severity | either kind of limit is passed |

3. For the "Allow" rules, type the limits. 0 blocks the first new issue.
   Categories are Security, Secrets, Code quality, Unused code and
   Dependencies. Severities are Critical, High, Medium and Low.
4. Optional: tick **Ignore statically unreachable dependency CVEs** so a
   vulnerable package your code never imports does not block. Malicious
   packages always block.
5. Select **Save policy**.

![Rule for new issues, with limits per severity. The presets above it fill the form for you.](img/cloud/policy-new-issues.png)

**Start from a preset** fills the form: **Recommended**, **Stricter on AI
code** or **Strict**. Nothing changes until you save.

## Choose which checks run and the code-quality limits

Open **Advanced** in the editor.

- **Which checks run:** Security, Secrets, Code quality, Unused code. All
  are on by default. A check that is off finds nothing, so it blocks
  nothing.
- **Code-quality limits:** when a function counts as too complex or too
  long. Defaults: Complexity 10, Nesting depth 4, Function length 50 lines,
  Arguments 5.
- **Paths to skip:** files and folders scans leave out, for example
  `tests/**`.
- **Required route guards (FastAPI)**, **AI code assurance** and
  **Instructions for AI review** are also here.

Changes to checks and limits show on each repository's next scan.

## Set fix-by deadlines

**For:** tracking how long issues stay open. A deadline never blocks a
merge.

1. In the editor, open **Advanced**, then **Fix deadlines**.
2. Tick **Use fix deadlines**.
3. Set the days for each severity. The defaults are Critical 7, High 30,
   Medium 90, and no deadline for Low. A deadline can be 1 to 3,650 days.
4. Select **Save policy**.

![Fix deadlines. (1) Use fix deadlines.](img/cloud/policy-fix-deadlines.png)

**What happens next:** issues past their deadline count as overdue on
Issues and on the coverage page. Compliance reports use these deadlines to
decide whether a critical or high finding is overdue. With deadlines off, a
report uses 7 days for critical and 30 days for high.

## Save, and see the history

Before saving, you can type a **Reason for change**. It is kept with the
saved version. **Preview impact** shows which repositories would newly fail
or newly pass.

Every save is a version. Versions cannot be edited or deleted. Under
**Policy history** you can pick the default policy or one repository, see
each version with who saved it and why, open **Show changes**, ask "What
was the policy on" a date, or restore an older version (which saves it
again as a new one).

![Policy history after one save.](img/cloud/policy-history.png)

## How a change affects the gate and reports

- **The gate.** A change applies from the next upload. Scans already
  uploaded keep the result and the policy they were judged by.
- **Old checks on GitHub.** After a change, Skylos does not re-publish the
  check of an older scan. Push or re-run CI to get a result under the new
  policy.
- **Compliance reports.** A report does not use your gate rule. It uses a
  fixed rule: open critical and high security, secret and dependency
  findings must not be past their fix-by date. The only setting it takes
  from Policy is the fix deadlines.
- **The CLI.** `skylos sync pull` brings the workspace's checks, limits,
  paths, gate rule and custom rules to a repository, so a local
  `skylos . --gate` agrees with Cloud.

## Policy for one project

**For:** one repository that needs different rules.

**Who:** an owner or admin, on the Workspace plan.

1. Open the project, then **Settings**, then **Project policy**.
2. Select **Give this project its own policy**.
3. Edit and save.

![Project policy. This project still follows the default policy.](img/cloud/policy-project.png)

A project with its own policy uses only that policy. Nothing is merged with
the default. A project without one follows the default, and default changes
reach it on its next scan.

To stop projects from loosening the rules, turn on **Apply to every
repository (repositories can only be stricter)** on the Policy page. From
then on a project policy that is looser than the default cannot be saved.

Supply-chain settings and agent checks are workspace-wide. A project cannot
override them.

## Rules for coding agents

Under **Coding agents**, **On pull requests** adds checks for pull requests
that contain code an AI agent wrote.

1. Tick **Turn on agent rules**.
2. Pick **Block new issues in files an agent wrote at** a severity.
3. For each **agent risk signal** choose Block, Warn or Off: weakened tests,
   a removed security control, a made-up package, an undeclared package, a
   suspicious version bump, wider CI permissions, and references to code
   that does not exist.
4. Optional: add **Protected paths**. An agent's change there cannot merge
   until the team you pick approves it. This needs a team.

![Agent rules for pull requests.](img/cloud/policy-agents.png)

**On developer machines** shows the checks an agent must pass in every
repository. Workspace settings for hooks on developer machines are not
available yet: the CLI uses its built-in settings.

## Supply-chain policy

Under **Supply chain** on the Policy page:

- **Block malware:** known malicious packages fail the scan and the
  install.
- **Check provenance:** blocks an npm version published without the
  provenance its earlier versions had.
- **Hold new versions for (hours):** holds installs of a version younger
  than this. Empty uses the CLI default.
- **Internal package names**, **Private registries**, **Trusted
  registries:** protect against a public package that takes the name of
  one of your internal packages.

## Custom rules

**For:** your own checks, for patterns the built-in rules miss.

**Who:** an owner or admin. Free allows 3 rules (pattern rules only), the
Workspace plan 50.

1. On the Policy page, under **Custom rules**, select **Add a rule**.
2. Pick the rule type, **Pattern (JSON)** or **Python**, or start from a
   template.
3. Fill in the rule ID, name, severity and category.
4. Select **Create rule for future scans**.

![A custom rule started from the "Require Auth Decorator" template.](img/cloud/policy-custom-rule.png)

The rule runs on future scans. What it finds appears as issues under the
rule ID you chose.
