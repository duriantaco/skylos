# Start with Skylos Cloud

{{cloud_verified}}

Skylos Cloud is the web app at skylos.dev. The CLI finds issues on your
machine and in CI; Cloud keeps the scans, decides the quality gate for the
whole team, and holds the policy, the decisions and the reports.

The chapters in this part are task-shaped. Each task says what it is for,
who can do it, the steps with the labels you see on screen, what happens
next, and the common problems. Screenshots show a fictional workspace,
"Example Co".

Cloud works with every language the CLI scans. Nothing in this part is
specific to one language unless it says so.

## Sign in

**For:** opening your account.

**Who:** anyone with a GitHub account. No card is needed.

1. Open skylos.dev and select **Sign in**.
2. Select **Continue with GitHub**. Skylos asks GitHub for your profile and
   email only. You choose repositories later.
3. Approve on GitHub. You come back to Skylos signed in.

![The sign-in page.](img/cloud/start-sign-in.png)

**What happens next:** the first time, Skylos asks you to create a
workspace. After that you land on **Home**.

**Common problems**

- **"Single sign-on required".** Your workspace owner turned on single
  sign-on. Sign in through your company's identity provider.
- **You were invited but see an empty account.** Open the invite link again
  and sign in with the email address the invite was sent to.

## Create and name a workspace

**For:** a shared place for your team's repositories, policy and reports.

**Who:** any signed-in person. You become the workspace's owner.

1. On **Create your workspace**, type your company name in **Workspace
   name**.
2. Leave **Email me a Monday summary of this workspace** ticked if you want
   the weekly digest.
3. Select **Create workspace**.

![Create your workspace. (1) The name. (2) Create workspace.](img/cloud/start-create-workspace.png)

> Use your company's real name. Compliance reports print the workspace name
> on the cover, after "Prepared for". You can change it later under
> **Settings**, **General**, **Workspace name**, **Rename workspace**.

**What happens next:** the workspace starts a trial of the Workspace plan
(see "The trial and the Free plan" below) and Skylos shows **Get started**,
where you add a first repository.

### More than one workspace

The workspace switcher is at the top of the sidebar. Select it to change
workspace. **New workspace** below it creates another one. One account can
own up to 10 workspaces, and at most 2 of them can be on the Free plan.
The trial is given once per account, to the first workspace.

![The sidebar. (1) The workspace switcher. (2) New workspace.](img/cloud/start-sidebar.png)

## Find your way around

The sidebar groups the places by job.

| Group | Place | The question it answers |
|:--|:--|:--|
| Code | Home | Which repositories need attention? |
| Code | Pull requests | Can this change merge? |
| Code | Issues | What is open, and who owns it? |
| Code | Supply chain | Are our packages and installs safe? |
| AI | Coding agents | What do AI coding agents write, and how often is it blocked? |
| AI | AI app safety | Do the AI features in our code have safeguards? |
| AI | Deep scans | An AI security review of a whole repository. |
| Governance | Policy | What do we enforce? |
| Governance | Not fixing | What did we decide not to fix, and why? |
| Governance | Audit evidence | What can we hand an auditor? |
| Governance | Compliance reports | Create and download a report for an auditor. |
| Workspace | Settings | Members, teams, integrations, keys, security. |
| Workspace | Billing | The plan and the credits. |

Before the first scan, the places that only show scan results are grey and
say "After your first scan". **Coding agents** and **Deep scans** appear
only where the Skylos service has them switched on.

A repository is called a **project** in Cloud. Select one on Home to open
its own tabs: **Overview**, **Issues**, **Pull requests**, **Scans**,
**Settings** and **More**.

## Invite members and set roles

**For:** giving teammates access.

**Who:** an owner or admin. Sending invites needs the Workspace plan (the
trial counts). Changing a role and removing a person work on every plan.

1. Open **Settings**, then **Members & teams**.
2. Under **Invite Team Member**, type the person's email.
3. Pick a role: Viewer, Member, Admin or Owner. Only an owner can invite
   another owner.
4. Select **Invite**. Skylos shows a link to copy and says whether it also
   emailed it.

![Members & teams. (1) The email. (2) The role. (3) Invite.](img/cloud/start-members.png)

**What happens next:** the person opens the link and signs in with that
email. To change a role later, use the role menu on their row. The bin icon
removes them.

**Invite Domain Controls** on the same page limits new invites to your
company's email domains: tick **Restrict invites**, list the domains, **Save**.

### What each role can do

A role applies to every project in the workspace.

| Action | Viewer | Member | Admin | Owner |
|:--|:--|:--|:--|:--|
| See scans, issues, trends, reports and the audit log | Yes | Yes | Yes | Yes |
| Add a project, upload scans, connect the CLI | | Yes | Yes | Yes |
| Mark an issue "Not fixing", ask for an exception | | Yes | Yes | Yes |
| Comment on and assign issues | | Yes | Yes | Yes |
| Spend credits (for example a compliance report) | | Yes | Yes | Yes |
| Approve or reject exception requests | | | Yes | Yes |
| Merge anyway on a failed gate | | | Yes | Yes |
| Change Policy and custom rules | | | Yes | Yes |
| Connect GitHub, Slack, Jira and webhooks | | | Yes | Yes |
| Create, mark and revoke project tokens and API tokens | | | Yes | Yes |
| Invite, remove and change members | | | Yes | Yes |
| Start a fix pull request, turn on weekly cleanup | | | Yes | Yes |
| Buy plans and credits, see credit history | | | | Yes |
| Single sign-on, require two-factor, delete the workspace | | | | Yes |

Some of these also need the Workspace plan. Chapter "Which plan do I need"
has the full list.

**Teams** group members so a team can own a repository and its issues.
Create them under **Settings**, **Members & teams**, **Teams**. Teams need
the Workspace plan.

## The trial and the Free plan

Your first workspace starts a trial of the Workspace plan: **14 days, 50
credits, no card**. Nothing renews and nothing is charged. The sidebar shows
the days left.

When the trial ends the workspace moves to the Free plan. Your data stays.

| | During the trial (Workspace plan) | After it (Free plan) |
|:--|:--|:--|
| Projects | Up to 10 | 1. Existing projects stay; you cannot add more. |
| Scans kept per project | Newest 500 | Newest 10. Older ones are removed at the next upload. |
| Quality gate and GitHub check | Yes | Yes |
| Change Policy, Merge anyway | Yes | No |
| Pull request comments | Yes | No |
| Invite members, teams | Yes | No new invites or teams. People already in stay. |
| Approval step for "Not fixing" | Yes | No. A member hides an issue directly, with an end date. |
| Slack, Discord, Jira, new webhooks | Yes | Paused |
| Credits | 50 to start | Kept. Credits work on every plan. |

> Free keeps only the newest 10 scans of a project. A compliance report
> that covers a period can only test what still has a stored scan; the
> Compliance reports page warns you before you pay. If you plan to buy a
> report, generate it before older scans are removed, or stay on the
> Workspace plan.

To keep the Workspace plan, see "Billing and credits".
