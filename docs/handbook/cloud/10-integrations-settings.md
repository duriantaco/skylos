# Integrations, notifications and settings

Workspace settings are under **Settings** in the sidebar. While you are in
Settings, the sidebar lists the settings pages: **General**, **Members &
teams**, **Integrations**, **API & keys**, **Security** and **Billing &
credits**. **Back to home** returns to the workspace.

Project settings are on each project's **Settings** tab.

## Connect GitHub

There are two connections. Both use the Skylos GitHub App.

**One repository** (any plan, owner or admin): open the project's
**Settings** and select **Connect GitHub** under **Merge blocking on
GitHub**. This is what publishes the Skylos check, opens the workflow pull
request, lets Skylos load more of a file, and allows fix and cleanup pull
requests.

**A whole GitHub organization** (Workspace plan, owner or admin):

1. Open **Settings**, then **Integrations**.
2. Under **GitHub organizations**, select **Connect a GitHub
   organization**.
3. On GitHub, choose the repositories and select **Save**.

Skylos then lists every repository in the organization under coverage:
which ones are not scanned yet, which are scanned without blocking merges,
and which block merges on the Skylos check.

![Integrations: GitHub organizations and webhooks. (1) Connect a GitHub organization.](img/cloud/settings-integrations-github-webhooks.png)

**Already installed on GitHub?** Change the repository selection on GitHub,
then **Save**. GitHub sends you back to Skylos.

## Webhooks

**For:** sending events to your own systems.

**Who:** an owner or admin, on the Workspace plan. Up to 10 webhooks.

1. Open **Settings**, **Integrations**, **Webhooks**.
2. Type the **Endpoint URL** (a public `https://` address).
3. Tick the events: a scan finished, a scan failed its gate, an exception
   was requested, approved, rejected or revoked, an agent was blocked
   repeatedly, a malicious package was detected, a dependency
   vulnerability was detected.
4. Select **Add webhook**. Copy the signing secret.
5. **Send test event** checks the endpoint.

Events never include source code. **How to check a request came from
Skylos** on the page explains the signature. An unverified upload is
reported as "unknown", never as passed.

## Jira

**For:** creating a Jira ticket from an issue.

**Who:** an owner or admin, on the Workspace plan. Jira Cloud only.

1. Open **Settings**, **Integrations**, **Jira**.
2. Type the **Jira site** (`https://your-team.atlassian.net`), choose the
   **API token type**, and type the **Atlassian account email** and the
   **API token**.
3. Select **Test connection**, then **Save**.

![Jira connection.](img/cloud/settings-integrations-jira.png)

> If a section says "Skylos hasn't turned on webhooks yet" or "Skylos
> hasn't turned on Jira yet", that integration is not available on your
> Skylos service. There is nothing for you to set up.

## Slack and Discord

**For:** scan results and new dependency alerts in a channel.

**Who:** an owner or admin, on the Workspace plan. Set per project.

1. Open the project's **Settings**, then **Notifications**.
2. Under **Slack Notifications**, paste an Incoming Webhook URL from your
   Slack workspace. For Discord, paste a channel webhook URL.
3. Select **Test Webhook**, then **Save & Enable**.
4. Choose when to post: on failure, always, or on failure and recovery.

![Project notifications: Slack, Discord and the README badge.](img/cloud/settings-project-notifications.png)

GitLab merge request reviews, Bitbucket Cloud and Azure DevOps pull request
statuses also connect per project. Each block is shown only where the
Skylos service has that integration switched on.

## What Skylos emails, and what it does not

Email depends on mail being set up on the Skylos service. The **Weekly
digest** panel tells you the truth for your workspace: it reads "Skylos
doesn't send digest emails yet" when no email is being sent.

| Message | Sent to | When |
|:--|:--|:--|
| Invitation | The invited address | An admin invites someone. The link is always shown to copy as well. |
| Weekly digest | Owners and admins by default; members can opt in | Mondays, 00:30 UTC. One email a week, one click to unsubscribe. |
| Trial ending, trial ended, renewal coming | Owners | Before and after those dates. |
| Welcome and first-scan reminders | The person who signed up | In the first days. |
| A decision is about to end | The requester and the approver | 14 days, 7 days and 1 day before a "Not fixing" decision ends. |
| Workspace deletion scheduled, cancelled, done | Owners | When it happens. |

**Not sent by email today:** gate failures, new issues, supply-chain
alerts and comments on issues. Use Slack, Discord or webhooks for gate
results and supply-chain alerts.

To manage the digest: **Settings**, **General**, **Weekly digest**.
**Email me a preview now** sends one to you only. **Stop emailing me the
digest** is your own choice. **Turn off the digest for everyone** is for
owners and admins.

![Weekly digest. This local copy has no mail set up, and the panel says so.](img/cloud/settings-digest.png)

## Project settings

**Who:** an owner or admin changes these.

| Section | What you set |
|:--|:--|
| Repository & connection | **Project name**. **Repository URL** and, for a monorepo service, the **Project root**. **Unlink** removes the repository link. |
| Merge blocking on GitHub | The four steps that connect GitHub and require the check. |
| Project tokens | Tokens for uploads. **Mark for CI** makes a token's uploads count. See "Get a first scan". |
| Owner | The team that owns the repository and its issues: Automatic (from CODEOWNERS), No owner, or a team. Teams need the Workspace plan. |
| Project policy | Follow the default policy, or **Give this project its own policy**. |
| Notifications | Slack and Discord. |
| README badge | A badge that shows whether the default branch passes the gate. Copy the Markdown. |

Three things people look for here live elsewhere:

- **Default branch.** There is no setting. Skylos reads the default branch
  from GitHub through the GitHub App. Without the App it assumes `main`;
  the Compliance reports page lets you pick another branch for a report.
- **Business criticality.** On **Compliance reports**, under "How important
  each project is": Not set, Very high, High, Medium or Low. It is printed
  on report covers and changes nothing else.
- **Removing a project.** **Settings**, **General**, **Repositories**,
  **Manage repositories**: select the projects, then **Remove selected**
  (owner or admin).

## API tokens and keys

**Who:** an owner or admin.

**API tokens** (**Settings**, **API & keys**) are read-only tokens for
your own tools.

1. Type a **Token name**.
2. Tick what it may read: projects, scans, findings, issues, exceptions,
   the audit log, posture.
3. Choose **Expires after**: 30, 90 or 365 days.
4. Select **Create token**. Up to 25 can be active.

Use the token as `Authorization: Bearer sky_org_…` against `/api/v1`. The
page links the OpenAPI document. Creating a token is recorded in the audit
log.

**API keys** on the same page hold your own AI provider keys, used by Deep
scans and billed by that provider.

## Security

**Who:** an owner.

- **Single sign-on (SAML):** part of the Growth and Enterprise plans.
- **Require two-factor for everyone:** members without two-factor must set
  it up before they continue. Tokens keep working. You must turn on
  two-factor for your own account first.
- **Your account security** (also under the account menu): set up an
  authenticator app, and sign out of other sessions.

## Data retention and deleting a workspace

**Settings**, **General**, **Data retention** sets how long scans are kept:
the plan default (no age limit; the newest 500 scans per project on the
Workspace plan, 10 on Free), or 30 days to 3 years. Each project always
keeps its most recent scan.

**Danger zone: delete workspace** is for owners. Deletion happens after a
7-day wait, and any owner can cancel during it. Unused credits are lost.
