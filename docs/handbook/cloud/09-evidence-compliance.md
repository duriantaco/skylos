# Audit evidence and compliance reports

Cloud keeps a record of what was scanned, what was decided and who did it.
This chapter covers the exports of that record and the paid compliance
reports built from it.

> A Skylos report is evidence about your code scanning and change control.
> It supports an audit. It is not an audit, and it is not a certificate. A
> SOC 2 report from Skylos is a readiness report; a CPA firm does the audit.

## Audit evidence

**For:** one page with everything you can hand an auditor.

**Who:** every member can open it. Downloads need the Workspace plan.

Open **Audit evidence**. It has four cards and one export:

| Card | What it gives you |
|:--|:--|
| Security evidence | A signed report of what your scans show for SOC 2, ISO 27001 or PCI DSS. **Choose a framework** opens Compliance reports. |
| Change history | Every scanned pull request in a date range, as a CSV or a printable report. |
| Workspace access review | Who can see or change the workspace, and whose access is stale. |
| Decisions & policy history | Issues the team chose not to fix, who approved each, and every policy change. |

![Audit evidence.](img/cloud/evidence-page.png)

**Export pull-request changes** at the bottom: pick **From** and **To**,
then **Download printable report** or **Download CSV**. It covers scanned
pull requests only. Add your Git reviews and deployment records yourself.

## The audit log

**For:** who did what, and when.

1. Open **Audit evidence**, then **Audit log**.
2. Filter by **Event** (scan uploads, status changes, not fixing,
   assignments, comments, resolutions, false positives), by what it
   **Applies to**, and by date.
3. Select **Download these events (CSV)**, **Download JSON** or **Download
   NDJSON**.

![The audit log. (1) Download the filtered events.](img/cloud/evidence-audit-log.png)

The log records uploads, policy saves, decisions and approvals, merge
anyway, token and member changes. The **AI runs** tab lists runs of AI
features. Entries cannot be edited.

## Access review

**For:** the periodic check of who has access.

Open **Audit evidence**, then **Review access**. The page counts members,
owners and admins, pending invites, and uploads that are not tied to a
member. Each member has a role, the last audit event, the last scan upload
and a status. "Review access" marks an owner or admin with no recent
activity.

**Change roles or remove access** opens **Members & teams**.

## Compliance reports from start to finish

**For:** a dated, signed report for one framework that you give to an
auditor or a customer.

**Who:** a member, admin or owner generates one. It works on every plan.
Each report costs **500 credits**, charged once when you confirm. Every
download afterwards is free, for viewers too.

Open **Compliance reports**. The page has three numbered steps:

1. **Check your scans (free)**
2. **Create the report**
3. **Download**

### Step 1: check your scans

The readiness table lists every project with the scan a report would use.

| Column | Meaning |
|:--|:--|
| Status | **Ready**, or **Not ready** with the reason. |
| Scan checked | The scan, commit, branch and how it was uploaded. |
| What to change | "Nothing. This project counts." or the one thing to fix. |

The pill above the table counts the projects, for example "3 of 4 projects
ready". Reasons you can meet:

| Status | What to do |
|:--|:--|
| Not ready: no scan | No completed Skylos scan yet. Use one of the trusted routes in "Get a first scan". |
| Not ready: no scan from CI yet | The only scans are unverified uploads. Upload from CI or let Skylos scan it. The row links **Open Project tokens** or **Open Repository & connection**. |
| Not ready: no CI scan of main | Skylos took `main` as the default branch because the GitHub App is not connected. Use the link in the row to use another branch for the report, or scan `main`. |
| Not ready: dependency check incomplete | The scan could not read or check every declared dependency. Fix the manifest or lockfile it names and push again. |

**How to get a scan that counts** under the table repeats the three
trusted routes from "Get a first scan".

A project that is not ready is not left out silently. The report says "Not
assessed" for it. Fix it first, or pick only ready projects in step 2.

![Step 1. (1) How many projects count. (2) A project that is not ready, with what to change.](img/cloud/compliance-readiness.png)

### Before you generate: name and importance

- **Prepared for.** The report prints the workspace name. The generate
  panel shows "Prepared for:" with a **change** link to **Settings**. If
  the name is still "My Workspace", change it first.
- **How important each project is.** Lower on the page. Set each project
  to Very high, High, Medium, Low or Not set. It is printed on the cover of
  new reports.

### Write your SOC 2 answers

**For:** the parts of a SOC 2 report only your company can write.

**Who:** an owner or admin. It is free.

1. On the SOC 2 card select **Fill in your SOC 2 answers**. The page
   **Prepare for SOC 2** opens.
2. On the **Description** tab, write each item, DC 1 to DC 9, in plain
   words and select **Save**: the services you provide, what you promise
   customers, the system's infrastructure, software, people, procedures and
   data, incidents in the period, your controls, what customers must do,
   the vendors you rely on, criteria that do not apply, and changes in the
   period.
3. On the **Controls** tab, approve the six controls Skylos tests.
4. **Readiness** and **Deviations** fill in after your first report. From
   then on the page opens on the **Readiness checklist**: what to fix
   before a deadline, settings to change so Skylos can test more, what to
   write and what to collect yourself, each with a button to the place to
   do it. **Deviations** is where you write your response to each
   deviation the report found.

An item you leave empty prints as "Not provided by management". Your
answers are printed as provided by management, not tested by Skylos.

![Prepare for SOC 2, Description tab. (1) The first answer. (2) Save.](img/cloud/compliance-soc2-answers.png)

> Your answers go into the next report you generate. If you generate
> first, you pay again for a report that includes them. The panel offers
> **Fill in your answers first (free)** for that reason.

### Step 2: create the report

1. Pick the standard your auditor asked for: **SOC 2**, **ISO/IEC 27001**
   or **PCI DSS**. **Security engineering** has OWASP, CWE and NIST SSDF
   references, and **Other frameworks** lists the rest. **How to prepare**
   on each card says what you still need to collect yourself.
2. Select **Generate readiness report** (SOC 2) or **Generate report**. The
   button shows the price: 500 credits, about $65.
3. In the panel, choose the projects, the branch and, for SOC 2, the
   period and categories (table below).
4. Read the summary line and the warning about projects that are not
   ready.
5. Confirm with the button that names the charge: **Generate and charge
   500 credits (about $65)**. Before any SOC 2 answer is written it reads
   **Generate without my answers and charge 500 credits (about $65)**, next
   to **Fill in your answers first (free)**.

![The SOC 2 panel. (1) Which projects. (2) Prepared for. (3) The button that charges.](img/cloud/compliance-generate.png)

| Field | Choices |
|:--|:--|
| Which projects | All projects, or only the projects you pick. |
| Which branch | Each repository's default branch, or another branch. |
| Audit period (SOC 2) | Up to 12 months, ending today or earlier. **Last 90 days** fills it in. |
| Trust services categories (SOC 2) | Security is always included. Add Availability, Confidentiality, Processing Integrity or Privacy if your auditor will examine them. |

**What happens next:** "Your report is ready. Next: download it." The line
under it gives the result, the scope, the period, "Signed by Skylos", the
start of the SHA-256 and "500 credits charged once". A second click or a
reload does not charge again.

**If you do not have enough credits,** the card shows "A report costs 500
credits, about $65. You have 50 credits." with a button to buy the smallest
pack that covers one report. Nothing is charged for a report that fails to
generate.

### The result line

The result on the page and in the report is the **Skylos scan policy**
result. It is not a framework result. It can read:

| Result | Meaning |
|:--|:--|
| Policy met | No open critical or high security, secret or dependency finding is past its fix-by date. |
| Policy met, fixes due | The same, with findings that will become overdue. |
| Policy not met | At least one such finding is overdue. |
| Not assessed | A project in scope had no trusted, complete scan. |

### Step 3: download

A new report appears at the top of the page as **Your latest report** and
in the table under **3 Download**. Each is a fixed copy from that day. New
scans do not change it.

| Download | For |
|:--|:--|
| PDF for your auditor | The copy to send outside. It leaves out file paths and finding text. |
| Full PDF for your team | Everything, including each finding. |
| More formats | The full and auditor copies in the browser (HTML), CSV and auditor CSV, signed JSON, SARIF for code-scanning tools, the verification page, and (SOC 2) the lists your auditor picks samples from, one CSV each. |

The table also shows who generated the report, the SHA-256, **Signed** and
a **Verify** link.

![Your latest report. (1) The PDF for your auditor. (2) More formats.](img/cloud/compliance-latest-report.png)

### The verify page

Anyone with the link can open the verify page. No sign-in is needed. It
shows the record Skylos stored for that report id: when it was generated,
its SHA-256, whether the stored content and the Skylos signature still
match, and key facts to compare with the copy in hand (framework, period,
projects in scope, the policy result and the counts of open findings).

It never shows the organization, repositories, findings or report content.

To check a copy exactly, drop the **JSON** edition on **Check the JSON
file**. The browser hashes it and compares it with the stored SHA-256. The
file is not uploaded. A PDF, HTML or CSV copy cannot be checked this way;
compare its facts with the page.

A valid signature shows who made the stored record and that it is
unchanged. It is not a SOC 2, ISO or PCI result.

![The public verify page for a report.](img/cloud/compliance-verify.png)

### Answer an auditor's sample

**For:** an auditor who picked some pull requests or findings from your
report to test one by one. You hand over the stored evidence for exactly
those items.

**Who:** anyone who can see compliance reports. It is free and can be
repeated. It works for reports generated with the current report format.

Auditors call the full list they pick from the **population**, for example
every pull request merged in the period. Your report already holds these
lists. The few items they pick are the **sample**.

1. Next to the report (under **Your latest report**, or in the table under
   **3 Download**), select **Answer an auditor's sample**.
2. Choose **My auditor sent the items** and paste them as they came, or
   **Draw a sample for me**: pick **How many items**, and Skylos picks at
   random and prints the seed. The same seed on the same report always
   gives the same sample, so the auditor can repeat it. **New seed** draws
   again.
3. Select **Check the sample first**. Items that are not in the report are
   named, never dropped.
4. Download the packet for your auditor, or the full packet.

![Answer an auditor's sample. (1) Draw a sample for me.](img/cloud/compliance-sample-packet.png)

**What you get:** one section per item, with what the stored report holds
for it and "not recorded in this report" where it holds nothing. The packet
is built only from the stored report, so it always agrees with the report
your auditor already has. Nothing is read again from GitHub or from newer
scans. The auditor packet leaves out emails, file paths, finding keys and
the reasons for exceptions and overrides, like the auditor copy of the
report, and says so where it does. The full packet includes them: share it
only if your auditor needs it.

### Questionnaire answers

**For:** a customer's security questionnaire. Skylos drafts answers to the
common code-security questions from one stored SOC 2 report.

**Who:** anyone who can see compliance reports. Free.

1. Next to a SOC 2 report, select **Questionnaire answers**.
2. Read each question with its draft answer. **Backed by** says which part
   of the report supports it; **What you add** says what only you can
   write.
3. Select **Copy all answers**, or download them.

![Questionnaire answers drawn from one SOC 2 report.](img/cloud/compliance-questionnaire.png)

The page also shows the report the answers come from: who it was prepared
for, its date and period, id, SHA-256, signature and verify link, so the
customer can check it. **Using this with Vanta, Drata or Secureframe**
opens a guide to uploading the report and answers to those platforms.
The answers are drafts: read and complete them before you send them.

### Request a change

**For:** a report with something wrong in it: a wrong company or project
name, the wrong scope, or a result you disagree with.

1. Select **Request a change** next to the report.
2. Pick what is wrong and add a sentence if you like.
3. Select **Send to the founder**.

![Request a change to this report.](img/cloud/compliance-request-change.png)

It is free. A generated report is signed and cannot be edited, so a fix
goes into a new report. The founder replies first. Generating the new
report costs the usual credits.

**Common problems**

- **"Report not generated… No credits were charged."** Nothing in scope
  could be assessed, usually because the chosen branch has no trusted scan.
  Check step 1 and the branch.
- **"Your plan keeps the newest 10 scans per project."** Shown before you
  pay when older scans of the period are gone. The report can then test
  only the pull requests that still have a stored scan; the others are
  listed as unable to test, never as a missed scan. You can still
  generate, or keep the Workspace plan so scans are kept.
- **A hidden critical or high finding reads as a deviation.** It was
  hidden without a second person's approval. The **Not fixing this** form
  warns about this: "Compliance reports will list this as hidden without
  an approval record." See "Decide on issues".
