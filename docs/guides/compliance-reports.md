# Skylos Compliance Report Guide

Use Skylos to turn security findings, pull request checks, and recorded risk decisions into evidence your team can review and share. Start with **Audit evidence** in the Cloud sidebar: it brings the framework reports, change history, audit log, access review, and policy history into one place.

This guide explains which report to choose, how to create it, how to read it, and how to build a useful audit evidence pack. The instructions follow the current Cloud source. Your deployed workspace may use different commercial terms; the amount shown beside **Generate report** is the amount to check before creating a new report.

## Choose the right evidence

![Desktop Audit evidence page with change history and report destinations](../assets/customer-guide/audit-reports-desktop.png)

*Actual Cloud Audit evidence page at a 1600 px desktop width, using illustrative data. Choose change history for a date range or Compliance reports for a framework report.*

| What you need to answer | Open | What you get | Why it helps |
| --- | --- | --- | --- |
| “Which scanned code weaknesses relate to our chosen standard?” | **Audit evidence → Compliance reports → All frameworks** | A saved framework report from the latest eligible code scan for each project | Engineers and reviewers can work from the same requirement references without manually classifying every rule. |
| “What did our checks find during this audit period?” | **Audit evidence → Change history for an audit (SOC 2 CC8.1)** | CSV or printable HTML containing every recorded pull request scan in the chosen period | Links a change, commit, check result, override, protected path approval, and accepted risk in one export. |
| “Which changes had an AI coding agent signal?” | **Audit evidence → AI agent changes only → Export agent changes** | The change history narrowed to records carrying agent evidence, with a project filter | Supports review of how AI assisted changes were checked and who approved exceptions. |
| “Which formal exception requests were reviewed?” | **Compliance reports → Won't fix for now** | Formal exception request counts and a CSV with requester, reviewer, reason, expiry, linked suppressions, and decision trail | Gives reviewers the context behind approved exception requests and a list of decisions to revisit. Direct suppressions, gate overrides, and organization triage rules require their own records. |
| “Who changed checks or made a decision?” | **Audit evidence → Audit log → Open the audit log** | Recorded workspace activity | Helps investigate decisions and setting changes. |
| “Who still has access?” | **Audit evidence → Access review → Review access** | Workspace access, roles, credentials, and stale access context | Supports an access review with evidence for follow-up. |
| “Which policy was in place?” | **Audit evidence → Policy history → Open policy history** | Saved quality gate policy versions and their change history | Helps explain changes in enforcement over time. |
| “What safeguards did our AI application checks report?” | **Compliance reports → EU AI Act / NIST AI RMF / ISO/IEC 42001** | Evidence mapped from uploaded AI defense attestations | Connects specific technical safeguard checks to recognized control themes. |

Direct links: [Audit evidence](https://skylos.dev/dashboard/evidence), [Compliance reports](https://skylos.dev/dashboard/compliance), [Not fixing](https://skylos.dev/dashboard/exceptions), [Audit log](https://skylos.dev/dashboard/activity), [Access review](https://skylos.dev/dashboard/access-review), and [Policy history](https://skylos.dev/dashboard/policy#policy-history). Sign in and select the workspace that holds the records you need.

## Generate and use compliance reports

**Goal:** create one saved report you can read, download in several formats, and refer back to later.

![Desktop Compliance reports page showing framework cards and generation controls](../assets/customer-guide/compliance-overview-desktop.png)

*Actual Cloud Compliance reports page at a 1600 px desktop width, using illustrative data. Find the framework, check its edition and mapped requirements, then use its Generate report button.*

**See an example first:** open the [illustrative SOC 2 evidence report](../assets/customer-guide/example-soc2-report.html), [canonical JSON](../assets/customer-guide/example-soc2-report.json), [CSV](../assets/customer-guide/example-soc2-report.csv), and [JSON fingerprint](../assets/customer-guide/example-soc2-report.sha256). These files use the actual Cloud report renderer and example findings. They show the report format without making a paid generation request or using customer scan data.

### Before you begin

- Use a workspace with the **Workspace** or **Enterprise** plan in the inspected implementation.
- To generate a new framework report, you need the **member**, **admin**, or **owner** role. A **viewer** can download existing reports.
- Upload complete native Skylos code scans for the projects you want represented. An AI defense report or technical debt report supplies different evidence and does not replace the code scan.
- Confirm the code scope, branch, and commit in the project's scan history before generating. Framework report selection uses the newest complete native code scan per project that is not a diff scan; it does not impose a default branch restriction.
- Check the cost shown on the framework's **Generate report** button. The repository's configured starting cost is **500 credits per new report**; the service reads the enabled cost at runtime. Enterprise generation is included in the inspected implementation. Downloading an existing report again has no credit charge.

The Workspace plan unlock and your credit balance are separate. A workspace can have access to the report feature and still lack the credits needed for a new report. Use the signed-in screen for your current plan, balance, and price; public pricing and this checkout have previously differed.

### Create and read the report

1. Sign in to Skylos Cloud and select the correct workspace.
2. Click **Audit evidence** in the sidebar.
3. On **Compliance reports**, click **All frameworks**, or use the **SOC 2**, **OWASP Top 10**, **PCI DSS**, **ISO 27001**, or **HIPAA** shortcut.
4. Under **Pick a framework**, find the standard and check its edition and mapped requirement count. A card marked **Not supported yet** has no supported mapping and cannot generate a paid report.
5. Click **Generate report** on that card. The button shows either the credit cost or **included in your plan**.
6. In **Download the report as**, choose **HTML** for a readable report, **CSV** for a spreadsheet, or **JSON** for the complete structured evidence.

   ![SOC 2 evidence report download format menu on the desktop Compliance reports page](../assets/customer-guide/compliance-menu-desktop.png)

   *Actual Cloud format menu at a 1600 px desktop width, using illustrative data. HTML is readable in a browser, CSV opens in a spreadsheet, and JSON retains the complete structured evidence.*

7. Open the downloaded file. For HTML, open it in a browser and use **Print → Save as PDF** if you need a PDF copy.
8. Read the organization, project scope, framework edition, generated date, and **Scope notice** before interpreting the results. Check the requirement table and its **Evidence Note** column.
9. Reload **Compliance reports**, then find the entry under **Reports you generated**. The row records its framework, creation time, generator, fingerprint, and **HTML**, **CSV**, and **JSON** links.
10. Use that history row to obtain any additional formats. Each new use of **Generate report** creates a fresh report; history downloads reuse the saved evidence without a new generation charge.

![Desktop saved compliance report history with generator, timestamp, fingerprint and download formats](../assets/customer-guide/compliance-history-desktop.png)

*Actual Cloud report history at a 1600 px desktop width, using illustrative data. Reuse the saved report row to download the same evidence in HTML, CSV or JSON without a new generation charge.*

[Explore the report format menu with example data](../assets/customer-guide/cloud-ui-demo.html?mode=compliance).

*Select Generate report to see the available formats. This interactive example uses the real Cloud controls; nothing is saved or charged.*

**Expected result:** one saved report appears in the history. You can reopen the same evidence after later scans arrive. Repeating a historical download does not run the scan again or update the report to today's findings.

### Which frameworks can I choose?

These are the supported mappings implemented in the inspected source. Active framework cards depend on the deployed configuration.

| Framework | Edition used by the current mapping | Evidence source |
| --- | --- | --- |
| OWASP Top 10 | 2025 | Code findings mapped through declared weaknesses and supported category correspondence |
| CWE Top 25 Most Dangerous Software Weaknesses | 2025 | Code findings with matching CWE references |
| PCI DSS | 4.0.1 | Code findings mapped to selected technical requirement references |
| SOC 2 | 2017 Trust Services Criteria, with 2022 points of focus | Code findings mapped to selected criteria |
| HIPAA Security Rule | 45 CFR 164.312 | Code findings mapped to selected technical safeguards |
| ISO/IEC 27001 | 2022 | Code findings mapped to selected secure coding references |
| EU AI Act | Regulation (EU) 2024/1689 | Uploaded AI defense attestation checks |
| NIST AI RMF | 1.0 | Uploaded AI defense attestation checks |
| ISO/IEC 42001 | 2023 | Uploaded AI defense attestation checks |

The database can also list **GDPR** and **NIST CSF**. They currently have no implemented framework report mapping and are shown as **Not supported yet** when active. A listed standard is not a promise that every requirement in that standard is assessed.

## Read compliance report results

A framework report organizes the evidence the service has. Start with the requirement notes and evidence coverage; a headline score is a summary of that evidence.

![Generated desktop SOC 2 evidence report with scope, summary and requirement statuses](../assets/customer-guide/compliance-report-desktop.png)

*Actual SOC 2 evidence report output from the Cloud renderer at a 1600 px desktop width, using illustrative evidence. Read the scope notice, evidence coverage, Finding observed rows and Not evaluated rows.*

| Label in the readable report | Meaning | Your next step |
| --- | --- | --- |
| **Finding observed** | At least one check mapped to this requirement reported a finding. Internal JSON status: `failed`. | Inspect the linked rule and finding details; fix the weakness or document the review decision. |
| **Not evaluated** | There is no complete evidence that the expected checks ran and applied to this requirement. Internal status is normally `not_evaluated`; older `not_scanned` records display this label too. | Confirm the scan scope and supply the missing evidence; do not treat it as a passing check. |
| **CLI reported pass** | An AI governance report received all expected recognized check outcomes as passing across projects with recognized framework evidence. JSON status: `passed`, evidence basis: `cli_attested_checks`. | Retain the attestation and review its scope. This is an uploaded CLI assertion, not independent verification. |
| **Unverified** | An older stored report included a passing status without the current evidence coverage contract. | Treat it as historical unverified evidence. Generate a current report if appropriate. |

For the ordinary code mapping reports, **no finding does not establish a pass**. The current service cannot independently prove that every mapped check ran with applicable scope. A report with zero findings can therefore still show **Not evaluated** throughout.

**Evidence coverage** is the percentage of the report's listed requirements that have an evaluated result: `(passed + failed) ÷ total listed requirements`. Its denominator is the implemented requirement list, not every obligation in the full standard. It is also not the percentage of your code scanned.

**Verified check score** or **CLI-attested check score** is `passed ÷ evaluated requirements`. It displays **N/A** when nothing was evaluated. In an ordinary mapped report, observed findings with no verified passes can produce a score of 0%; that does not mean “the company is 0% compliant.” Use the underlying requirement rows to decide what to do.

For example, a report with ten mapped requirements and findings under two of them may show **20% evidence coverage**, two **Finding observed** rows, and eight **Not evaluated** rows. Fixing the findings and uploading a new scan may remove the observed findings from a newly generated report. The absence of findings still does not prove the remaining requirements passed.

[View the example SOC 2 evidence report](../assets/customer-guide/example-soc2-report.html).

*Read the scope notice, evidence coverage and requirement statuses in this report generated from illustrative evidence by the actual Cloud report renderer.*

### What is inside each format?

| Format | Included information | Best use |
| --- | --- | --- |
| HTML | Organization, project scope, standard and edition, generation date, scope notice, summary, requirement statuses, finding counts, last evidence dates, and evidence notes; AI reports also list obligations outside scan scope | Read with a reviewer, share as a readable artifact, or print to PDF |
| CSV | Report metadata and scope notice, summary, requirement IDs and descriptions, status, finding count, related rules, last evidence date, and notes | Filter requirements, add your own owners and evidence links, or import into an audit workbook |
| JSON | Structured report, summary, requirement rows, and `findingsByRule` with stored finding details such as rule, severity, file, line, message, scan date, and suppression state | Preserve the canonical artifact, inspect detailed findings, or integrate with internal evidence tooling |

HTML and CSV summarize findings at the requirement level. Keep JSON when a reviewer needs the underlying rule and location details.

## Preserve a report and verify its fingerprint

The history stores the report data captured at generation time, including the scope notice, alongside the canonical JSON text and a SHA-256 fingerprint. HTML and CSV downloads render that saved data. They do not recompute evidence from newer scans.

1. Open **Compliance reports → Reports you generated**.
2. Find the framework and generation time you are handing over. Use **Previous** and **Next** if the history spans several pages; the page shows 20 reports at a time.
3. Download **JSON** and retain the original bytes. A browser may open JSON instead of saving it automatically; use the browser's save option without reformatting the content.
4. Hover over the shortened **Fingerprint (SHA-256)** in the history row to see the complete value. The report download response also supplies `X-Skylos-Canonical-Json-Sha256` and `X-Skylos-Report-Artifact` headers for tools that collect download metadata.
5. Compute the downloaded JSON file's SHA-256 and compare the complete value:

   ```bash
   # macOS
   shasum -a 256 framework-evidence.json

   # Linux
   sha256sum framework-evidence.json
   ```

6. Retain the JSON, fingerprint, artifact ID if collected, and the HTML/PDF used for human review in your evidence folder.

**Expected result:** the original JSON bytes have the same SHA-256 as the saved report's fingerprint. Formatting JSON, changing line endings, or adding a newline changes its hash. The fingerprint is for canonical JSON; hashing the CSV, HTML, or printed PDF will produce a different value.

The fingerprint helps demonstrate that a particular report file is unchanged. It does not establish the completeness or truth of the uploaded scan evidence. Normal scan retention settings keep compliance reports and other audit records separately from expiring scans; download the evidence pack you need for your own retention requirements.

## Include accepted risks in your evidence pack

**Goal:** retain the reason for leaving a real finding open, its reviewer, and its expiry, so the decision can be examined later.

1. Open the issue from **Issues**. Under **Can't fix it now?**, click **Not fixing this** and choose **Accept the risk until a date**. Fill in **Why is it safe to leave for now?**, choose **7**, **30**, or **90 days** under **Until when?**, then click **Send to an admin for approval**. In the inspected Workspace and Enterprise flow, the issue stays open while the request waits for review.
2. An **admin** or **owner** other than the requester opens **Not fixing → Requests** and selects the request.
3. Click **Approve or reject**, choose **Approve** or **Reject**, and add a **Note for the record** explaining the decision.
4. Review the consequence shown by the form. An approved request needs an expiry. Click **Approve until [date]** to accept it, or **Reject request** to keep the issue open.
5. On the decision page, use **Download this decision record (CSV)** for a specific formal exception request. To export the workspace's formal exception requests, open **Compliance reports → Won't fix for now → Download not-fixing decisions (CSV)**.
6. Review **Active**, **Waiting for approval**, **Ending soon**, and **Revoked / expired**. **Ending soon** covers active decisions ending within 14 days.
7. If the risk is no longer acceptable before its expiry, an authorized reviewer can open the decision and use **Revoke this decision → Revoke now**. Retain the history and reason.

**Expected result:** the approval or rejection appears in the decision history and audit log. Accepted risks retain requester and reviewer identity, justification, review reason, decision and expiry dates, linked suppression counts, and subsequent revoke/expiry events in the CSV.

Despite the broad download label, this CSV covers **formal exception requests and their linked suppressions**. It does not include direct false positive suppressions, directly accepted risks, gate overrides, or organization triage rules. Review those entries under **Not fixing** and include their relevant audit records separately when assembling evidence. The counters in **Won't fix for now** also count formal exception requests; they are not a total of every decision in Not fixing.

Suppression affects day-to-day finding visibility and gate handling according to the applicable policy. In a framework report, a suppressed mapped finding remains observed evidence, with its suppression state retained in JSON. It does not become a verified passing requirement. Keep the accepted risk CSV beside the framework report so a reviewer can see why the finding remains.

Use the false positive workflow when the reported issue is not a problem. That is a different decision from accepting a real risk until an agreed date; preserve the explanation appropriate to the decision.

## Export change history for an audit period

**Goal:** show the recorded checks and review decisions during an audit period.

1. Sign in as a workspace **owner** or **admin** with Workspace or Enterprise access.
2. Open **Audit evidence**.
3. Find **Change history for an audit (SOC 2 CC8.1)**.
4. Set **From** and **To** to the audit period. Both days are included, using UTC dates. The default is the last 90 days; one export can cover up to 366 days.
5. Click **Download CSV** for a workbook or **Download printable report** for a readable HTML file.
6. Open the HTML file in a browser and print it to PDF if required.
7. Review the export's repository, project, branch, pull request number and source, head commit, uploaded identity and trust, findings, gate result and conditions, override identity/time/reason, agent rules, protected path approvals, and accepted risks in force.
8. For the narrower agent view, open **Compliance reports → Changes with agent evidence** or use **AI agent changes only → Export agent changes** from Audit evidence. Choose **From**, **To**, and **Project** (or **All projects**), then download in the same way.

![Desktop agent change evidence export with UTC dates, project selector and export actions](../assets/customer-guide/compliance-export-desktop.png)

*Actual Cloud agent change exporter at a 1600 px desktop width, using illustrative data. The date range includes both UTC days; select the project before downloading CSV or a printable report.*

[Explore Audit evidence and change-history exports](../assets/customer-guide/cloud-ui-demo.html?mode=history).

*Choose the relevant evidence type. The report controls example above also shows the inclusive UTC date inputs and export formats; example actions do not download live workspace data.*

**Expected result:** a file representing the recorded scans in the selected scope. Each successful export is recorded in the activity log. The current change-history export route does not deduct report-generation credits; it requires the plan and role described above.

The full change history contains each qualifying pull request scan, so repeated scans of the same pull request can appear. Agent exports include records with recognized agent evidence. Editable commit names and co-author trailers identify a recorded signal; they do not establish who wrote every line. The export also preserves upload trust so a reviewer can distinguish sources.

Use your source control and deployment systems for merge, deployment, and ordinary pull request review records. This export records Skylos scans and Skylos decisions. Changes that were never scanned, changes without a qualifying pull request in the full PR scope, and reviews performed only in GitHub or GitLab are not established by this file.

## Create AI governance evidence

**Goal:** show the technical safeguard outcomes reported for supported AI application integrations.

1. Connect the CLI to the Cloud project using `skylos login` and the browser flow. Confirm the target workspace and project.
2. In the AI application's repository, run a defense scan and upload it:

   ```bash
   skylos defend . --format json --output defense-evidence.json --upload
   ```

3. Keep the local JSON with your engineering evidence. Confirm the defense upload appears in the project's scan history. A normal code scan alone does not create the defense attestation evidence these reports use.
4. Open **Audit evidence → Compliance reports → All frameworks**.
5. Choose **EU AI Act**, **NIST AI RMF**, or **ISO/IEC 42001** and use **Generate report**. The same displayed credit rules apply as for other new framework reports.
6. Read **CLI-attested check score**, **Evidence coverage**, the requirement rows, the scope notice, and **Not addressed by static verification** before sharing.
7. Download JSON from the saved report's history row so the detailed check outcomes accompany the readable artifact.

**Expected result:** a report built from each project's latest available defense attestation and the server's recognized control mappings. It describes the projects with recognized framework evidence; it does not imply that every workspace project has supplied evidence.

| Framework | Mapped technical themes in the current report | Additional evidence to arrange |
| --- | --- | --- |
| EU AI Act | Record keeping; accuracy, robustness and cybersecurity; resilience against AI specific attacks | Training data governance, human oversight, and the organizational risk management system are explicitly outside this report's static evidence. |
| NIST AI RMF | Accountable and transparent; privacy enhanced; secure and resilient; valid and reliable | Organizational policy/accountability and context/risk identification are explicitly outside this report's static evidence. |
| ISO/IEC 42001 | AI change management, logging and monitoring, system security, and data protection themes | Management system processes, audits, and continual improvement under clauses 4–10 are explicitly outside this report's static evidence. |

A mapped AI control is reported as passing only when the expected recognized checks are supplied exactly once with valid boolean outcomes and all projects with recognized evidence report those checks as passing. An observed failed check produces **Finding observed**. Missing, duplicated, or malformed expected evidence produces **Not evaluated** unless a failure was also observed. Projects without recognized framework evidence are outside the report's passing aggregation, so check the project count and evidence scope.

The checks include signals such as logging, model pinning, input limits, output validation, tool schemas and scope, prompt and retrieval context separation, and data filtering. They are static code evidence uploaded by the CLI; they do not independently demonstrate deployed behavior or legal conformance.

## Prepare a SOC 2 evidence pack

Suppose a customer asks how your team checks security issues and controls changes across three services during a quarter. Prepare a pack with a clear scope and records that can be traced back to the work.

1. **Define the scope.** List the three services, their Skylos projects, the intended branches, and the audit dates. Check that the workspace contains the relevant projects; a framework report aggregates its eligible project scans and has no per-report project picker.
2. **Confirm current code evidence.** Check each service's complete code scan and the branch/commit it represents. Run and upload a fresh full scan where needed before generating the point-in-time report.
3. **Generate one SOC 2 evidence report.** Use **Audit evidence → Compliance reports → SOC 2**. Keep canonical JSON plus HTML or PDF, the generation time, and fingerprint. The report supplies mapped code finding evidence for selected criteria.
4. **Export the audit period.** On **Audit evidence**, set the quarter's dates and download the full change history. This gives the recorded pull request check results and Skylos decisions for review toward CC8.1.
5. **Explain accepted risks.** Export **Download not-fixing decisions (CSV)** for formal exception requests and their linked suppressions. Cross-reference relevant requests by project, rule, issue, requester, reviewer, justification, and expiry. Separately review direct false positive/risk suppressions, gate overrides, and organization triage rules under **Not fixing**; the formal exception CSV does not contain them. Include the relevant decision and audit records in the evidence pack.
6. **Add policy context.** Open **Policy history** and retain the policy versions relevant to the period. Add the **Audit log** records needed to explain changes or decisions.
7. **Review access.** Open **Access review** and document the team's actual review, the access decisions it made, and any follow-up. A list of accounts alone does not prove the review occurred.
8. **Include AI scope when relevant.** Add the agent change export for the same period and AI governance reports if these services contain supported AI application integrations.
9. **Complete the pack with external records.** Attach the source control reviews, merge/deployment records, organizational policies, access approval evidence, incident handling records, and other items your reviewer requests. Identify each file's period and owner.
10. **Write a short cover note.** State which projects and periods the pack covers, which evidence comes from CLI assertions or unverified uploads, what is not evaluated, and what follow-up remains.

**Customer value:** reviewers receive a repeatable set of dated files with requirement references, code locations, decision reasons, and owners. Engineers can find the issue behind a requirement. Security leads can track deferred risks and expiry. A customer security review can examine the saved evidence without reconstructing the dashboard state from memory. These features reduce manual assembly and make follow-up more specific; actual time saved depends on your workflow.

Skylos supplies technical and operational evidence for review. Your auditor or assessor determines the evidence required for your scope and whether the relevant obligations are met.

## Compliance report troubleshooting

| What you see | What to do | Expected result |
| --- | --- | --- |
| **Compliance reports are part of the Workspace plan** | Ask the workspace owner to review **Billing** and confirm the deployed plan. | Eligible framework controls become available when the workspace has access. |
| **Download only** | Use the history links, or ask a member, admin, or owner to generate a new report. | Viewers can still obtain saved evidence. |
| **A report costs … credits. Your balance is too low.** | Confirm the displayed cost and ask the owner to review **Billing**. | Generation is available when the balance covers the displayed charge. |
| **Retry credit check** | Click it after checking connectivity. | The button shows the actual available cost/balance state. |
| **Not supported yet** | Choose a framework with a supported mapping; use other evidence for the unsupported standard. | No unsupported report generation charge is offered. |
| No active frameworks | Reload; ask your workspace administrator or support to check deployment configuration. | Active supported cards appear after configuration is available. |
| The report shows **Not evaluated** despite uploaded scans | Check the requirement note and scan scope. For ordinary mapped reports, absence of findings cannot establish every mapped check ran. For AI reports, check recognized attestation coverage. | Missing or incomplete evidence remains visible instead of being interpreted as a pass. |
| No AI governance evidence | Upload a current `skylos defend` report to the correct project and confirm it contains recognized integration/check evidence. | The framework report can describe the projects with recognized evidence. |
| **Report is still being generated** or final state unconfirmed | Retry the same format in the same tab after the indicated wait. The client retains the report request ID for safe retries. Check history before intentionally generating another report. | A completed request is replayed without a second charge. |
| Previous attempt failed safely and asks you to start again | Follow the displayed instruction to start a new attempt. | A failed pre-commit attempt does not leave a report generation debit. |
| Report page says it could not load | Use **Reload compliance reports**. If it persists, report the exact error and workspace to support. | A load failure is shown as unavailable evidence, not zero totals. |
| Change-history date range is too long | Use 366 days or fewer; export longer periods in parts. | Valid inclusive UTC ranges can be exported. |
| Change-history scope is too large | Shorten the dates or select one project in the agent export. Current limits include 5,000 scans and 5,000 accepted-risk records, with separate protected-approval bounds. | The service returns a complete bounded export rather than a partial file. |
| Change history is empty | Check dates, workspace, project, and the chosen full/agent scope. Verify qualifying scans were uploaded. | You can distinguish absent records from absent activity. |
| Some Not fixing decisions are missing from the exception CSV | Check whether they are direct suppressions, gate overrides, or organization triage rules. The CSV exports formal exception requests and linked suppressions only. | Gather those additional decision and audit records separately. |
| An export says new scans arrived while it was built | Retry. | The service returns a consistent export rather than a partial file. |
| JSON fingerprint mismatch | Compare original, unformatted JSON bytes with the full canonical JSON fingerprint for the same artifact. | An unchanged download matches; HTML/CSV/PDF hashes are different. |


[Open the complete Skylos customer guide](../customer-guide.md).
