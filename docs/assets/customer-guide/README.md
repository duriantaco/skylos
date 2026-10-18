# Customer guide visuals and sample evidence

These files accompany [the customer guide](../../customer-guide.md) and the [compliance report tutorial](../../guides/compliance-reports.md).

## Desktop screenshots

The guide uses a **1600 × 1050 desktop browser viewport** with a device scale factor of 1. The generated SOC 2 report and fix evidence use full-page captures at the same desktop width. These screenshots show actual Cloud React components and application CSS with isolated illustrative data. They do not show a signed-in customer workspace. No production report was generated, account changed, PR created, or credits spent.

| File | What it shows |
| --- | --- |
| `audit-reports-desktop.png` | Audit reports hub, audit-period change history and evidence destinations |
| `compliance-overview-desktop.png` | Actual Compliance reports page, framework editions, mapped requirements and report generation controls |
| `compliance-menu-desktop.png` | Actual SOC 2 report format menu, opened using its normal trigger |
| `compliance-history-desktop.png` | Saved report history, creator, creation time, SHA-256 fingerprint and HTML/CSV/JSON downloads |
| `compliance-report-desktop.png` | Generated SOC 2 report, scope notice, summary, evidence coverage and requirement statuses |
| `compliance-export-desktop.png` | Agent change evidence, inclusive UTC date filters, project selector and export actions |
| `fix-confirmation-desktop.png` | Actual confirmation before proposing a fix, opened using the normal action button |
| `fix-results-desktop.png` | Actual embedded fix evidence, observed checks, follow-up scan observations and coverage warning |
| `cloud-home.png` | Home repository board and repositories needing attention |
| `cloud-project.png` | Repository overview and latest result |
| `cloud-scan.png` | Scan result, gate verdict and recorded blocking evidence |
| `cloud-policy.png` | Workspace Policy controls |
| `cloud-not-fixing.png` | Recorded review decisions under Not fixing |
| `cloud-investigator.png` | Evidence Investigator controls and fixture results |

`desktop-capture-manifest.json` records the capture time, viewport, source, route parameters, content checks and browser errors. The Compliance reports fixture imports the actual production `CompliancePage`; only its workspace reads and exception expiry transport are replaced with isolated example responses. It renders the production framework cards, report history, agent exporter, accepted-risk section and navigation controls. Audit reports imports the real page directly. Other views use existing Cloud browser-test fixtures and production components. The wrapper identifies the data as illustrative.

All browser HTTP(S) requests were blocked during capture. Fixture interactions run locally. The two saved history rows are illustrative; the SOC 2 row uses the fingerprint of the demonstration JSON below. Captions in the guide state which component or output is shown. Legacy mobile test captures are not used by the guide.

## Interactive Cloud examples

`cloud-ui-demo.html` contains actual Cloud React components and application CSS with isolated illustrative fixtures. Its views include Compliance reports, Audit reports, Home, repository overview, scan result, Policy, Not fixing, Investigator and fix evidence. The Compliance reports view imports the complete production page, including saved reports and export controls.

The example replaces workspace reads and network requests with local responses and prevents external navigation and native form submission. Nothing is saved or charged. Displayed balances, history rows and prices are illustrative data. The standalone example and report HTML can be opened locally without a preview server. These illustrative Cloud captures are dated in the manifest; they do not establish the current deployed interface or scanner behavior.

## Illustrative SOC 2 report

The HTML, JSON and CSV were produced using the Cloud checkout's actual compliance requirement evaluator and report renderer, with invented workspace, project and finding data. The example does not assert a customer's compliance status.

`example-soc2-report.sha256` is the SHA-256 of the exact bytes in `example-soc2-report.json`. It does not fingerprint the HTML or CSV. The report demonstrates two distinct findings, requirement mapping, evidence coverage, and the distinction between **Finding observed** and **Not evaluated**.

Authenticated production workflows were not exercised. The guide's written steps were checked against the local CLI and Cloud source; the feature catalog records test results and known deployment differences.
