# Security Policy

Skylos handles security reports privately. Do not create a public GitHub issue
for a vulnerability or exposed secret.

## Supported Versions

Security fixes are prioritized for the latest released Skylos CLI version and
the current Skylos Cloud production deployment. Older CLI releases may receive
fixes when the issue has high impact or a practical upgrade path is not
available.

## Reporting a Vulnerability

Email security reports to aaron@skylos.dev with the subject `SECURITY`.

Include:

- A clear description of the issue
- Affected component: CLI, Cloud, GitHub Action, MCP server, docs, or package
- Steps to reproduce
- Impact and any known exploitability
- Affected version, commit, URL, or environment
- Your preferred contact information

If email is unavailable, open a private security advisory on GitHub where possible.

## Response Targets

Skylos aims to acknowledge valid reports within 2 business days and provide an
initial triage update within 5 business days. Critical issues may be handled on
an accelerated timeline.

## Safe Harbor

Good-faith security research is welcome when it avoids privacy violations,
destructive actions, service disruption, data exfiltration, and access to data
that does not belong to you. Stop testing and report immediately if you access
customer data, credentials, or production infrastructure unexpectedly.

## Secrets and Customer Data

Do not include real customer secrets, private source code, or personal data in a
report unless it is necessary to demonstrate impact. Redact sensitive values
where possible.
