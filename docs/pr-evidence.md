# PR evidence and fix checks

Skylos PR cards put the finding, location, impact and suggested next step first.
Expand **Evidence and context** for the supporting source, graph context and limits.
Generated GitHub review workflows enable cards with `--evidence-cards`.

The visible evidence labels describe what is available:

- **Source path found:** a rule supplied its required structured static evidence.
- **Static match:** a deterministic rule matched, without a complete source path.
- **Needs context:** important evidence is missing or comes only from model review.

A static match, model verdict or severity does not establish runtime reproduction.
Cards do not show the old severity-derived confidence percentages as probabilities.
Existing raw findings, severities and gate decisions are preserved.

The context packet includes bounded Python callers and callees, source excerpts,
file hashes, candidate tests and analysis limits. It shares the existing static
import and call resolver with AI review. Dynamic dispatch and external callers can
remain unresolved. Candidate tests have **not run** merely because they appear in
the packet. Source links appear only when the collected file matches the linked
commit. The collected context is separate from the original scan snapshot.

AI remediation uses the same packet alongside the local fix context. It records
the actual check command, result and source hashes. Disabled or missing tests say
**Not run**; an applied change with incomplete checks remains **Incomplete**.
A successful scanner rescan is a static check, not a runtime exploit test.
Generated regression checks are reported separately from the project test suite.
Recognized pytest commands require case receipts; an all-skipped suite cannot
pass. Other selected commands report their exit result without claiming test
cases executed. Multiple applied fixes get a final shared check.

Remediation compares findings before and after editing the affected file and
rejects newly introduced findings. This check covers that file and the enabled
scan categories; it does not prove every repository behavior is preserved.
Before publishing a fix PR, Skylos checks the current and committed bytes against
the recorded hashes. Later edits, unexpected staged files or changed commit-hook
output stop publication. Incomplete checks produce draft PRs. Failed checks or a
requested PR that could not be published produce a failing CLI exit status.

Cloud PR action links open authenticated evidence or the existing fix choices.
Opening a link does not start a paid review or write a fix. The existing permission,
credit and current-source checks still apply when the user confirms an action.
The Cloud changes must be deployed before those new links appear on hosted PRs.
