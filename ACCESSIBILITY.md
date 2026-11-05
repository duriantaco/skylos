# Accessibility

Skylos helps people understand and improve their code. Everyone, including
people with disabilities and people using assistive technology, should be able
to run a scan, understand its findings, read the documentation, and contribute.

This statement covers the Skylos command-line tool, interactive terminal view,
reports, documentation, and VS Code extension. It describes our accessibility
goals, contributor expectations, and how to report a barrier.

If something prevents you from using Skylos, [report an accessibility issue](#reporting-accessibility-issues)
or email [founder@skylos.dev](mailto:founder@skylos.dev).

## Priorities

For web content and editor webviews, we work toward
[WCAG 2.2 Level AA](https://www.w3.org/TR/WCAG22/). This is an aspirational
target, not a claim of verified conformance. Our priorities across Skylos are:

- **Keyboard access:** People should be able to reach and use controls without
  a mouse, follow a logical focus order, see which control has focus, and leave
  menus or dialogs without getting trapped.
- **Screen reader access:** Headings, controls, findings, and status messages
  should have a meaningful reading order and clear names. Changes such as
  errors or scan completion should be available without relying on sight.
- **Readable findings:** Explain findings in plain language, with copyable
  source locations. Do not rely on color, icons, or visual layout alone to
  communicate severity or next steps.
- **Readable content:** Use descriptive links, meaningful image descriptions,
  sufficient contrast, and layouts that remain usable when text is enlarged.
- **Language:** Use clear wording and identify the language of web pages and
  translated passages so screen readers can pronounce them appropriately.

## Contributor expectations

Follow [CONTRIBUTING.md](CONTRIBUTING.md) and include accessibility in the review
of changes that affect how people use Skylos.

### Testing and review

- For interactive changes, complete the affected task using only a keyboard.
  Check focus visibility and order, activation of controls, and entering and
  leaving menus or dialogs.
- For new controls or substantial layout changes, check screen reader reading
  order, control names and states, and announcements of errors and updates.
  Record anything you could not test so reviewers know what remains.
- For web content and editor webviews, use an automated accessibility check
  where available alongside manual checks. Automation alone cannot establish
  that a task is usable.
- Check web content at 200% zoom and narrow widths. Text and controls should
  remain readable and usable without hiding information or actions.
- For terminal output changes, review the plain and structured report formats
  as well as the visual report. Keep finding messages and locations available
  without requiring an interactive terminal view.
- In the pull request, describe the task tested, the operating system and
  relevant application or assistive technology versions, results, and any
  remaining barriers. Screenshots are optional and do not replace these notes.

Skylos does not currently have a dedicated automated accessibility check in CI.
Passing existing tests does not establish accessibility. Maintainers may request
changes when a contribution introduces a barrier.

### Documentation and content

- Use real headings in a logical order and real lists rather than visual
  formatting that only resembles them.
- Write descriptive link text that explains the destination or action.
- Give informative images meaningful alternative text and decorative images
  empty alternative text. The [W3C image description decision tree](https://www.w3.org/WAI/tutorials/images/decision-tree/)
  can help choose the right treatment.
- Explain complex diagrams nearby in text. Include copyable commands and
  findings alongside screenshots of terminal output.
- Give tables clear headers. Avoid tables when a short list is easier to read.
- Provide captions and transcripts for instructional videos, and describe
  essential visual information in text or narration.
- Use text labels alongside color or symbols that convey meaning.

## Reporting accessibility issues

[Open a Skylos issue](https://github.com/duriantaco/skylos/issues/new) and describe
the barrier. A title beginning with "Accessibility:" helps identify the report;
you do not need a special template or a suggested fix.

If GitHub is difficult to use, or you prefer a private report, email
[founder@skylos.dev](mailto:founder@skylos.dev) or use the
[private feedback form](https://skylos.dev/feedback?src=github), which does not
require a GitHub account.

Share whatever context you can:

- What you were trying to do, what happened, and what you expected.
- The command, page URL, report format, or editor feature involved.
- Steps to reproduce and the Skylos or extension version, if known.
- Your operating system, terminal, browser, editor, or assistive technology and
  versions, where relevant.
- How the barrier affects completing your task and any workaround you found.

Screenshots and recordings are optional. You do not need to disclose a
disability, diagnosis, or other personal information. Remove secrets and private
code from public reports. For security vulnerabilities, follow
[SECURITY.md](SECURITY.md).

### Severity

Maintainers assign severity during triage; reporters do not need to choose it.
We consider the effect on the task and whether a practical workaround exists.

- **Critical:** A core task is blocked with no practical workaround, such as
  being unable to read findings in any available report format.
- **Serious:** A task requires substantial extra effort or a difficult
  workaround, such as a report view that cannot be navigated by keyboard.
- **Moderate:** A task remains possible but requires repeated extra effort,
  such as unclear labels that make finding the right action difficult.
- **Minor:** A localized issue adds friction with little effect on completing
  the task, such as an unnecessarily verbose image description.

### How we respond and prioritize fixes

We aim to acknowledge reports respectfully, clarify the affected task, and
explain next steps. Reports that block core tasks take priority. Where possible,
maintainers share a workaround, track the fix, and update the report when its
status or expected timeline changes. We may invite you to try a fix; you are not
required to test it for us.

We do not currently commit to fixed response or resolution times. After triage,
maintainers communicate an owner and an estimated timeline when available. If
an estimate changes, we explain the delay and share an updated estimate or next
step. Dependencies on terminals, editors, browsers, or other projects may affect
when a barrier can be resolved.

## Ownership and maintenance

Skylos maintainers own accessibility work, including triaging reports, tracking
barriers, reviewing contributions, and keeping this statement accurate. The
project contact is [founder@skylos.dev](mailto:founder@skylos.dev).

Review this statement when user-facing interfaces or reporting channels change,
and during release review. When responsibility changes, maintainers should
update the contact details and hand over open accessibility reports.

## Supported environments and evaluation status

The CLI requires Python 3.10 or newer and is intended for use on Linux, macOS,
and Windows. Documentation is read in a browser, and the editor extension runs
in VS Code. Platform availability does not establish accessibility with every
terminal, browser, editor, or assistive technology.

A formal accessibility evaluation and a matrix of tested assistive technology
combinations are not currently documented. We therefore do not claim verified
support for particular screen reader or browser combinations. Future evaluation
results should identify the scope, date, method, evaluator, versions tested,
and remaining barriers.

## Known limitations and alternatives

Visual terminal reports use tables, panels, and symbols whose reading order or
meaning may be harder to follow with some terminal and screen reader settings.
The interactive terminal view has not been documented as evaluated with screen
readers. If either view is difficult to use, try the plain findings format:

```bash
skylos . --format concise
```

For structured results you can open or process in another tool, save JSON:

```bash
skylos . --format json --output skylos-report.json
```

See the [output format guide](docs/cli-output.md) for available formats. These
alternatives may help with reading findings; they are not a guarantee that every
interactive task has an accessible equivalent.

Accessibility testing across documentation and editor views is incomplete.
Please report barriers through the channels above so maintainers can track the
affected task and any available workaround.

## Feedback

Suggestions for improving this statement or Skylos's accessibility practices are
welcome through an issue, pull request, or the contact options above. For a
barrier affecting you now, use the reporting process so we can understand its
impact and help you complete your task.
