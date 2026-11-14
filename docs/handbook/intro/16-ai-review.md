# The optional AI review

No AI model takes part in the rules in this handbook. The same code and the
same settings give the same findings, except where a rule looks things up
online (`--sca` and the registry checks of `--ai-defects`), whose answers
can change over time. On top of the rules, you can ask an AI model for a
second opinion.

```bash
skylos . -a --ai-review
skylos . -a --ai-review --model claude-sonnet-4-20250514
```

## What it reviews

- **High-severity security findings in Python files.** Your model checks
  each one several times (three runs, at most 20 findings, worst first). This
  is the same check as `--verify-security`. Security findings in other
  languages are not AI-reviewed yet.
- **Unused-code findings**, in every language: by your model, and by Jev, an
  outside dead-code model, when `TYPESAFE_API_KEY` is set.

Each reviewed finding records one verdict per reviewer (`real`,
`false_positive` or `unsure`), with the model and its reason: in JSON under
`metadata.ai_review`, in SARIF under `properties.skylos_metadata`.

> **Display only.** The AI review never hides a finding and never changes
> the gate or the exit code. A finding the AI disagrees with still blocks
> until someone fixes it, suppresses it or adds it to a baseline.

## What it needs and what it sends

It needs the `skylos[llm]` extra and an API key for your model provider, or
`TYPESAFE_API_KEY`. Without one, the terminal report prints one line and the
scan carries on unchanged. The default model in this release is `gpt-4.1`.

What it sends to your provider, with your key:

- for a security finding, the flagged Python file with comments and
  docstrings removed, and the rule's message;
- for an unused-code finding, the symbol's source and the matching code
  Skylos found elsewhere in the project.

With `TYPESAFE_API_KEY`, Jev also receives the unused-code candidates and a
bounded copy of the project's source. Nothing goes to Skylos Cloud unless you
also upload.

None of the "Checked" lines in this handbook used the AI review.
