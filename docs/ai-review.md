# AI in Skylos

Skylos uses the word "AI" for three different jobs. Each has one name in the
CLI, these docs and Skylos Cloud.

| Job | Name | CLI | Skylos Cloud |
|---|---|---|---|
| An AI double-checks the issues Skylos found | **AI review** | `skylos . -a --ai-review` | Each issue shows Confirmed by AI, AI disagrees, AI unsure or Found by AI only, on the PR board, in Issues and on the issue page. Deep scans are an AI review of a whole repository |
| Rules for code that AI coding agents write | **Coding agents** | `skylos done`, `skylos agent install-hooks`, `skylos agent install-standards`, `skylos verify` | Coding agents, Agent checks, Policy › Coding agents, Bot approvals |
| Safety of your own AI features | **AI app safety** | `skylos discover`, `skylos defend`, `skylos agent test` | AI app safety |

## AI review

```bash
skylos . -a --ai-review                 # local report
skylos cloud --ai-review                # same, uploaded to Skylos Cloud
skylos . -a --ai-review --model claude-sonnet-4-20250514
```

- High-severity security issues in Python files are checked several times by
  your model (the same check as `--verify-security`). Security issues in other
  languages are not AI-reviewed yet.
- Unused-code issues are checked by your model, and by Jev when
  `TYPESAFE_API_KEY` is set. With only `TYPESAFE_API_KEY`, Jev reviews them
  alone.
- Each reviewed issue gets `metadata.ai_review` in JSON and SARIF output:
  one entry per reviewer with its verdict (`real`, `false_positive` or
  `unsure`), model, and reason.
- **Nothing is hidden and blocking never changes.** The gate only uses
  Skylos's rules. An issue the AI disagrees with still blocks until someone
  fixes it or marks it Not fixing.
- Without an LLM key or `TYPESAFE_API_KEY`, the scan prints one line and
  carries on unchanged.

What each verdict means in Skylos Cloud:

| Shown as | Meaning |
|---|---|
| Confirmed by AI | Skylos found it and the AI agrees. Fix these first. |
| AI disagrees | The AI thinks it is a false positive. Check the reason, then fix it or mark it Not fixing. |
| AI unsure | The reviewers split or could not decide. |
| Found by AI only | Only `skylos agent scan` reports these. Skylos's rules did not find it, and it never blocks. |

Only CI uploads (GitHub or GitLab OIDC, or a project key marked as a CI key)
set an issue's AI state in Issues. An upload from a laptop login shows its
verdicts on that scan only.

### In CI

Issues get their AI state only from scans of the default branch that CI
uploads. To turn AI review on there:

1. In the repository's GitHub settings, add the variable `SKYLOS_AI_REVIEW`
   with the value `true`.
2. Add one of `OPENAI_API_KEY`, `ANTHROPIC_API_KEY` or `TYPESAFE_API_KEY` as a
   repository secret.
3. Optional: add the variable `SKYLOS_AI_REVIEW_MODEL`, for example
   `claude-sonnet-4-20250514`. The default is `gpt-4.1`.

This works in the workflow the Skylos GitHub App writes (merge its workflow
update pull request first) and in one from `skylos cicd init` (run it again).
Only the default-branch scan reads the key. Pull request jobs never receive it,
and a key secret on its own does nothing without the variable.

`skylos agent verify`, `agent scan`, `agent security-quick`,
`agent security-deep` and `agent remediate` stay available when you want to
run one AI pass on its own.

## What is sent where

See [What Leaves Your Machine](../README.md#what-leaves-your-machine).
`--ai-review` sends code to your model provider (and to Jev when its key is
set), never to Skylos Cloud unless you upload.
