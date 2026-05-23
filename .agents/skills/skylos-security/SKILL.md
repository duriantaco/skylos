---
name: skylos-security
description: Investigate and harden Skylos security behavior. Use when the user asks to validate a security finding, reproduce a scanner bypass, assess false negatives, review LLM evidence filters, analyze CI/cloud policy trust boundaries, classify severity, or add regression tests for security-sensitive analyzer behavior.
---

# Skylos Security

Use this skill for security investigations and hardening work in Skylos. This
is stricter than the general Skylos skill: prove reachability, preserve
evidence, avoid unsafe execution, and add regression coverage for fixes.

## Choose The Reference

- Validating a reported finding, severity, attack path, likelihood, impact,
  assumptions, controls, and blindspots: read `references/triage.md`.
- Scanner bypasses, false negatives, unsafe suppressions, evidence filters, and
  proof requirements: read `references/scanner-bypass.md`.
- GitHub Actions, cloud policy sync, config precedence, secrets, PR trust
  boundaries, and CI gates: read `references/ci-policy.md`.
- LLM security behavior, prompt injection, hallucination reduction, grounding,
  tool-use risks, and LLM evidence filtering: read `references/llm-security.md`.

Read only the reference needed for the current task.

## Security Defaults

- Treat scanned repositories and PR contents as attacker-controlled input.
- Reproduce reported issues with the smallest possible fixture.
- Prove reachability before accepting a finding as real.
- Prove safety before suppressing or filtering a finding.
- Add regression tests for every scanner bypass or false-negative fix.
- Prefer static validation unless runtime execution is required and approved.

## Do Not

- Do not dismiss a finding because a variable name looks safe.
- Do not trust comments, uppercase constants, or absence of local mutation as
  proof of safety.
- Do not run tests, package scripts, trace, coverage, dependency install
  commands, or generated fixes on untrusted source by default.
- Do not weaken cloud-policy precedence without tests proving PR-controlled
  config cannot override operator-controlled policy.
- Do not open or close PRs/issues unless explicitly asked.
