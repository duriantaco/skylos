# Security Triage Reference

Use this when deciding whether a reported Skylos security finding is real,
reachable, and correctly classified.

## Triage Workflow

1. Identify the security claim, affected commit, file, rule/finding ID, and
   alleged attacker-controlled input.
2. Read the relevant code path from input source to sink.
3. Reproduce with a minimal fixture or direct helper invocation when safe.
4. Confirm whether the finding is emitted, suppressed, or missed.
5. Classify the result as true positive, false positive, false negative,
   duplicate, or not enough evidence.
6. If fixing code, add a regression test that fails on the old behavior.

Do not rely on screenshots, summaries, or model claims when repository evidence
is available.

## Evidence Standard

Strong evidence includes:

- Source-to-sink path with file and line references.
- Executable static test or helper-level proof.
- Before/after output from Skylos.
- Regression test showing old behavior fails and new behavior passes.

Weak evidence includes:

- A suspicious variable name without data-flow proof.
- A comment claiming data is safe.
- A framework assumption without checking the framework pattern.
- A model answer with no source or test artifact.

## Severity Format

Use this structure when reporting:

- Summary: one or two sentences describing the bug and affected path.
- Attack path: attacker-controlled input to scanner result, CI gate, secret,
  policy, or code execution impact.
- Likelihood: prerequisites and ease of exploitation.
- Impact: what an attacker gains or bypasses.
- Assumptions: conditions that must hold.
- Controls: existing mitigations.
- Blindspots: what was not validated.
- Validation: commands, tests, fixtures, or helper invocations used.

## Severity Heuristics

- Critical: direct credential compromise, remote code execution in Skylos
  infrastructure, or cross-tenant compromise.
- High: reliable bypass of mandatory security gates with broad exposure, or
  unsafe execution with meaningful secret/code impact.
- Medium: integrity loss in scan results, CI policy bypass under realistic
  prerequisites, or security false negatives that require a specific mode.
- Low: limited or noisy issue with narrow preconditions and low blast radius.

Keep severity tied to product impact, not how clever the proof is.

## Minimal Report Checklist

- Affected files and functions.
- Exact unsafe condition.
- Why existing controls do not stop it.
- Reproduction steps or test fixture.
- Fix direction and regression test expectation.
