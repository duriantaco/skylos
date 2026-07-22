# LLM package map

The root of this package contains shared runtime surfaces and compatibility
entry points. Feature-specific implementation belongs in a subpackage.

## Subpackages

- `harness/`: bounded agent runs, tool registration, traces, replay, and
  benchmark harnesses.
- `investigator/`: repository-aware Deep Audit. `orchestrator.py` owns the
  turn loop; protocol, response validation, evidence, findings, prompts,
  adapter budgeting, and repository tools live in focused modules.
- `review/`: static agent-review findings, refutation, and routing.
- `verification/`: dead-code verification phases, entry-point discovery,
  LLM response handling, survivor checks, and verification data types.

## Root modules

- Core analysis: `analyzer.py`, `agents.py`, `schemas.py`, `context.py`,
  `graph.py`, `prompts.py`, `validator.py`, and `ui.py`.
- Repository evidence: `_grounding.py`, `repo_activation.py`, `liveness.py`,
  and `finding_evidence.py`.
- Security review: `security_taskflow.py`, `security_verifier.py`, and
  `threat_trace.py`.
- Remediation: `cleanup_orchestrator.py`, `orchestrator.py`, `planner.py`,
  `executor.py`, and `merger.py`.
- Stable verification entry points: `dead_code_verifier.py` and
  `verify_orchestrator.py`. Their implementation helpers live in
  `verification/`.
- Runtime support: `runtime.py` and `feedback.py`.

When adding a feature, prefer an existing subpackage or create a focused one
instead of adding another unrelated root module.
