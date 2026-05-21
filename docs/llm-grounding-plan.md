# LLM Grounding Plan

Goal: reduce LLM hallucination and false positives by adding bounded, local graph evidence to the existing repo activation context. GitNexus is only a design reference; Skylos must not depend on the GitNexus package, MCP server, or dependency tree.

## Checklist

- [x] Add Skylos-native Python graph grounding with no new dependencies.
- [x] Emit high-confidence facts only: callers, callees, entrypoint traces, related tests, confidence, and graph limits.
- [x] Keep facts bounded so prompt size does not grow without control.
- [x] Wire grounding into repo activation context by default after deterministic checks.
- [x] Update prompts so the model treats graph facts as evidence and does not invent missing reachability.
- [x] Add regression tests for risky, safe, and clean fixtures.
- [x] Run targeted deterministic tests.
- [x] Run agent-review baseline and grounded benchmark if an LLM provider is available.
- [x] If grounding regresses, remove it before finishing. Grounding did not regress, so it remains enabled by default.
- [x] Add an always-on deterministic LLM finding verifier after analysis collection.
- [x] Keep verifier conservative: no new dependencies, no GitNexus runtime, no feature flag.
- [x] Suppress only refuted security findings: unreachable non-test symbols with entrypoint evidence, allowlisted argv-list subprocess calls, and plainly parameterized SQL calls.
- [x] Run a temporary adversarial benchmark against Skylos static, Vulture static, and the LLM analyzer.

## First Useful GitNexus Idea

The first thing to copy is not GitNexus' storage, MCP interface, semantic search, or package dependency graph. The useful core is symbol grounding:

- which symbols call the reviewed symbol
- which symbols the reviewed symbol calls
- which entrypoints can reach it
- which tests are related
- which facts are static evidence versus heuristics
- where the graph is partial

## Final Validation

- Focused regression tests: `38 passed`.
- Full agent-review benchmark: `25/25` passed, `failure_count=0`, `overall_score=100.0`.
- Targeted shell-hook regression rerun: passed after narrowing graph traces to multi-step paths and clarifying safe allowlisted subprocess calls.
- Verifier-focused tests: `30 passed`.
- Full test suite: `4074 passed`, `4 skipped`, `2 warnings`.
- Full agent-review benchmark after verifier: `25/25` passed, `failure_count=0`, `overall_score=100.0`, `60435` tokens, `98.5327s`.

## Hard Benchmark Evidence

Temporary fixture path: `/private/tmp/skylos_hard_grounding_benchmark/maze`.

The case includes two live vulnerable paths and four lookalikes that should stay quiet:

- Expected present: `compose_lookup`, `run_dynamic`.
- Expected absent: `compose_archive`, `lab_debug_query`, `run_allowed`, `run_sample`.

Measured results:

- Skylos static security: `66.25` overall, `0.5` recall, `0.75` absence guard, `0.5904s`.
  - Found symbols: `run_dynamic`, `run_sample`.
  - Missed: `compose_lookup`.
  - False positive: `run_sample`, which static dead-code evidence marks unreachable.
- Skylos static dead-code: `100.0` overall, `0.5054s`.
  - Correctly marked `lab_debug_query` and `run_sample` unused, while keeping `compose_lookup`, `compose_archive`, `run_dynamic`, and `run_allowed` used.
- Vulture static dead-code: `100.0` overall, `0.2137s`.
  - Same labeled liveness result as Skylos dead-code; also reported unlabeled unused helpers in `app.py`, `formatting.py`, and `storage.py`.
- LLM security audit with verifier: `100.0` overall, `1.0` recall, `1.0` absence guard, `14.8653s`, `8324` tokens.
  - Final symbols: `compose_lookup`, `run_dynamic`.
- LLM security+quality review with verifier: `100.0` overall, `1.0` recall, `1.0` absence guard, `15.6239s`, `12195` tokens.
  - Final symbols: `compose_lookup`, `handle_api`, `run_dynamic`; the extra `handle_api` is a quality finding, not a forbidden security symbol.

## Extreme Benchmark Evidence

Temporary fixture paths:

- Framework/package-root case: `/private/tmp/skylos_extreme_grounding_benchmark/extreme`.
- Static-blind plugin-dispatch case: `/private/tmp/skylos_static_blind_benchmark/blind`.
- Public adversarial manifests:
  - `benchmarks/agent_review/adversarial_manifest.json`.
  - `benchmarks/dead_code/adversarial_manifest.json`.

Framework/package-root case:

- Purpose: Flask-style decorator root, pyproject script root, app/CLI roots, safe lookalikes, dead risky decoys, mutable allowlist trap.
- Skylos static security: `63.33` overall, `0.5` recall, `0.6667` absence guard, `0.9599s`.
- Skylos dead-code static: `100.0` overall, `1.105s`.
- Vulture dead-code static: `83.56` overall, `0.1969s`; false-positive on `admin_query_route` and `dangerous_admin`.
- LLM security audit before extra hardening: `66.67` overall.
- LLM security audit after extra hardening: `91.67` overall, `0.8333` recall, `1.0` absence guard, `24.2488s`, `16838` tokens.
  - Final symbols: `admin_query_route`, `dangerous_admin`, `dispatch_http`, `load_account`, `run_dynamic_hook`, `run_mutable_runner`.
  - Remaining miss: `fetch_partner`.
- LLM security+quality review after extra hardening: `87.14` overall, `1.0` recall, `0.6667` absence guard, `43.4677s`, `24801` tokens.
  - It found `fetch_partner` but reintroduced false positives `fetch_internal_status` and `lab_fetch`.

Static-blind plugin-dispatch case:

- Purpose: dynamic `module:function` registry strings, `importlib.import_module`, `getattr`, live plugin handlers, safe lookalikes, dead risky decoys.
- Skylos static security: `63.33` overall, `0.5` recall, `0.6667` absence guard, `0.8125s`.
- Skylos dead-code static: `59.0` overall, `1.5629s`; all registry-dispatched plugin handlers were marked unused.
- Vulture dead-code static: `59.0` overall, `0.1184s`; same labeled failure pattern as Skylos.
- LLM security audit before extra hardening: `50.0` overall, final findings empty.
- Diagnostic LLM security audit with verifier disabled: `82.5` overall, `1.0` recall, `0.5` absence guard.
  - This proved the LLM generated the true positives, but the verifier was suppressing them because it did not understand string registry roots.
- LLM security audit after extra hardening: `100.0` overall, `1.0` recall, `1.0` absence guard, `20.5232s`, `11865` tokens.
  - Final symbols: `charge_card`, `fetch_url`, `run_mutable_registered`, `ship_audit`.
- LLM security+quality review after extra hardening: `94.17` overall, `1.0` recall, `0.8333` absence guard, `35.0098s`, `17605` tokens.
  - It reintroduced false-positive `lab_fetch`.

Post-hardening validation:

- Focused tests: `27 passed`.
- Checked-in agent-review benchmark: `25/25` passed, `failure_count=0`, `overall_score=100.0`, `60319` tokens, `86.3307s`.

## Acceptance Criteria

- No GitNexus runtime dependency.
- No new third-party dependencies.
- Grounding context remains small and deterministic.
- Clean/safe benchmark fixtures do not gain false-positive language from the context itself.
- Existing repo activation behavior still ranks central files and related tests.
- Agent-review results are not worse; if they are worse, grounding is removed.
- LLM verifier remains enabled because it improved the hard case from `82.5` to `100.0` without checked-in benchmark regression.

## Hardening Backlog

The current verifier works, but the next hardening should focus on stronger deterministic proof rather than more prompt text.

1. Replace regex-based safe-sink suppression with AST proof.
   - Prove `subprocess.run(...)` is safe only when `shell=True` is absent and the executable/argv list resolves to literals or a same-module immutable allowlist.
   - Prove parameterized SQL is safe only when the query expression resolves to a literal/constant query and parameters are passed separately.
   - Add adversarial tests where an uppercase allowlist is imported, mutated, or built from user input; those must not be suppressed.
   - Status: partially implemented for subprocess calls. Mutable local allowlists are no longer treated as safe.

2. Reuse Skylos dead-code liveness roots for LLM finding verification.
   - Current LLM liveness roots are entrypoint basename heuristics such as `app.py`, `cli.py`, and `main.py`.
   - Skylos already has richer framework and package entrypoint evidence for pyproject scripts, Flask/FastAPI decorators, Click/Typer commands, pytest fixtures, and route registration.
   - The verifier should consume those roots or evidence records so live framework endpoints are not incorrectly treated as dead.
   - Status: partially implemented for decorator roots, `pyproject.toml` script roots, and `module:function` string registry roots.

3. Add an evidence contract per finding.
   - Required fields: source symbol, sink symbol, source-to-sink trace, liveness status, safe-pattern proof, and graph limitations.
   - A finding can be CI-blocking only when it has a positive evidence contract or a deterministic static corroboration.
   - Refuted findings should be counted and exported in benchmark metadata, even when they are removed from final output.

4. Add independent challenge passes only for high-impact findings.
   - Use a Chain-of-Verification style pass: generate candidate finding, ask independent verification questions, answer from source/graph evidence, then finalize.
   - Keep this bounded to unmatched LLM-only security findings and critical/high severity cases because agentic verification has useful accuracy upside but real cost.

5. Add uncertainty sampling for unstable findings.
   - Run 2-3 cheap independent verdict prompts only when deterministic evidence is incomplete and the finding is security-critical.
   - If verdicts disagree, keep the finding as `needs_review` instead of suppressing it.

6. Add hard benchmark families, not one hard case.
   - Include framework entrypoints, package scripts, alias imports, dynamic dispatch, safe wrappers, tainted-but-sanitized flows, and dead risky decoys.
   - Track both candidate LLM output and post-verifier output so we can tell whether improvements come from better prompting or better proof.

Research basis:

- RAG and external memory improve factual grounding and provenance compared with parametric-only generation: https://arxiv.org/abs/2005.11401.
- Chain-of-Verification reduces hallucination by separating draft generation from independent fact-checking questions: https://arxiv.org/abs/2309.11495.
- SelfCheckGPT-style sampling can detect unstable claims from black-box models by checking cross-sample consistency: https://arxiv.org/abs/2303.08896.
- LLM/static-analysis hybrids show strong false-positive reduction when findings are enriched with traces and structured evidence: https://arxiv.org/abs/2601.18844 and https://arxiv.org/abs/2510.02534.
- Vulnerability-specific RAG improves distinguishing vulnerable code from benign patched lookalikes: https://arxiv.org/abs/2406.11147.
