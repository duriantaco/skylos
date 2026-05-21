# Agent Review Benchmark

This benchmark measures the fast agent-review lane, not the static analyzer.

What it checks:

- whether the LLM review path attaches findings to the right owner symbol
- whether clean files stay quiet
- whether review latency stays within a reasonable budget
- how many Skylos API tokens the fast review lane spends per case
- how security coverage is landing by benchmark class
- how many Codex tokens are consumed during the head-to-head compare run

What it does not check:

- dead-code verification accuracy
- static rule precision
- repo-wide reachability certainty

Run it with:

```bash
python3 scripts/agent_review_benchmark.py --manifest benchmarks/agent_review/manifest.json
```

Adversarial grounding cases live in a separate manifest:

```bash
python3 scripts/agent_review_benchmark.py --manifest benchmarks/agent_review/adversarial_manifest.json
```

The adversarial manifest is public but not part of the default required gate.
Some cases intentionally document current failure modes or high-cost review
paths while grounding and verification work is still in progress.

Compare against Codex with:

```bash
python3 scripts/compare_codex_skylos_agent_review.py --manifest benchmarks/agent_review/manifest.json
```

The compare script reads token usage from `codex exec --json` `turn.completed` events, so Codex token totals are now measured directly during head-to-head runs.

This benchmark is intentionally symbol-oriented. A review finding only counts as correct if it points to the owning function/class/method/variable, not a syntax token like `except`.

The checked-in suite is intentionally difficult. It includes:

- branch-heavy handlers
- inconsistent return contracts
- swallowed exceptions
- async blocking calls
- missing `await`
- mutable default state
- resource cleanup mistakes
- duplicated branch conditions
- tricky clean async/control-flow modules that should stay quiet
- request-driven Flask SQL injection and shell-injection handlers
- getter-based command injection with a nearby safe argv-based helper
- request-driven Flask SSRF with a nearby constant-url health probe
- request-driven path traversal with a nearby fixed-path file reader
- upload-path traversal with a nearby basename-sanitized handler
- JWT verification bypass with a nearby algorithm-pinned decode helper
- FastAPI query-parameter SSRF with a nearby constant-url probe
- open redirect with a nearby urlparse-guarded redirect helper
- reflected XSS with a nearby escaped template path
- unsafe pickle deserialization with a nearby JSON-only handler
- unsafe tar extraction with a nearby member-validated extraction path

Benchmark cases can optionally declare `scan.issue_types`, which lets the suite
exercise stricter review lanes such as `["security_audit"]` instead of the
default mixed fast-review path.

Security cases should also declare `security_classes` so the corpus scales by
major vulnerability family rather than by an unbounded list of one-off case
names. The current class buckets are:

- `sql_injection`
- `command_injection`
- `ssrf`
- `path_traversal`
- `file_upload`
- `auth_bypass`
- `xss`
- `open_redirect`
- `deserialization`
- `archive_extraction`
- `secrets_exposure`

This keeps the benchmark representative instead of exhaustive: we want a few
strong vulnerable/safe cases per class, not a thousand disconnected examples.
