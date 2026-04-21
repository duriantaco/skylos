# Agent Review Benchmark

This benchmark measures the fast agent-review lane, not the static analyzer.

What it checks:

- whether the LLM review path attaches findings to the right owner symbol
- whether clean files stay quiet
- whether review latency stays within a reasonable budget
- how many Skylos API tokens the fast review lane spends per case
- how many Codex tokens are consumed during the head-to-head compare run

What it does not check:

- dead-code verification accuracy
- static rule precision
- repo-wide reachability certainty

Run it with:

```bash
python3 scripts/agent_review_benchmark.py --manifest agent_review_benchmarks/manifest.json
```

Compare against Codex with:

```bash
python3 scripts/compare_codex_skylos_agent_review.py --manifest agent_review_benchmarks/manifest.json
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

Benchmark cases can optionally declare `scan.issue_types`, which lets the suite
exercise stricter review lanes such as `["security_audit"]` instead of the
default mixed fast-review path.
