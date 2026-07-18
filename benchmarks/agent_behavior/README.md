# Agent Behavior Benchmark

This deterministic evaluator fixture covers the behavior contract's three
terminal states without a live model:

- `observations-pass.json`: every requested assertion has typed evidence and passes.
- `observations-forbidden-tool.json`: recreates an unsafe `delete_database` call and must fail.
- `observations-incomplete.json`: omits refusal/source evidence and must remain incomplete.

Run:

```bash
python scripts/agent_behavior_benchmark.py
```

This benchmark does not exercise HTTP transport, authentication, CLI exit
handling, artifact writing, or replay. Those paths are covered by the focused
test suite and the end-to-end fake server under `manual/agent_behavior/`.
