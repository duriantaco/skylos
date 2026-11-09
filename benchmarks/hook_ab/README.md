# Hooks on/off pilot

Does an agent with the Skylos hooks ship safer code than the same agent without them?
Paired, following the design of [Guardrails Beat Guidance](https://arxiv.org/html/2604.11088v2):
same model, tools, prompt and base commit, with the hooks as the only difference.

```bash
python benchmarks/hook_ab/run_ab.py --work /tmp/ab --deps /path/to/deps --model sonnet --repeats 3
python benchmarks/hook_ab/run_ab.py --work /tmp/ab --deps /path/to/deps --summary
```

`--deps` holds a `.venv` with flask, flask-cors, requests, pytest, mypy and bandit, and a
`node_modules` with typescript, express and their types. Each run gets a throwaway Git
repository from `fixtures/`, file tools plus the type checker and pytest, and a dollar cap.
Twelve developer requests in `tasks.py` tempt a shortcut; none mentions security.

Each final diff is scored by a Skylos scan, by Bandit and by a plain search for added type
escapes, on production files. Acceptance tests the agent never sees check the feature works.
Paired differences use McNemar's exact test.

## Results, 8 Nov 2026: Sonnet and Haiku, 12 tasks, 3 repeats, 72 pairs

| Measure | Hooks off | Hooks on | McNemar p |
|---|---|---|---|
| Runs with any flagged defect or escape | 18 | 6 | 0.0005 |
| Runs with a type escape, plain search | 6 | 0 | 0.03 |
| Runs flagged by Bandit | 6 | 6 | 1.0 |
| Acceptance tests passing, of 60 | 54 | 54 | |
| Type checker passing, of 72 | 71 | 72 | |

| Per session | Hooks off | Hooks on |
|---|---|---|
| Sonnet time | 22 s | 47 s |
| Haiku time | 28 s | 70 s |
| Sonnet cost | $0.067 | $0.078 |
| Turns, Sonnet | 7.9 | 9.5 |

The effect comes from two tasks. `mypy-red` went from 6 runs using `cast` or `type: ignore`
to 0, with behavior kept. `debug-tracebacks` went from 5 runs with `debug=True` to 0, but
agents often replaced it with a flag that is on by default and bound to loopback. All 6
remaining hooks-on runs are `sort-column`: Bandit's B608 pattern rule on a query guarded by an
allowlist, or Skylos on an older form of it. On the other 9 tasks these models made no such
mistake in either arm.

Limits: the tasks are written to tempt; both models are careful; Skylos is one of the judges;
and this is a pilot, so it sizes a larger study and does not settle the question on real
projects.
