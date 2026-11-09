# agent-pr-bench

Skylos vs Semgrep CE vs Bandit (and SonarQube when a server is configured) on
agent-written code changes. Method, corpus, labeling rules, results and
limitations: [`docs/benchmark-agent-code.md`](../../docs/benchmark-agent-code.md).

Reproduce (from the repository root, with Skylos' dependencies installed via
`pip install -e .`):

```bash
benchmarks/agent-pr-bench/run.sh            # add --strict to fail on unlabeled findings
```

Layout:

| Path | Content |
|---|---|
| `corpus/real_commits.json` | 36 pinned agent-attributed commits and the selection parameters that produced them |
| `corpus/seeded/bases.toml` | pinned upstream repositories for seeded cases |
| `corpus/seeded/cases/*.toml` | one seeded case per file: edits, story, ground-truth defects |
| `labels/findings.json` | TP/FP label and written reason for every in-scope finding, keyed by fingerprint |
| `results/` | tables and JSON written by `bench.py score` |
| `harness/` | workspace preparation, tool runners/normalizers, scoring |
| `scripts/select_real_commits.py` | one-time corpus selection (read-only GitHub API) |
| `tests/` | offline harness tests: `python3 -m pytest benchmarks/agent-pr-bench/tests` |

`--tools skylos-hook` replays each workspace's changed files through the
post-edit hook's own blocking policy (`harness/hook_driver.py`, one process per
file, changed line ranges only) and scores the blocking findings against the
same labels: a `skylos-hook` finding reuses the `skylos` label for the same
rule, file and line (`score.LABEL_ALIASES`). Non-blocking notes and per-file
wall times are kept as signals. This measures what an agent is told after an
edit, not what a full scan reports.

SonarQube: set `SONAR_HOST_URL`, `SONAR_TOKEN` and put `sonar-scanner` on
`PATH` (or set `SONAR_SCANNER`). Without them the runner records
`not run` and the tool is left out of the metric tables.
