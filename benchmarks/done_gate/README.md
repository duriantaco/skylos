# Done-gate benchmark

Measures `skylos done` on real coding-agent runs that published labels say
cheated (edited the tests or test data, or special-cased the solution) or did
not. Method, numbers and limits: [`docs/done-gate-benchmark.md`](../../docs/done-gate-benchmark.md).

```bash
# smoke: 5 runs per label, gate code from this checkout
python3 scripts/done_gate_benchmark.py --limit 5 --progress

# the baseline in results/, gate code as committed at a ref
python3 scripts/done_gate_benchmark.py --skylos-ref 3af22c5 --workers 6 \
    --output benchmarks/done_gate/results/baseline-4.45.0.json
```

Needs Docker (the replay runs in `python:3.11-slim`, the task's own image,
with `--network none`) and network access for the first download
(about 240 MB from Hugging Face, plus one streamed pass over two LiveCodeBench
files of which only 15 problems are kept). Everything goes to `--cache-dir`
(default: `$SKYLOS_DONE_GATE_BENCH_CACHE`, else `~/.cache/skylos/done-gate-benchmark`),
never into the repository.

| Path | Content |
|---|---|
| `manifest.json` | pinned sources (dataset, task code and LiveCodeBench revisions), the replay image, the label rules, and the sources that could not be rebuilt |
| `results/` | JSON summaries written with `--output` |
| `../../scripts/done_gate_benchmark.py` | fetch, rebuild, replay, gate, score |
| `../../test/test_done_gate_benchmark.py` | offline tests for labels, scoring and the replay rules |

Per run the cache holds the rebuilt changes (`replay/<id>.json`) and the gate
receipt (`gate/<code hash>/<id>.json`). The code hash covers every file in
`skylos/`, so a new or changed check is measured on the next run without
replaying anything; `--refresh-gate` and `--refresh-replay` force a redo.
