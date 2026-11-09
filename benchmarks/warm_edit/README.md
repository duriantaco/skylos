# Warm-Edit Hook Benchmark

This benchmark times the agent edit loop: how long `skylos hook recheck FILE`
takes on one real file, first as found and then after each of several small
edits. That is the latency a coding agent waits for after every edit when the
post-edit hook is installed, including process start-up. The file is restored
byte for byte when the run ends, including when a recheck fails. If the file
changes independently during the run, the benchmark stops and leaves those
contents untouched rather than replacing them with its original copy. Run it
without editing or formatting that file concurrently.

## Run

```bash
python scripts/warm_edit_benchmark.py skylos/cli.py --repo . --edits 5
python scripts/warm_edit_benchmark.py src/app.ts --repo /path/to/repo --json
python scripts/warm_edit_benchmark.py skylos/cli.py --output .skylos-internal/bench/warm-edit.json
```

Each warm round appends one top-level marker statement for the file's
language (`bench_edit_marker_N = N` in Python, an exported constant in
TypeScript, and so on) so the content hash changes the way a real edit does.
The marker starts on a new line even when the original file has no final newline.
Pass `--skylos PATH` to time a specific executable; by default the one beside
the running interpreter is used, then the one on `PATH`.

## Columns

- `first`: the run before any edit, with whatever caches the repository
  already had. It is not a cold-cache number unless the caches were cleared.
- `warm p50` / `p95`: median and nearest-rank 95th percentile of the edit
  rounds. With five rounds, nearest-rank p95 is the slowest sample; a larger
  sample is needed to assess tail latency. The engine work item targets a
  warm p95 under one second.
- `exit`: 0 means no blocking issue, 1 means the hook would block, anything
  else aborts the benchmark.
- The header records the Skylos version, commit, number of dirty paths,
  Python and platform, because all of them move the numbers.
- Each run's JSON includes `verification_stats`, a list of diagnostic records
  requested with `SKYLOS_VERIFY_STATS=1`. Module-facts records expose whether
  the index is enabled, entries loaded, hits, misses, rebuilds and reference
  targets, so timings can distinguish cache reuse from rebuilding. Records
  are collected from stderr without replacing the hook's verdict. An older
  executable that does not emit these diagnostics produces an empty list.

## Baseline

| Date | Skylos | Commit | File | Repo | Edits | First | Warm p50 | Warm p95 | Machine |
|---|---|---|---|---|---|---|---|---|---|
| 8 Nov 2026 | 4.50.1 (working tree) | 4efe5acd, 84 dirty paths | `skylos/cli.py` (6,119 lines) | skylos, 794 Python files | 5 | 26.15 s | 22.45 s | 23.59 s | macOS 13.7.3 arm64, Python 3.14.4 |
| 8 Nov 2026, later | 4.50.1 (working tree) | 8cd6633c, verification scoping and hook policy applied | `skylos/cli.py` (6,119 lines) | skylos, 794 Python files | 5 | 13.56 s | 13.58 s | 13.96 s | macOS 13.7.3 arm64, Python 3.14.4 |

The first row's profile (cProfile, which inflates wall time about 6x) put the time
in repo-wide passes: module facts rebuilt for about 1,870 modules (34%), Python
dependency import probing (16%), the manifest walk (8%) and repository policy files
(7%). After verification scoping, 78% of a run on this file is analysis of the file
itself, mostly quality visitors and taint flows.

The fixed cost is about 2 s on a 10-line file. Hook time on other repositories comes
from `benchmarks/agent-pr-bench` with `--tools skylos-hook`.
