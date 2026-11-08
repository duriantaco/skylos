# Profile Skylos analysis

Use `--profile` to see where Skylos spends time while checking a repository:

```bash
skylos . --danger --profile
skylos src/app.py --format json --profile
skylos verify src/app.py --format json --profile
```

Profiling measures Skylos's own analysis. It does not run the application or
enable tests, call tracing, coverage execution, or a type checker. Those
features keep their existing options and execution requirements. Profiling
does not change rules, severities, quality-gate thresholds or exit-code policy.
Its overhead can make timed work reach an existing limit sooner; that work
still reports incomplete rather than passing.

The human profile goes to stderr, including when the report uses JSON on
stdout. The `json` and `json-ci` scan reports and verify JSON responses also
contain a top-level `profiling` object. To save a
standalone profile, use `--profile-output`; that option enables profiling even
without `--profile`:

```bash
skylos . --format json --profile-output profile.json > findings.json
```

The output directory must already exist, and the profile path must differ from
`--output` so the two artifacts cannot overwrite each other. An unavailable profile output path
is an operational error (exit 2), including with `--force`; the normal report
is still rendered when analysis completed. An existing scanner exception is
preserved if writing its partial profile also fails.

## Read the profile

The report includes:

- **Phase wall times:** elapsed time between the scanner's progress phase
  markers, including time waiting for workers or subprocesses. Repeated
  visits to a phase are combined. Work before the first marker is listed as
  `analysis setup`.
- **Top cumulative scanner functions:** Python functions in Skylos with the
  most time including child calls. Rows overlap; do not add their times.
- **Top self-time scanner functions:** functions with the most time inside
  the function itself, excluding child calls.
- **Call counts:** total calls and, in JSON, primitive calls excluding
  recursive re-entry.

Function measurements cover the current process and thread. Worker-process,
other-thread and subprocess internals are not profiled. Their enclosing phase
can still be slow even when the function list does not expose the work inside
them. An explicitly requested type check runs separately from this static
scanner profile; its elapsed time is reported as `type_check.seconds`. Calls
inside that subprocess are not application or compiler runtime profiles.

Profiling adds overhead, sometimes substantial overhead for code that makes
many Python calls. Use the ordinary warm-edit benchmark for latency comparisons;
use `--profile` to locate work that explains those timings. The JSON records
this limitation alongside the measured values.

Normal scans profile the main analyzer call, excluding CLI startup, report
formatting and uploads. Verify profiles its static verification call, including
the separately reported static behavior comparison when enabled.

## JSON shape

The `profiling` object in a scan report and the standalone file have the same
shape:

```json
{
  "schema_version": 1,
  "kind": "skylos_analysis",
  "completed": true,
  "wall_seconds": 0.42,
  "phases": [
    {"name": "analysis setup", "seconds": 0.12, "visits": 1},
    {"name": "AI defect scan", "seconds": 0.3, "visits": 1}
  ],
  "functions": {
    "by_cumulative": [],
    "by_self": []
  },
  "notes": []
}
```

Each function row contains `file`, `line`, `function`, `calls`,
`primitive_calls`, `self_seconds` and `cumulative_seconds`. File names refer to
scanner source under `skylos/`. A partial profile has `completed: false`; its
timings do not establish that the requested analysis finished.
The profile's completion field describes that profiled call only. Read the
report verdict and `type_check.status` for their own completion and outcome.
