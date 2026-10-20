# Follow a static security trace

Security scans record a bounded, deterministic explanation alongside each finding. Save a report, then inspect its steps:

```bash
skylos src --danger --format json --output report.json
skylos explain report.json --rule SKY-D211
skylos explain report.json --rule SKY-D211 --finding 1 --interactive --root .
```

`--file` and `--line` narrow the finding list. `--finding` selects a 1-based index within that filtered list. `--format json` emits the selected finding and its recorded trace.

The interactive viewer supports:

| Command | What it inspects |
|---|---|
| `next` / `n` | Next recorded step, including steps inside a source-resolved helper |
| `back` / `b` | Previous recorded step |
| `step N` | A specific step or caller branch |
| `parents` | Recorded predecessor steps feeding the selected step |
| `callers` | Recorded call and argument boundaries |
| `source` | Local source around the selected step |
| `quit` / `q` | Exit the viewer |

This follows a saved static explanation. It never starts the application, imports its modules, runs tests, sets runtime breakpoints, or calls an LLM. Skylos's existing `--trace` option is a separate feature that runs pytest to collect dead-code liveness; it is not used here.

Source viewing requires an explicit `--root`. The viewer reads only regular files inside that root, rejects symlink components, and checks the file's recorded SHA-256 before showing code. If source changed after the scan, it asks for a rescan. Source output redacts recognized credentials and terminal controls. Report text cannot choose a source root or execute a navigation command.

## What the steps establish

The trace follows imports, stable assignments, source-resolved calls, argument-to-parameter bindings and return expressions. A step records its kind, location, source digest and predecessor edges. Multiple callers remain separate branches. Conditional guards are recorded as observations, without assuming they are effective sanitizers.

Receiver identity has its own proof. A method named `execute`, `write_text` or `open` does not establish that its object is a database cursor or filesystem path. The resolver tracks source bindings, constructors and import aliases and reports effects separately from identity. An annotation alone does not prove the runtime object. Unknown providers, rebinding, mutation, dynamic dispatch and unsupported inheritance remain unknown.

An exact, unambiguous call location can be traced even when its name is absent from the legacy sink-name list. Calls sharing the reported start remain ambiguous. Source-bound `os` and `shutil` filesystem operations identify their declared path argument rather than treating the module as a path; project-local providers and unresolved lookalikes do not receive that standard-library contract. These additional operand models apply only to the explanation.

Rules exclude a lookalike only when source proof establishes the relevant non-database or non-filesystem effect. Unknown receiver warnings, real unsafe paths, SQL interpolation and interpolated SQL with an additional parameter argument remain detectable. This feature does not lower severity or change gate policy.

The status describes the recorded explanation:

| Status | Meaning |
|---|---|
| `source_to_sink` | A modeled static input path reaches the candidate sink without an unresolved recorded step |
| `partial` | Some steps are known; caller, receiver, provider or analysis scope remains unresolved |
| `unknown` | A source path cannot be established for this candidate |

Even `source_to_sink` does not verify runtime exploitation or complete external callers. Python reflection, runtime imports, plugins, monkeypatching and dependency code unavailable in the selected snapshot can prevent a complete explanation. Non-Python and configuration findings retain a factual location and explicit limits rather than a guessed Python call chain.

## Reports and determinism

JSON stores `metadata.security_trace`. The existing semantic `metadata.security_evidence` packet remains unchanged. Located trace fields do not upgrade a finding to verified or refuted. SARIF uses the recorded per-step locations for code flows and keeps the trace in metadata; compact uploads also retain trace and receiver evidence.

The same selected source snapshot, configuration, analyzer/model version and work limits produce the same trace IDs and ordered steps. Limits count files, bytes, AST nodes, callers, depth and steps rather than wall-clock time. Reaching a limit produces a partial explanation and preserves the finding. `analysis_summary.security_trace_coverage` describes explanation availability separately from detector coverage.

The trace records identifiers and relationships rather than embedding literal values or complete source files. Old reports without located traces remain inspectable, but the viewer does not invent missing steps. Rescan to obtain located explanations.
