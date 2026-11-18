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

For Python path rules D215, D324 and D325, caller provenance also determines
whether a candidate can be suppressed:

| `metadata.path_provenance.status` | Result |
|---|---|
| `untrusted` | A modeled input reaches the operation; the finding and its chain remain reported. |
| `conditional_http_guard` | For D215, each traced HTTP input goes through a filename check that constrains ordinary decoded strings. Runtime validation and unresolved callers still require review. |
| `safe` | The complete caller analysis proves safe inputs for that particular rule; the candidate is suppressed with its proof. |
| `unknown` | A caller, source, provider or boundary is unresolved; the candidate stays visible as a review item. |
| `incomplete` | An analysis limit or error interrupted the trace; the candidate stays reported. |

The primary Python path list uses positive matches. An unchecked modeled source
reaching a filesystem operation stays on the list. A predictable name in a
shared temporary directory can also establish a symlink alert, even when the
program supplies the name itself. Skylos checks the actual open mode and read
or write effect before applying that rule.

When a complete-project scan traces an operand but cannot establish either
match, the default report places the finding under **Path findings needing
review**. The HTML and Markdown reports link to every such finding with its
file, line, rule and reason. A partial project, missing evidence, an analysis
failure or an independent source-to-sink trace keeps the finding on the
primary list. The trace describes static evidence. Runtime conditions such as
directory permissions can still determine whether a link is exploitable.

JSON retains all rows in `danger`, their original severity, and the per-finding
chains. `issue_summary.path_review_count` counts the separate review list.
An explicitly selected rule or `--all-advice` includes its review candidates
in the primary list. Security gate limits still evaluate the raw findings.

Path provenance and explanation status are separate. A partial explanation
does not refute a finding. A filename sanitizer may protect traversal while
leaving symlink following or an unbounded read possible; safety evidence is
specific to the rule and to the checked value before the operation.

In Python D215 reports, `guarded_http` records the checked HTTP paths and
`input_trust` records the HTTP origin. An unchecked caller takes priority
in the evidence sent to the terminal and Cloud. If a subsequent operation
can reintroduce path separators, the earlier filename check no longer
establishes the shape of the value reaching the filesystem.

Symlink proofs belong to the exact native open operation. A check elsewhere
in the function, a flag name, or a precheck that can race does not suppress
D324 or D325. Native `O_NOFOLLOW` or exclusive creation can establish
final-component write safety; ancestor containment remains a separate check.
Read safety also requires bounded reads through the descriptor that was
opened, with no unresolved handle escape, replacement or premature closure.
Custom openers, changed I/O providers and unresolved flag values do not
inherit native atomic guarantees. An observed read through an exclusive
update handle still receives the read check.

Read and write direction are separate from link protection. Native optional
non-access flags, such as `O_CLOEXEC` with a fallback of zero, can preserve a
proven read-only mode; optional `O_NOFOLLOW` does not prove link protection.
A descriptor used only for proven native metadata, locking or synchronization
operations is not a content read. Actual reads, escaped descriptors, callbacks
and uncertain providers retain the corresponding checks.

Test filenames and unused helpers are not safety proofs. The caller trace can
model native unittest dispatch and the lifetime of a native temporary directory,
but custom workspaces, escaped objects and unresolved callbacks remain reviews.
Likewise, a validated native JSON integer can establish a traversal-safe path
component without establishing symlink or bounded-read safety.

For modeled native Python subprocess launches, a fixed child `sys.argv`
position follows the corresponding parent argument, with separate steps at
the process boundary. An untrusted sibling argument does not taint a literal
argument in a different position. A safe parent value proves safety only when
the child target and runtime context are established. Relative targets can
remain candidates without proving the working directory.

Operator sources in imported modules keep their possible worker contexts
through directed import edges. Importing a shared utility does not join two
otherwise unrelated scripts into one process. Environment, working-directory
and stdin transports are checked separately from argv. Unsupported parser
fields, opaque execution options, provider mutations, dynamic imports and
exhausted context budgets remain explicit reviews or incomplete traces.
These are static models; the analysis never launches the child program.

For SSRF source classification, native argparse construction is insufficient
when actions, type callbacks or defaults can obtain remote data. Only finite
source-proven scalar converters and native operator defaults inherit the
operator-input classification. Unknown callbacks, explicit unproven argv,
provider replacement and escaped parser capabilities remain candidates.
HTTP-to-worker URL transports also retain SSRF findings: a worker's environment
or argv is operator input only when its modeled launch context establishes it.
`metadata.process_context` records known sources and unresolved boundaries and
survives compact uploads with bounded chains.

JSON stores `metadata.security_trace`. The existing semantic `metadata.security_evidence` packet remains unchanged. Located trace fields do not upgrade a finding to verified or refuted. SARIF uses the recorded per-step locations for code flows and keeps the trace in metadata; compact uploads also retain trace and receiver evidence. When the source-resolved walk finds no source but the detector recorded an untrusted chain (`metadata.sql_provenance`, `redirect_provenance` or `path_provenance`), the trace adds that chain as a `source` step and `propagation` steps (edge kind `provenance`) with their file, line and column. Python steps also carry `snippet`, the single source line at their location (at most 240 characters) with every string literal replaced by `<literal>` and comments removed; a step on a line a secret finding flags, or where credential redaction would apply, has no snippet. SARIF puts the snippet in each thread-flow location's `region.snippet`; the compact upload fallback keeps step locations without code and keeps the provenance chains.

The same selected source snapshot, configuration, analyzer/model version and work limits produce the same trace IDs and ordered steps. Limits count files, bytes, AST nodes, callers, depth and steps rather than wall-clock time. Reaching a limit produces a partial explanation and preserves the finding. `analysis_summary.security_trace_coverage` describes explanation availability separately from detector coverage.

The trace records identifiers and relationships rather than embedding literal values or complete source files. Old reports without located traces remain inspectable, but the viewer does not invent missing steps. Rescan to obtain located explanations.


## Repository source passed to Python exec

When Python's native `exec` receives a compiled syntax tree, Skylos follows
the tree back to its source file. A loader that selects project-owned Python
source, compiles it and uses a fresh namespace can receive a
`compiled-project-source` low-risk record. The record names the source files
and the scope of the static check. Runtime integrity remains unverified.
External or mixed inputs, a changed compiler, conflicting source evidence,
or a namespace the analyzer cannot account for keep the alert primary.

The raw security report and strict gate retain low-risk records.
`--all-advice` or explicit selection of `SKY-D202` lists them individually.
