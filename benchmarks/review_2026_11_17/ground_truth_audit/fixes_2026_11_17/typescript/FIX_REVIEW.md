# TS/JS detector repairs — 17 November 2026

The two source-confirmed dead-file misses are now detected. A path constructed
with node:path is no longer treated as a load when its immutable, unexported
value is unused or passed only to a source-proven empty function. The actual
`require(path.join(...))` provider load remains live.

The refutation is narrow. CommonJS provider proof requires one literal export
of empty methods, no opaque dependency effects, no alias escape or mutation,
and stable native path bindings. The shared dependency guard also applies to
local empty functions and unread path values. Default arguments, unknown
providers, shadowing, assignment, escaped paths, eval aliases and other
observable consumers keep conservative retention. No target code is executed.
Independent peer review caught the missing local-function dependency guard;
negative controls now cover both local and external modules patching node:path.

RGX and MAP now have exact definition coverage: module-level `var` declarations
were missed by the TS parser's top-level predicate, while parsed module
variables were excluded from the reporting context. TS/JS variables now appear
in that context; Python variable volume is unchanged. Positive unused-variable
controls continue to report.

A further fresh-repository replay exposed same-file arrow declarations silently
overwriting each other under `file:name` keys. Each parsed TS/JS declaration
site now survives with a unique location key. Existing conservative same-file
name-based references reach all members of that former collision group; this
change makes no claim of lexical disambiguation and adds no cross-file refs.
The outer and two local trouter `noop` declarations are all present, and an
unrelated dead function remains detectable.

## Evidence

- Four regressions failed before the initial changes; the duplicate-site
  regression failed separately, retaining only one of three locations.
- All **166 focused tests pass**, including Node preload and existing TS path,
  template-consumer, actual-loader, mutation, shadowing, default-argument and
  opaque-dependency controls. [Final test log](tests_final_reviewed.log).
- Source-corrected JS/TS benchmark: **38/38 cases, TP98 / FP0 / FN0 / TN95**.
  [Full result](source_corrected_js38.json).
- The preserved old labels yield 37/38 cases and two expected contradictions:
  TP96 / FP2 / FN0 / TN95. Those two old used labels were independently proven
  incorrect, and now produce the correct dead-file warnings.
- Both frozen fresh repositories have complete selected extraction and
  **20/20 retained controls**: regexparam9/9, trouter11/11. Their original frozen
  label hash is unchanged. [Replay](fresh_source_labels_after.json).

The existing broad loader test had the same incorrect no-op stub as the old
corpus. Its intended live-file contract is now backed by a real source consumer:
`shared.run(input, entry)` calls `require(input)` and `require(entry)`. The
source-corrected no-op corpus and paired new no-op tests remain unchanged.

An initial relocated-manifest replay bypassed the harness's normal fixture
isolation and inherited repository context. Its diagnostic JSON and log are
preserved with `diagnostic_nonisolated`/`measure.log` names and earn no benchmark
credit. Authoritative runs stage exact fixture copies beneath their manifest,
restoring normal isolation. Final commands and output are in
[measure.py](measure.py) and [measure_final_reviewed.log](measure_final_reviewed.log).

Parsed-site preservation does not solve every lexical dead-code case. These
measurements establish no lost labels in the tested TS/JS corpus and controls;
they do not prove unchanged accuracy on all repositories. No confidence
threshold or broad framework suppression was relaxed to obtain these results.
