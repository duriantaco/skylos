# Research Dead-Code Engine

This package is intentionally isolated from the default Skylos CLI path.

The first goal is not to replace production behavior. The first goal is to make
research claims measurable:

- emit normalized roots;
- record evidence per symbol;
- classify candidates as alive, likely_dead, validated_dead, or uncertain;
- support ablations for each evidence source;
- produce artifacts that can be scored independently.

Product integration happens only after the research method beats Skylos-current
on frozen and holdout evaluations.

## Current Seed

The current seed includes:

- an evidence ledger;
- normalized root models;
- AST-based root inference for routes, CLI commands, tasks, tests, validators,
  serializers, plugin hooks, imperative route registration, and pyproject
  scripts;
- conservative Python reachability from inferred roots through same-module and
  explicit-import call edges;
- a JSON ablation exporter for root-only, root-plus-reachability,
  top-level-execution, factory-return-summary, conservative-reporting,
  general-action-reporting, and reference-safe-reporting variants;
- a JSON manifest scorer that reports TP/FP/FN/TN deltas per variant, using
  dead-code predictions as the positive class and reporting unlabeled dead-code
  predictions as `extra`;
- a benchmark adapter that evaluates the current Python
  class/function/method/variable subset of the independent dead-code benchmark
  and retains raw/scored outputs;
- development-scale runtime recording for retained benchmark runs.

The current final comparison variant is `v7-reference-safe-reporting`.  It keeps
the V6 evidence model but abstains on standalone deletion actions when the
symbol is still involved in unresolved value flow, method-object references,
unknown attribute references, or dependency edges from another dead candidate.
Those abstentions are reported explicitly and should be read as action-yield
tradeoffs, not as proof that the symbol is live.

The next research step is to freeze a larger repository-scale holdout before
making further method changes, then expand the method beyond the current Python
class/function/method/variable subset with imports, exports, files, and broader
dynamic registration recovery.
