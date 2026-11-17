# Implemented Go fixes

Go now preserves legacy-project package identities and alternate-build definitions, recovers object-bound live test-helper chains despite incomplete package typing, and reports methods on provably unobtainable private test-only receiver types. Security analysis resolves single-definition captured native functions/methods, genuine HTTP request type aliases and assignments disabling verification on native TLS configurations.

Final engine: `/tmp/skylos-review-fixes-20261117-go`, SHA256 `3865e4716c344400c8b1d1e37fe8464d89de6084c70b16cbfd335e525dbdc907`. Original `/tmp/skylos-review-20261117-go` preserved. Tracked Darwin arm64 binary rebuilt to the same final hash, so normal CLI discovery receives the fixes without an override; security test harness also respects an explicit engine override. Packaging/discovery proof is in bundled_binary_provenance.json.

| Frozen source facts | Before | After |
| --- | --- | --- |
| Goji live controls parsed and retained | 13/18, five incomplete | 18/18, zero false positives |
| Three Goji unused test methods | Excluded | Three exact-location true positives |
| Six authored security challenge operations | No corresponding warning | Six expected rules at exact locations |

Goji outputs only `pattern.boolPattern.Match:11`, `pattern.prefixPattern.Match:20` and `pattern.prefixPattern.PathPrefix:23`. All pinned source hashes unchanged. No extra findings were suppressed. `final/comparison.json` and raw outputs preserve every label outcome and both engine hashes. This is development remeasurement after source inspection, not new blind evidence or a whole-repository recall estimate.

The six security operations cover captures of HTTP fetch, HTTP client method, command execution and file reading; native request aliases; and TLS field assignment. Sixteen paired native controls retain fixed hosts/files, ordinary argv data, custom methods, package shadows, custom requests, enabled TLS and shadowed boolean values. Multiply assigned captures remain unresolved.

Test-method proof requires a private receiver type declared once in test source, complete admitted package source, no assembly/export directive and no type-name occurrences outside its declaration/receiver syntax. Constructors, aliases, interface conversions, framework values and ambiguous uses decline this proof. Partial typing proves only live helper use, never unknown helper deadness. Test/source admission boundaries remain intact.

Validation: full native `go test ./...` passed (`native_tests_final.log`); combined Python Go suites **112 passed** (`python_tests_final.log`), including scope, identity, helper, graph, workspace, replacement, security and runner controls. The synthetic security fixtures were copied outside the Skylos repository for the final run to avoid parent-workflow contamination.

Environment matters. The preserved original engine already finds all five graph and four private-helper positives when host SDK source is available through `GOROOT=/tmp/skylos-gap-go/go` and its bin directory on PATH. Those previous misses were environment failures, not new detector improvements. `GOWORK=off` disables workspace fixtures that explicitly require selection. `workspace_environment_proof.json` shows both engines prove all three workspace private dead functions with empty GOWORK. Neither engine was changed to override an explicit workspace disable; use the same SDK and empty/unset GOWORK in canonical before/after runs.

No new unmatched Go findings appeared in the root canonical/challenge summaries inspected. All six standalone security fixtures have unregistered private handlers correctly reported unused in both arms; this is unchanged dead-code evidence, not a new security false positive. The five recovered live controls and three selected dead methods do not establish population accuracy.
