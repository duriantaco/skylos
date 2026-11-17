# Security corpus gap evidence — 17 November 2026

This is the task-start gap review. Challenge failures and detector line
references below describe that earlier snapshot. The [completed repairs and
current results](ground_truth_audit/confirmed_results.md) supersede those failure
statuses; historical run evidence is in the [artifact archive](ARTIFACTS.md).

This audit proves missing labels or unsupported analysis scope. It separately records nine already-failing challenge contracts. It does **not** infer detector failures from corpus omissions. The earlier negative-only repository scans could not establish misses or recall. The subsequent [frozen 73-fact study](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/REVIEWED_GROUND_TRUTH_RESULTS.md) includes one conditional Rust example positive and confirms that miss; its denominator is too small for population recall. Unreviewed findings remain unknown.

Scope: `benchmarks/security/manifest.json` plus `corpus/manifest.json`, with challenge, local null-reset and cloud manifests identified separately. Unit tests are a different evidence layer. [The machine-readable matrix](ARTIFACTS.md) records native source references, exact manifest case IDs/lines, fixture paths and polarity. [The inventory script](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/audit_security_gaps.py) reproduces it statically. Go G IDs are normalized through the real adapter mapping. JS/TS share a detector but remain distinct benchmark source languages. Unit references were inspected, not newly executed for this inventory.

**Scoring provenance correction:** the executed scorer proof and saved before/after results concern the earlier implementation. Concurrent current workspace changes now support structured exact rule/file/line-range labels, validate real source locations, normalize relative paths and correct the zero-precision/zero-recall F1 fallback. This review team did not author those changes. The default manifest still has 290 legacy string expectations, so its remaining sink-identity limit is a **corpus migration gap**. The missing rule polarities below are unchanged; adding scorer support does not supply missing source truth. [Exact source hashes and limits](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/SCORER_CHANGE_PROVENANCE.md).

## Every supported source language

All paths below are repository-relative. Manifest lines refer to `benchmarks/security/manifest.json`; complete per-label fixture paths and references are in the JSON matrix.

| Language | Proven gap or bounded coverage | Exact implementation evidence | Existing unit evidence / interpretation |
| --- | --- | --- | --- |
| Python | D206 only has absent `yaml-safeloader-positional` at manifest:159; no present label | `skylos/rules/danger/calls.py:68` | `test/test_deserialization.py:174` has positive and safe-loader controls. Missing benchmark parity, not missing detection. |
| TypeScript | D211 has four absent labels starting `typescript-server-action-constant-safe` at manifest:1239, no present label. D226 absent from default/shared labels | `skylos/visitors/languages/typescript/danger.py:3655` | Positive SQL unit test at `test/test_ts_danger_release_blockers.py:61`. Local null corpus adds D226 facts separately. |
| JavaScript | No JS-declared case or .js/.jsx/.mjs/.cjs fixture in default security manifest; shared-corpus JS cases have no danger expectations | `skylos/analysis/file_processing.py:102` lists JS/TS extensions and dispatches shared engine | `test/test_ts_innerhtml_values.py:111` has a .js DOM sink test. Benchmark gap does not imply missing JS support. |
| Go | D207/D208/D250 lack default/shared labels. Six positive challenges fail | `skylos/engines/go/internal/analyzer/analyzer.go:314`; canonical mapping `skylos/visitors/languages/go/go.py:23` | `test/test_go_security.py:195` asserts weak-random reporting. Challenges establish only their six named misses. |
| Java | D233 and D236/D237 are implemented but neither polarity appears in default/shared labels | `skylos/visitors/languages/java/flow.py:2193` | `test/test_java_security.py:2385` has deserialization controls. Manifest omission is not a detector defect. |
| PHP | D211/D212/D216 and XSS families implemented but absent from default/shared rule labels | `skylos/visitors/languages/php/danger.py:1844` emits D211 | `test/test_php_security_sinks.py:314` pairs SQL controls; `test/test_php_security.py:123` checks Drupal. |
| Rust | D212 positive `rust-shell-arg-taint` (manifest:1721), negative `rust-shell-literal-command` (:2390); D215 also paired | `skylos/visitors/languages/rust/danger.py:788` | `test/test_rust_security.py:1`. No missing polarity among direct D212/D215 families. The later source-reviewed tiny-http example demonstrates a request-source-model miss ([diagnosis](https://github.com/duriantaco/skylos/blob/ca17bb2e12248bc02893ead2dc957f19cb25baff/benchmarks/review_2026_11_17/TINY_HTTP_POSTSCAN_SECURITY_DIAGNOSTIC.md)); broader web/auth/SQL coverage is not inferred. |
| Ruby | D212 positive shell/string and negative argv/literal labels (manifest:2567 onward) | `skylos/visitors/languages/ruby/security.py:40` explicitly declares supported rule and unsupported families | `test/test_ruby.py:127`. SQL, Rails request flow and interprocedural command flow are explicitly unsupported; native family is paired. |
| Dart | D212/D215/D216 all paired; D216 pair at manifest:1780/1809. Two positive challenges fail | `skylos/visitors/languages/dart/danger.py:163` | `test/test_dart_security.py:49`. No missing native-family polarity. Optional parser absence cannot count as safety. |
| C# | D226/D228 neither polarity in default/shared corpus | `skylos/visitors/languages/csharp/models.py:91` | `test/test_csharp_aspnet_security.py:440` has paired ASP.NET HTML controls. Manifest gap, not absent implementation. |
| C++ | Native adapter returns an empty danger slot; no native SAST labels | `skylos/visitors/languages/cpp/__init__.py:99` | `test/test_cpp_integration.py:23` tests discovery. Generic secrets are separate (`skylos/rules/secrets.py:225`). Empty danger output cannot prove C++ safety. |
| Kotlin | D236/D233/D237/D257/D258 absent from default/shared labels; command-argv challenge is one FP | `skylos/visitors/languages/kotlin/security.py:1234` | `test/test_kotlin.py:425` has XXE unsafe/safe/independent-receiver controls. Do not extrapolate the command FP to those families. |
| Swift | Native adapter returns an empty danger slot; security benchmark allowlist excludes Swift/C++ | `skylos/visitors/languages/swift/__init__.py:30` | `test/test_swift_secrets.py:15` separately tests secrets. Dead-code/secret support is not injection-flow coverage. |
| Shell | D212 only present labels: shell-eval-arg/source-arg/c-flag-arg (manifest:1868 onward) | `skylos/visitors/languages/shell/danger.py:188` | `test/test_shell_privilege_context.py:85` has safe command controls. Presence-only labels cannot measure false positives. |

## Special scopes

- **Terraform/HCL:** `skylos/rules/config/terraform/model.py:236` selects `.tf`/`.tf.json`; generic HCL secret scanning is separate. `benchmarks/cloud/manifest.json:5` contains 22 declaration contracts for D400/D401 with unsafe/safe/unknown/not-applicable outcomes. They are not missing merely because the source-security manifest lacks them. D402–D408 are implemented at `skylos/rules/config/terraform/high_risk.py:24` but have **no labelled cases in that cloud manifest**. `test/test_terraform_aws.py:15` tests frozen D400/D401 outcomes. Unknown/module/unsupported states remain partial (`terraform/scanner.py:75`). TerraGoat holdout facts (`benchmarks/holdouts/manifest.json:76`) describe training-source declarations, not production exposure; unknown/not-applicable earn no safe credit.
- **Standalone SQL:** native dispatch (`skylos/analysis/file_processing.py:578`) and configuration dispatch (`skylos/rules/config/registry.py:119`) contain no standalone `.sql` analyzer. SQL injection checks inspect host-language sinks; they do not establish stored-procedure, schema-privilege or standalone SQL coverage.
- **HTML/components:** native JS/TS extensions (`skylos/analysis/file_processing.py:102`) exclude `.html/.vue/.svelte/.astro`. HTML secrets (`skylos/rules/secrets.py:206`) and script/component references (`skylos/deadcode/browser_refs.py:65`) are separate. Empty findings/reference consumption cannot prove complete inline-script/template security. PHP/Blade has targeted paired tests (`test/test_php_security_sinks.py:298`), not universal markup-engine coverage.
- **YAML/JSON/TOML/Docker/CI:** configuration scanners are registered at `skylos/rules/config/registry.py:10`; these policy scopes must not be pooled with language-level flow claims.

## Evidence limits and next work

Promote reviewed unit positive/negative pairs into exact-location manifests before editing detectors. Add JS-specific source controls and Go hash/random controls; distinguish review-policy warnings from source-proven vulnerabilities. Add D402–D408 cloud contracts with explicit unknown outcomes. Retain the nine challenge expectations while fixing binding/provider/context logic; whole-family or name-based suppression risks recall. Independent repository evaluation needs source-reviewed positive and negative facts plus unknowns frozen before a run. Negative-only checks cannot substantiate recall or general accuracy preservation.

## Observed challenge failures

The saved earlier before/after reports preserve eight missing required findings and one forbidden finding. These are failures of frozen facts, not inferred corpus omissions. No new reproduction or target execution was used.

| Challenge | Rule/polarity | Failure | Manifest line |
| --- | --- | --- | --- |
| `kotlin-command-argv` | `SKY-D212` absent | FP | 5 |
| `go-ssrf-function-alias` | `SKY-D216` present | FN | 32 |
| `go-ssrf-method-alias` | `SKY-D216` present | FN | 58 |
| `go-command-function-alias` | `SKY-D212` present | FN | 84 |
| `go-path-function-alias` | `SKY-D215` present | FN | 110 |
| `go-ssrf-request-alias` | `SKY-D216` present | FN | 136 |
| `go-tls-field-assignment` | `SKY-D210` present | FN | 162 |
| `dart-process-fake-canonicalize` | `SKY-D212` present | FN | 188 |
| `dart-http-fake-canonicalize` | `SKY-D216` present | FN | 214 |

Artifacts: [before](ARTIFACTS.md), [after](ARTIFACTS.md). Those saved default-security runs report 277 passing cases / 150 TP / 140 TN. This neither erases challenge failures nor fills unlabelled families.

## Complete missing-polarity index

Direct native security rule references missing a polarity in **default security + shared corpus** follow. This is not a capability or accuracy denominator: references may include model/guard tables, and shared helpers may add rules not directly named in a language directory. Highlighted examples above were manually checked. JSON unit references are search leads, sometimes in other language tests, not proof of executed paired coverage. Source and fixture locations for every entry are in the JSON matrix.

| Language | Neither polarity | Present missing | Absent missing |
| --- | --- | --- | --- |
| python | `SKY-D200`, `SKY-D202`, `SKY-D203`, `SKY-D204`, `SKY-D213`, `SKY-D218`, `SKY-D227`, `SKY-D228`, `SKY-D233`, `SKY-D234`, `SKY-D235`, `SKY-D240`, `SKY-D241`, `SKY-D242`, `SKY-D244`, `SKY-D252`, `SKY-D261`, `SKY-D262`, `SKY-D263`, `SKY-D264`, `SKY-D265`, `SKY-D267`, `SKY-D282`, `SKY-D283`, `SKY-D324`, `SKY-D325`, `SKY-D326`, `SKY-D327`, `SKY-D344`, `SKY-D346`, `SKY-D347`, `SKY-D348`, `SKY-D349`, `SKY-D355`, `SKY-D356`, `SKY-D358`, `SKY-D359`, `SKY-D378`, `SKY-D379` | `SKY-D206`, `SKY-D217` | `SKY-D231`, `SKY-D232`, `SKY-D345` |
| typescript | `SKY-D202`, `SKY-D207`, `SKY-D208`, `SKY-D215`, `SKY-D226`, `SKY-D228`, `SKY-D238`, `SKY-D245`, `SKY-D246`, `SKY-D247`, `SKY-D248`, `SKY-D250`, `SKY-D251`, `SKY-D270`, `SKY-D271`, `SKY-D327`, `SKY-D510` | `SKY-D211` | — |
| javascript | `SKY-D201`, `SKY-D202`, `SKY-D207`, `SKY-D208`, `SKY-D210`, `SKY-D211`, `SKY-D212`, `SKY-D215`, `SKY-D216`, `SKY-D226`, `SKY-D228`, `SKY-D230`, `SKY-D238`, `SKY-D245`, `SKY-D246`, `SKY-D247`, `SKY-D248`, `SKY-D250`, `SKY-D251`, `SKY-D252`, `SKY-D253`, `SKY-D270`, `SKY-D271`, `SKY-D280`, `SKY-D281`, `SKY-D282`, `SKY-D327`, `SKY-D510` | — | — |
| go | `SKY-D207`, `SKY-D208`, `SKY-D226`, `SKY-D250`, `SKY-G203`, `SKY-G206`, `SKY-G280` | — | — |
| java | `SKY-D203`, `SKY-D208`, `SKY-D233`, `SKY-D236`, `SKY-D237`, `SKY-D250`, `SKY-D252`, `SKY-D254`, `SKY-D349` | — | — |
| php | `SKY-D201`, `SKY-D203`, `SKY-D211`, `SKY-D212`, `SKY-D216`, `SKY-D226`, `SKY-D228`, `SKY-D349` | — | — |
| rust | — | — | — |
| ruby | — | — | — |
| dart | — | — | — |
| csharp | `SKY-D226`, `SKY-D228` | — | — |
| cpp | — | — | — |
| kotlin | `SKY-D203`, `SKY-D233`, `SKY-D236`, `SKY-D237`, `SKY-D257`, `SKY-D258` | — | — |
| swift | — | — | — |
| shell | — | — | `SKY-D212` |

The new null-reset extension remains separate from the default-scope table. Rust/Ruby/Dart have no missing polarity among direct native families: bounded coverage, not security completeness.
