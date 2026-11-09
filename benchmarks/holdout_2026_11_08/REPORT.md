# Fresh repository study — 8 November 2026

> Historical baseline from 8 November 2026. See [REMEASURE.md](REMEASURE.md) for the subsequent fixes and remeasurement; the results below retain their original scopes and limitations.

This study acquired **70 distinct pinned public repositories: five for each of 14 language groups**. TypeScript and JavaScript are separate. Codex and the actual Claude CLI independently reviewed **651 source-selected candidates before the first target scan**. All original responses, source hashes, prompts, disagreements, source-only corrections and the global label seal remain in the local evidence directory.

**Result:** default Skylos emitted 1,019 dead-code/security diagnostics. Source review confirmed **422 false alerts**: **346 from the 50 complete scoped scans**, plus **76 diagnostic-only false alerts from 20 incomplete scans**. These are diagnostic counts, not 422 distinct root causes. Experimental Rust confidence 40 produced **24 additional false alerts**, reported separately. The evaluated snapshot is **60f383b1305c1f526ee82cf058b35a199e92c6b9**, with the exact native/runtime hashes recorded; these numbers are not a claim about another branch or later release.

The remaining default diagnostics were **11 valid unused-code/import/test-naming observations, 482 source-true policy/API review observations, 92 vendored-catalog observations, 11 unresolved warnings, and one duplicate**. The **478 quality diagnostics were not adjudicated** and are excluded from these counts. Policy observations do not establish exploitable vulnerabilities.

Frozen source outcomes: **562 used/retained, 1 unused, 29 safe, 0 unsafe, 59 unknown**. Unknowns do not earn TP/FP/FN/TN. These are selected source facts, not exhaustive labels for every declaration or vulnerability in every repository.

**Recall is not measurable here.** The single genuine unused positive belongs to a Swift file that failed parsing; no unsafe positive was source-proven. The frozen probes measure protected negative controls and extraction coverage. Post-scan source adjudication measures emitted false alerts separately and is never retroactively inserted into the blind label set.

## What the numbers mean

The blind-score columns measure only eligible frozen labels. Every emitted Skylos dead-code/security diagnostic received separate post-scan source review; quality diagnostics remain unreviewed. Confirmed false alerts remain a lower bound where warnings are unresolved or scans are incomplete. Selected-label recall cannot estimate population recall, and a language with no eligible positive labels has **N/A recall**, not 100%.

Failed, partial, unsupported, unresolved-dependency and missing-definition outcomes remain separate. A quiet live label only receives Skylos TN credit when the exact source definition and successful parse are present. Tool categories and capabilities differ: Ruff unused-import/local checks, Knip export/file analysis, native compiler/index checks and Semgrep security rules are not interchangeable whole-program detectors.

## Skylos by language

| Repository language | Repos | Complete scoped scans | Confirmed false diagnostics | Blind dead-code TP / FP / FN / TN | Blind security TP / FP / FN / TN | Unknown / unsupported / unscored labels |
| --- | ---: | ---: | ---: | --- | --- | ---: |
| python | 5 | 5/5 | 1 | 0 / 0 / 0 / 41 | 0 / 0 / 0 / 2 | 9 |
| typescript | 5 | 5/5 | 3 | 0 / 0 / 0 / 20 | 0 / 0 / 0 / 2 | 27 |
| javascript | 5 | 5/5 | 15 | 0 / 0 / 0 / 23 | 0 / 0 / 0 / 6 | 16 |
| go | 5 | 5/5 | 0 | 0 / 0 / 0 / 16 | 0 / 0 / 0 / 3 | 26 |
| java | 5 | 5/5 | 8 | 0 / 0 / 0 / 26 | 0 / 0 / 0 / 0 | 16 |
| php | 5 | 5/5 | 9 | 0 / 0 / 0 / 41 | 0 / 0 / 0 / 0 | 3 |
| rust | 5 | 4/5 | 2 | 0 / 0 / 0 / 27 | 0 / 0 / 0 / 3 | 18 |
| dart | 5 | 5/5 | 203 | 0 / 1 / 0 / 41 | 0 / 0 / 0 / 2 | 3 |
| csharp | 5 | 5/5 | 106 | 0 / 0 / 0 / 40 | 0 / 0 / 0 / 1 | 9 |
| cpp | 5 | 0/5 | 5 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 40 |
| kotlin | 5 | 5/5 | 0 | 0 / 0 / 0 / 40 | 0 / 0 / 0 / 1 | 5 |
| ruby | 5 | 0/5 | 17 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 53 |
| swift | 5 | 1/5 | 0 | 0 / 0 / 0 / 5 | 0 / 0 / 0 / 0 | 41 |
| shell | 5 | 0/5 | 53 | 0 / 0 / 0 / 0 | 0 / 0 / 0 / 0 | 44 |

False-diagnostic counts include individually verified warnings from partial scans; partial scans receive no aggregate accuracy credit. Repository language is the selection stratum: mixed-language source, CI YAML and documentation can emit warnings too. For example, Dart repositories contribute 203 false alerts, of which 200 are Dart source and three are JavaScript documentation assets. All five C++-repository false alerts are CI shell-script warnings, not a demonstrated C++ code precision result.

The Rust confidence-40 arm is reported separately below; it is not folded into the default-confidence result. Blind counts are eligible label outcomes, not unique emitted diagnostics. A complete scan means the declared file/parse/status checks passed; it does not establish complete language semantics.

### False alerts by actual source language

| Actual source category | Confirmed false diagnostics |
| --- | ---: |
| configuration | 16 |
| csharp | 106 |
| dart | 200 |
| java | 5 |
| javascript | 15 |
| php | 9 |
| ruby | 14 |
| shell | 51 |
| shell/zsh | 1 |
| text | 3 |
| typescript | 2 |

Zero observed source-code false alerts in Python, Go, Kotlin, Rust default, Swift or C++ do not prove accuracy: the sample, category scope and incomplete parsing still apply.

## Competitor execution and limits

| Repository language | Comparator | Complete | Incomplete | Unavailable |
| --- | --- | ---: | ---: | ---: |
| cpp | cppcheck | 0 | 5 | 0 |
| csharp | csharp-native | 0 | 0 | 5 |
| csharp | semgrep-csharp | 3 | 2 | 0 |
| dart | dart-analyzer | 0 | 5 | 0 |
| go | semgrep-go | 5 | 0 | 0 |
| go | staticcheck | 0 | 5 | 0 |
| java | pmd | 0 | 0 | 5 |
| java | semgrep-java | 5 | 0 | 0 |
| javascript | knip-static | 4 | 1 | 0 |
| javascript | semgrep-javascript | 5 | 0 | 0 |
| kotlin | detekt | 0 | 0 | 5 |
| kotlin | semgrep-kotlin | 5 | 0 | 0 |
| php | phpstan | 0 | 0 | 5 |
| php | psalm | 0 | 0 | 5 |
| php | semgrep-php | 5 | 0 | 0 |
| python | bandit | 5 | 0 | 0 |
| python | ruff-unused | 5 | 0 | 0 |
| python | semgrep-python | 5 | 0 | 0 |
| python | vulture | 5 | 0 | 0 |
| ruby | semgrep-ruby | 5 | 0 | 0 |
| rust | clippy | 0 | 0 | 5 |
| rust | semgrep-rust | 4 | 1 | 0 |
| shell | semgrep-shell | 3 | 2 | 0 |
| shell | shellcheck | 0 | 5 | 0 |
| swift | periphery | 0 | 5 | 0 |
| swift | semgrep-swift | 3 | 2 | 0 |
| typescript | knip-static | 4 | 1 | 0 |
| typescript | semgrep-typescript | 4 | 1 | 0 |

There were 215 planned arms: 185 executable attempts and 30 unavailable records. Two additional guard-only Python replays preserve the original failures. Competitor comparisons use frozen language-specific scopes/configurations; unavailable or incomplete arms never receive a zero-error score. Local dependency/index/header/macro constraints are not automatically detector failures. Some incomplete arms also expose harness limitations, including a Knip normalization error and Staticcheck check-ID admission; those are not attributed to competitor accuracy.

## Comparable frozen-label scores

| Language | Tool / category | TP | FP | FN | TN | Precision | Recall | F1 | Protected-negative false-alert rate | Unscored / unsupported / unknown labels |
| --- | --- | ---: | ---: | ---: | ---: | --- | --- | --- | --- | ---: |
| cpp | cppcheck / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 40 |
| cpp | skylos-conf60 / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 40 |
| csharp | csharp-native / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| csharp | csharp-native / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 5 |
| csharp | semgrep-csharp / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| csharp | semgrep-csharp / security | 0 | 1 | 0 | 0 | 0.00% | N/A | N/A | 100.00% | 4 |
| csharp | skylos-conf60 / dead_code | 0 | 0 | 0 | 40 | N/A | N/A | N/A | 0.00% | 5 |
| csharp | skylos-conf60 / security | 0 | 0 | 0 | 1 | N/A | N/A | N/A | 0.00% | 4 |
| dart | dart-analyzer / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| dart | dart-analyzer / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 2 |
| dart | skylos-conf60 / dead_code | 0 | 1 | 0 | 41 | 0.00% | N/A | N/A | 2.38% | 3 |
| dart | skylos-conf60 / security | 0 | 0 | 0 | 2 | N/A | N/A | N/A | 0.00% | 0 |
| go | semgrep-go / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 42 |
| go | semgrep-go / security | 0 | 0 | 0 | 3 | N/A | N/A | N/A | 0.00% | 0 |
| go | skylos-conf60 / dead_code | 0 | 0 | 0 | 16 | N/A | N/A | N/A | 0.00% | 26 |
| go | skylos-conf60 / security | 0 | 0 | 0 | 3 | N/A | N/A | N/A | 0.00% | 0 |
| go | staticcheck / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 42 |
| go | staticcheck / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| java | pmd / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 41 |
| java | pmd / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 1 |
| java | semgrep-java / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 41 |
| java | semgrep-java / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 1 |
| java | skylos-conf60 / dead_code | 0 | 0 | 0 | 26 | N/A | N/A | N/A | 0.00% | 15 |
| java | skylos-conf60 / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 1 |
| javascript | knip-static / dead_code | 0 | 0 | 0 | 12 | N/A | N/A | N/A | 0.00% | 27 |
| javascript | knip-static / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 6 |
| javascript | semgrep-javascript / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 39 |
| javascript | semgrep-javascript / security | 0 | 0 | 0 | 6 | N/A | N/A | N/A | 0.00% | 0 |
| javascript | skylos-conf60 / dead_code | 0 | 0 | 0 | 23 | N/A | N/A | N/A | 0.00% | 16 |
| javascript | skylos-conf60 / security | 0 | 0 | 0 | 6 | N/A | N/A | N/A | 0.00% | 0 |
| kotlin | detekt / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| kotlin | detekt / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 1 |
| kotlin | semgrep-kotlin / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| kotlin | semgrep-kotlin / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 1 |
| kotlin | skylos-conf60 / dead_code | 0 | 0 | 0 | 40 | N/A | N/A | N/A | 0.00% | 5 |
| kotlin | skylos-conf60 / security | 0 | 0 | 0 | 1 | N/A | N/A | N/A | 0.00% | 0 |
| php | phpstan / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 44 |
| php | psalm / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 44 |
| php | semgrep-php / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 44 |
| php | skylos-conf60 / dead_code | 0 | 0 | 0 | 41 | N/A | N/A | N/A | 0.00% | 3 |
| python | bandit / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| python | bandit / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 7 |
| python | ruff-unused / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| python | ruff-unused / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 7 |
| python | semgrep-python / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| python | semgrep-python / security | 0 | 0 | 0 | 2 | N/A | N/A | N/A | 0.00% | 5 |
| python | skylos-conf60 / dead_code | 0 | 0 | 0 | 41 | N/A | N/A | N/A | 0.00% | 4 |
| python | skylos-conf60 / security | 0 | 0 | 0 | 2 | N/A | N/A | N/A | 0.00% | 5 |
| python | vulture / dead_code | 0 | 0 | 0 | 45 | N/A | N/A | N/A | 0.00% | 0 |
| python | vulture / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 7 |
| ruby | semgrep-ruby / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| ruby | semgrep-ruby / security | 0 | 0 | 0 | 6 | N/A | N/A | N/A | 0.00% | 2 |
| ruby | skylos-conf60 / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| ruby | skylos-conf60 / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 8 |
| rust | clippy / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| rust | clippy / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| rust | semgrep-rust / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| rust | semgrep-rust / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| rust | skylos-conf60 / dead_code | 0 | 0 | 0 | 27 | N/A | N/A | N/A | 0.00% | 18 |
| rust | skylos-conf60 / security | 0 | 0 | 0 | 3 | N/A | N/A | N/A | 0.00% | 0 |
| rust | skylos-rust-conf40 / dead_code | 0 | 4 | 0 | 23 | 0.00% | N/A | N/A | 14.81% | 18 |
| rust | skylos-rust-conf40 / security | 0 | 0 | 0 | 3 | N/A | N/A | N/A | 0.00% | 0 |
| shell | semgrep-shell / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 41 |
| shell | semgrep-shell / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| shell | shellcheck / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 41 |
| shell | shellcheck / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| shell | skylos-conf60 / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 41 |
| shell | skylos-conf60 / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| swift | periphery / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 43 |
| swift | periphery / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| swift | semgrep-swift / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 43 |
| swift | semgrep-swift / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| swift | skylos-conf60 / dead_code | 0 | 0 | 0 | 5 | N/A | N/A | N/A | 0.00% | 38 |
| swift | skylos-conf60 / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 3 |
| typescript | knip-static / dead_code | 0 | 0 | 0 | 13 | N/A | N/A | N/A | 0.00% | 32 |
| typescript | knip-static / security | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 4 |
| typescript | semgrep-typescript / dead_code | 0 | 0 | 0 | 0 | N/A | N/A | N/A | N/A | 45 |
| typescript | semgrep-typescript / security | 0 | 0 | 0 | 1 | N/A | N/A | N/A | 0.00% | 3 |
| typescript | skylos-conf60 / dead_code | 0 | 0 | 0 | 20 | N/A | N/A | N/A | 0.00% | 25 |
| typescript | skylos-conf60 / security | 0 | 0 | 0 | 2 | N/A | N/A | N/A | 0.00% | 2 |

The blind sampler caught one eligible false alert; the full post-scan audit found 422. The sampler omitted many import/file/constructor/parameter failure sites, so its low false-alert rate is not representative of the whole warning stream. Precision on negative-only probe subsets has no population interpretation. No overall scanner ranking is justified.

At selected false-alert sites, official Semgrep JS rules also flag the alphabet-bounded NanoID HTML sinks; static Knip also flags seven of the same published/test/fixture files. Those are local overlaps, not complete competitor precision measurements. Its configured entry/plugin scope matters, and incomplete/unsupported comparator arms earn no correctness credit. Exact raw/normalized matches and scope qualifications are in `postscan-comparator-contrast.json`.

## All 70 repository receipts

| Language | Repository / exact commit | Skylos default status | Source-confirmed FP | Emitted dead-code/security diagnostics | Unreviewed quality diagnostics | Comparator execution statuses |
| --- | --- | --- | ---: | ---: | ---: | --- |
| python | [tox-dev/pyproject-api@ab35d3ab13](https://github.com/tox-dev/pyproject-api/tree/ab35d3ab1333f0b4033752d1809164abe7ca2fb3) | completed (guard replay) | 0 | 2 | 13 | vulture: completed; ruff-unused: completed; bandit: completed; semgrep-python: completed |
| python | [python-trio/outcome@03ed6218b0](https://github.com/python-trio/outcome/tree/03ed6218b08001877745bb1a9e180c8c5cf7c903) | completed (guard replay) | 0 | 5 | 3 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| python | [tkem/cachetools@1ce79efa55](https://github.com/tkem/cachetools/tree/1ce79efa552d1bdda70d144d401ef9105d999184) | completed | 0 | 14 | 30 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| python | [pypa/pyproject-hooks@184c9f56a8](https://github.com/pypa/pyproject-hooks/tree/184c9f56a87ede1276a5b33f5024204adb792cd2) | completed | 1 | 1 | 7 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| python | [python-humanize/humanize@d16e6352c9](https://github.com/python-humanize/humanize/tree/d16e6352c9785c5ab86de0133222bd22e89b0db2) | completed | 0 | 0 | 28 | bandit: completed; vulture: completed; ruff-unused: completed; semgrep-python: completed |
| typescript | [privatenumber/resolve-pkg-maps@6d78804995](https://github.com/privatenumber/resolve-pkg-maps/tree/6d788049958514dbce52ef2bebc633f0ad336b51) | completed | 0 | 10 | 18 | knip-static: completed; semgrep-typescript: completed |
| typescript | [unjs/defu@82632b66f5](https://github.com/unjs/defu/tree/82632b66f5914e9946edce300e10633a3d5c0cb7) | completed | 1 | 5 | 8 | knip-static: incomplete; semgrep-typescript: completed |
| typescript | [unjs/scule@5bc68048ca](https://github.com/unjs/scule/tree/5bc68048caad7c0e7de35842c83a510e8e1a7c4f) | completed | 0 | 8 | 5 | knip-static: completed; semgrep-typescript: completed |
| typescript | [danielroe/errx@cb8ff401ad](https://github.com/danielroe/errx/tree/cb8ff401ad07e8aa2b1c448a535248a357de5744) | completed | 0 | 1 | 5 | knip-static: completed; semgrep-typescript: incomplete |
| typescript | [unjs/untun@dfd84231c7](https://github.com/unjs/untun/tree/dfd84231c740a514120e4d7c0efd622822908798) | completed | 2 | 7 | 4 | knip-static: completed; semgrep-typescript: completed |
| javascript | [lukeed/uvu@1a47ca1434](https://github.com/lukeed/uvu/tree/1a47ca14347e085330759911fc6c090e584be12f) | completed | 1 | 10 | 54 | knip-static: incomplete; semgrep-javascript: completed |
| javascript | [ai/nanoid@055d1700cc](https://github.com/ai/nanoid/tree/055d1700cc67ac843e3efb5235d806b419ec7b2b) | completed | 7 | 7 | 13 | knip-static: completed; semgrep-javascript: completed |
| javascript | [sindresorhus/yoctocolors@a85b98a90e](https://github.com/sindresorhus/yoctocolors/tree/a85b98a90e5731914567d8c209e7ec45ac2d24e2) | completed | 4 | 10 | 2 | knip-static: completed; semgrep-javascript: completed |
| javascript | [isaacs/once@0fbb41ec58](https://github.com/isaacs/once/tree/0fbb41ec58d13f6f222fdccd03429a892606000b) | completed | 1 | 10 | 2 | knip-static: completed; semgrep-javascript: completed |
| javascript | [sindresorhus/slash@2e8a56bd8b](https://github.com/sindresorhus/slash/tree/2e8a56bd8b2863be09d4fc85283c0e465131a6d3) | completed | 2 | 6 | 2 | knip-static: completed; semgrep-javascript: completed |
| go | [cenkalti/backoff@ce2ae81589](https://github.com/cenkalti/backoff/tree/ce2ae81589e4316be0722e20928b2f9a6d28335a) | completed | 0 | 4 | 7 | staticcheck: incomplete; semgrep-go: completed |
| go | [hashicorp/go-cleanhttp@b0e8488e2f](https://github.com/hashicorp/go-cleanhttp/tree/b0e8488e2fe29dce6a369099f264aa046c27b659) | completed | 0 | 3 | 3 | staticcheck: incomplete; semgrep-go: completed |
| go | [google/go-querystring@854f39986c](https://github.com/google/go-querystring/tree/854f39986c87d97512b6cc5c59ccee17a72b248e) | completed | 0 | 3 | 13 | staticcheck: incomplete; semgrep-go: completed |
| go | [rs/cors@7ca5fe28f7](https://github.com/rs/cors/tree/7ca5fe28f7d56465f559f143e5ee3758f8baf33d) | completed | 0 | 4 | 11 | staticcheck: incomplete; semgrep-go: completed |
| go | [dustin/go-humanize@f5b54ae139](https://github.com/dustin/go-humanize/tree/f5b54ae1392365a578bb43ab728e3fcdc291f0cd) | completed | 0 | 4 | 13 | staticcheck: incomplete; semgrep-go: completed |
| java | [EsotericSoftware/minlog@f032e8c7c5](https://github.com/EsotericSoftware/minlog/tree/f032e8c7c56f8a4b70ec7a9692f47a72e06ec9b4) | completed | 0 | 0 | 2 | pmd: unavailable; semgrep-java: completed |
| java | [kohsuke/wordnet-random-name@91f2497c0c](https://github.com/kohsuke/wordnet-random-name/tree/91f2497c0c98a0400474c484a95cc984981f2521) | completed | 0 | 0 | 2 | pmd: unavailable; semgrep-java: completed |
| java | [jhalterman/typetools@4d3e59a465](https://github.com/jhalterman/typetools/tree/4d3e59a4651170a920309754e70a1fc9a2b9e6d5) | completed | 4 | 4 | 14 | pmd: unavailable; semgrep-java: completed |
| java | [davidmoten/word-wrap@e33d8eed74](https://github.com/davidmoten/word-wrap/tree/e33d8eed74918bf34bd3f79d464b94bb6f18c3c8) | completed | 4 | 7 | 10 | pmd: unavailable; semgrep-java: completed |
| java | [jchambers/java-otp@06c26e8b55](https://github.com/jchambers/java-otp/tree/06c26e8b5586cc4032a08be2021a9a1b129b0492) | completed | 0 | 4 | 2 | pmd: unavailable; semgrep-java: completed |
| php | [clue/stream-filter@a291df9574](https://github.com/clue/stream-filter/tree/a291df95744d459cb35704b10c2db64ec2506b87) | completed | 1 | 6 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [ramsey/collection@1678fd9462](https://github.com/ramsey/collection/tree/1678fd9462f52aa77532479fdf37c3bae47dd8fe) | completed | 0 | 14 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [theseer/tokenizer@52a7b89c4a](https://github.com/theseer/tokenizer/tree/52a7b89c4aa776e5dfbb1ae05d29495d55dbea6e) | completed | 3 | 6 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [paragonie/constant_time_encoding@5efef6e6cb](https://github.com/paragonie/constant_time_encoding/tree/5efef6e6cb43e088ccab7d0c1e2f2ab25b9e8b54) | completed | 5 | 21 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| php | [reactphp/promise@63cde9c050](https://github.com/reactphp/promise/tree/63cde9c050a876ac25d2d2880c0a2a000b26e211) | completed | 0 | 3 | 2 | phpstan: unavailable; psalm: unavailable; semgrep-php: completed |
| rust | [dtolnay/anyhow@87c8571326](https://github.com/dtolnay/anyhow/tree/87c8571326d60b90391d0555c9675b5ac6f044b1) | incomplete | 1 | 12 | 2 | clippy: unavailable; semgrep-rust: incomplete |
| rust | [matklad/once_cell@80fe900b21](https://github.com/matklad/once_cell/tree/80fe900b21f6d76c1a2ed74d3343e8a3a88c46d0) | completed | 0 | 2 | 2 | clippy: unavailable; semgrep-rust: completed |
| rust | [petgraph/fixedbitset@111fb25521](https://github.com/petgraph/fixedbitset/tree/111fb2552130f6f4c06a4a1a2e0de7ea6e28b922) | completed | 0 | 4 | 2 | clippy: unavailable; semgrep-rust: completed |
| rust | [dtolnay/dyn-clone@23fcf09d96](https://github.com/dtolnay/dyn-clone/tree/23fcf09d96222d9f0f11a204ae6193af27362f72) | completed | 1 | 13 | 2 | clippy: unavailable; semgrep-rust: completed |
| rust | [sfackler/rust-fallible-iterator@0b4fdb728e](https://github.com/sfackler/rust-fallible-iterator/tree/0b4fdb728e643c1cbd9ce06868715bbf98f9052a) | completed | 0 | 4 | 2 | clippy: unavailable; semgrep-rust: completed |
| dart | [felangel/equatable@8329906781](https://github.com/felangel/equatable/tree/832990678125b10103b26500ce8ce7188d775925) | completed | 8 | 13 | 2 | dart-analyzer: incomplete |
| dart | [tekartik/synchronized.dart@65b41ed7a3](https://github.com/tekartik/synchronized.dart/tree/65b41ed7a31344a224431a2b1fd43792b1bc2b53) | completed | 57 | 67 | 2 | dart-analyzer: incomplete |
| dart | [felangel/mocktail@d6a96e15b9](https://github.com/felangel/mocktail/tree/d6a96e15b9203d33af61083e02e8c40ac07192d6) | completed | 35 | 46 | 2 | dart-analyzer: incomplete |
| dart | [daegalus/dart-uuid@bf552fbad0](https://github.com/daegalus/dart-uuid/tree/bf552fbad09f15217e098a8082b86bb36c90fe0f) | completed | 87 | 100 | 106 | dart-analyzer: incomplete |
| dart | [jogboms/flutter_offline@8062f547c6](https://github.com/jogboms/flutter_offline/tree/8062f547c66677f14509185a90e5eb5f07fde52f) | completed | 16 | 21 | 2 | dart-analyzer: incomplete |
| csharp | [ardalis/GuardClauses@61dde6c9d3](https://github.com/ardalis/GuardClauses/tree/61dde6c9d3e1715286bd100144a9edff1ad0664c) | completed | 6 | 119 | 2 | csharp-native: unavailable; semgrep-csharp: completed |
| csharp | [ardalis/SmartEnum@e06da55095](https://github.com/ardalis/SmartEnum/tree/e06da550950b347f0ee47b1ec370a7416e79b030) | completed | 18 | 69 | 2 | csharp-native: unavailable; semgrep-csharp: completed |
| csharp | [Tyrrrz/CliWrap@6d1c90bced](https://github.com/Tyrrrz/CliWrap/tree/6d1c90bced37aa384d609d2a31f891d8b3c33734) | completed | 13 | 15 | 2 | csharp-native: unavailable; semgrep-csharp: incomplete |
| csharp | [drewnoakes/figgle@804efc8e65](https://github.com/drewnoakes/figgle/tree/804efc8e65276154ff7d71e2062ecd475ccd4e9f) | completed | 15 | 31 | 5 | csharp-native: unavailable; semgrep-csharp: incomplete |
| csharp | [WalkerCodeRanger/semver@4e10217ce1](https://github.com/WalkerCodeRanger/semver/tree/4e10217ce1fd5d51721ea3ca98cfe6abc0375c36) | completed | 54 | 54 | 2 | csharp-native: unavailable; semgrep-csharp: completed |
| cpp | [jarro2783/cxxopts@7af8aad55e](https://github.com/jarro2783/cxxopts/tree/7af8aad55eddd73715ded20d4478e242424a0bda) | incomplete | 0 | 15 | 4 | cppcheck: incomplete |
| cpp | [Neargye/magic_enum@d7b75f1407](https://github.com/Neargye/magic_enum/tree/d7b75f140707769031519fbe463449614433f285) | incomplete | 5 | 9 | 8 | cppcheck: incomplete |
| cpp | [Tessil/ordered-map@88b7a58f5e](https://github.com/Tessil/ordered-map/tree/88b7a58f5e9be7f87998bbcbdd3865023738ef92) | incomplete | 0 | 2 | 2 | cppcheck: incomplete |
| cpp | [serge-sans-paille/frozen@d53e0a1157](https://github.com/serge-sans-paille/frozen/tree/d53e0a11578d56dc331dc267c2084d52bcdee1d9) | incomplete | 0 | 7 | 2 | cppcheck: incomplete |
| cpp | [nemtrif/utfcpp@b54cc2d4bc](https://github.com/nemtrif/utfcpp/tree/b54cc2d4bc1a76985d383d9b814afa52a5b2ba0a) | incomplete | 0 | 6 | 4 | cppcheck: incomplete |
| kotlin | [michaelbull/kotlin-retry@2f2617e85a](https://github.com/michaelbull/kotlin-retry/tree/2f2617e85a18f5eee317328ba6c4f39e15c8175a) | completed | 0 | 0 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [michaelbull/kotlin-result@aed7438b2b](https://github.com/michaelbull/kotlin-result/tree/aed7438b2bd92adc704b5022e64cddf263e38800) | completed | 0 | 0 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [h0tk3y/better-parse@51557fd3a8](https://github.com/h0tk3y/better-parse/tree/51557fd3a89bddf86adeafe85a9eddc7d870b0ca) | completed | 0 | 11 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [skydoves/WhatIf@a5aa2ae068](https://github.com/skydoves/WhatIf/tree/a5aa2ae0685787c79c7b17b6d5552646095a7383) | completed | 0 | 8 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| kotlin | [jsoizo/kotlin-csv@8b557f2be1](https://github.com/jsoizo/kotlin-csv/tree/8b557f2be10ea89775fd38eb49a7336a26c6f9c1) | completed | 0 | 5 | 2 | detekt: unavailable; semgrep-kotlin: completed |
| ruby | [mperham/connection_pool@17c1eefdac](https://github.com/mperham/connection_pool/tree/17c1eefdacebead60c5ac706b4c1088094e3b86b) | incomplete | 0 | 4 | 2 | semgrep-ruby: completed |
| ruby | [collectiveidea/interactor@c0e0079375](https://github.com/collectiveidea/interactor/tree/c0e0079375e8d447eadcd062d7bb3b550fcb60bb) | incomplete | 1 | 4 | 2 | semgrep-ruby: completed |
| ruby | [laserlemon/figaro@a2d7dcb70c](https://github.com/laserlemon/figaro/tree/a2d7dcb70c1af1e758089b7d529e0089177c5f51) | incomplete | 8 | 11 | 2 | semgrep-ruby: completed |
| ruby | [dry-rb/dry-inflector@65f186bb68](https://github.com/dry-rb/dry-inflector/tree/65f186bb68e5a40be8552dafc203d03cd35223a9) | incomplete | 5 | 9 | 2 | semgrep-ruby: completed |
| ruby | [dry-rb/dry-configurable@54da11fe9c](https://github.com/dry-rb/dry-configurable/tree/54da11fe9c85d8e170cf42be1028c21b07339981) | incomplete | 3 | 8 | 2 | semgrep-ruby: completed |
| swift | [pointfreeco/swift-tagged@6a85175780](https://github.com/pointfreeco/swift-tagged/tree/6a8517578035408b6c14ccba00ee990a1435515c) | incomplete | 0 | 3 | 2 | periphery: incomplete; semgrep-swift: completed |
| swift | [mxcl/Version@3043fcd2a5](https://github.com/mxcl/Version/tree/3043fcd2a50375db76d89ff206a612471833d1c2) | completed | 0 | 11 | 2 | periphery: incomplete; semgrep-swift: completed |
| swift | [apple/swift-numerics@669f618518](https://github.com/apple/swift-numerics/tree/669f6185187f8e1b5857a25c4bbe6c34a3a02b96) | incomplete | 0 | 2 | 2 | periphery: incomplete; semgrep-swift: incomplete |
| swift | [pointfreeco/swift-case-paths@57160303c3](https://github.com/pointfreeco/swift-case-paths/tree/57160303c3954432637a536d503d4c50f42bcaf6) | incomplete | 0 | 9 | 2 | periphery: incomplete; semgrep-swift: completed |
| swift | [pointfreeco/swift-custom-dump@4fb9e7cbb4](https://github.com/pointfreeco/swift-custom-dump/tree/4fb9e7cbb4b8f5a7354005db39447f570d6b3e19) | incomplete | 0 | 10 | 2 | periphery: incomplete; semgrep-swift: incomplete |
| shell | [rcaloras/bash-preexec@5ae4758c36](https://github.com/rcaloras/bash-preexec/tree/5ae4758c36e8391fb3932e6ae68c283489fc813d) | incomplete | 0 | 3 | 2 | shellcheck: incomplete; semgrep-shell: completed |
| shell | [basherpm/basher@7c3d238ce2](https://github.com/basherpm/basher/tree/7c3d238ce263856edbb99fee000613c01ba5712d) | incomplete | 15 | 20 | 2 | shellcheck: incomplete; semgrep-shell: completed |
| shell | [nvm-sh/nvm@4e8758a801](https://github.com/nvm-sh/nvm/tree/4e8758a801eea9479b32a904f31093e410ddaba4) | incomplete | 34 | 101 | 2 | semgrep-shell: incomplete; shellcheck: incomplete |
| shell | [zsh-users/zsh-autosuggestions@85919cd1ff](https://github.com/zsh-users/zsh-autosuggestions/tree/85919cd1ffa7d2d5412f6d3fe437ebdbeeec4fc5) | incomplete | 3 | 7 | 2 | shellcheck: incomplete; semgrep-shell: completed |
| shell | [babarot/enhancd@190d739d59](https://github.com/babarot/enhancd/tree/190d739d597a486a9922363f3c1c4daa792f6cf1) | incomplete | 1 | 5 | 2 | shellcheck: incomplete; semgrep-shell: incomplete |

Emitted counts above come from the retained normalized artifacts, including partial output; they are not zeroed when a scope is incomplete. The post-scan audit cannot measure false negatives. Full finding-by-finding judgments, rule IDs, source references and qualifications are in the corresponding local `postscan-review/<repository-id>.json` files.

## Representative source proof

| Repository group | Pinned source location | Source-review conclusion |
| --- | --- | --- |
| python | [pypa/pyproject-hooks .github/workflows/ci.yml:32](https://github.com/pypa/pyproject-hooks/blob/184c9f56a87ede1276a5b33f5024204adb792cd2/.github/workflows/ci.yml#L32) | Confirmed false alert. The complete local matrix is explicit, with no include override or external expression; the self-hosted possibility is contradicted by source. |
| typescript | [unjs/defu .github/workflows/ci.yml:21](https://github.com/unjs/defu/blob/82632b66f5914e9946edce300e10633a3d5c0cb7/.github/workflows/ci.yml#L21) | Confirmed false alert. Pinned pnpm 10 blocks dependency lifecycle scripts by default; the blanket claim that this installation runs lifecycle scripts is contradicted by the configured manager and manifest. Official versioned semantics: https://pnpm.io/10.x/settings#ignoredepscripts and https://pnpm.io/10.x/settings#onlybuiltdependencies. This does not assert safety of later explicit lint/build/test commands. |
| javascript | [lukeed/uvu parse/index.mjs:10](https://github.com/lukeed/uvu/blob/1a47ca14347e085330759911fc6c090e584be12f/parse/index.mjs#L10) | Confirmed false alert. Published ESM subpath API; absence of an internal caller does not make the exported implementation unused. |
| go | [cenkalti/backoff retry_test.go:728](https://github.com/cenkalti/backoff/blob/ce2ae81589e4316be0722e20928b2f9a6d28335a/retry_test.go#L728) | Frozen retained control; this is source proof, not a claim of complete extraction. `stuckDoneContext` is declared at retry_test.go:721-733, with `Done` returning nil at :726 and `Err` at :728-732. The call sites at retry_test.go:759,762 and :775,777 supply this receiver to `Retry`; :775 constructs it, and :777-779 also supplies `cancelOnStartTimer`. `Retry` calls `context.Cause(ctx)` at retry.go:161,191,200, consuming this context contract. The comment at retry_test.go:718 describes cancellation through `Err`; `cancelOnStartTimer.Start` changes it at :741-743, and :766 and :780 assert `context.Canceled`. The embedded Background context cannot provide that cancellation result. |
| java | [jhalterman/typetools src/main/java/net/jodah/typetools/TypeResolverUtil8.java:5](https://github.com/jhalterman/typetools/blob/4d3e59a4651170a920309754e70a1fc9a2b9e6d5/src/main/java/net/jodah/typetools/TypeResolverUtil8.java#L5) | Confirmed false alert. Source-proven reflective instantiation of a Java-version adapter; missing a syntactic constructor call does not make the class dead. |
| php | [clue/stream-filter src/CallbackFilter.php:10](https://github.com/clue/stream-filter/blob/a291df95744d459cb35704b10c2db64ec2506b87/src/CallbackFilter.php#L10) | Confirmed false alert. String-based PHP stream-filter registration is an actual runtime root, contradicting no references/no entrypoint. |
| rust | [dtolnay/anyhow .github/workflows/ci.yml:36](https://github.com/dtolnay/anyhow/blob/87c8571326d60b90391d0555c9675b5ac6f044b1/.github/workflows/ci.yml#L36) | Confirmed false alert. The expanded variable is bound to a workflow-authored literal; no attacker-controlled or command-derived data enters this env-file write in the shown path. Scan is incomplete; this source adjudication is diagnostic-only and earns no aggregate accuracy credit. |
| dart | [felangel/equatable lib/src/equatable_utils.dart:76](https://github.com/felangel/equatable/blob/832990678125b10103b26500ce8ce7188d775925/lib/src/equatable_utils.dart#L76) | Confirmed false alert. Actual callback reference and calls. |
| csharp | [ardalis/GuardClauses src/GuardClauses/CompilerFixes/CallerArgumentExpressionAttribute.cs:10](https://github.com/ardalis/GuardClauses/blob/61dde6c9d3e1715286bd100144a9edff1ad0664c/src/GuardClauses/CompilerFixes/CallerArgumentExpressionAttribute.cs#L10) | Confirmed false alert. Actual attribute-suffix resolution uses this compatibility type for the supported older targets; it preserves caller-expression metadata. |
| cpp | [Neargye/magic_enum .github/actions/timed-run/macos-diagnostics.sh:8](https://github.com/Neargye/magic_enum/blob/d7b75f140707769031519fbe463449614433f285/.github/actions/timed-run/macos-diagnostics.sh#L8) | Confirmed false alert. Actual repository invocation roots use trusted runner temp plus fixed phase names, contradicting a user-controlled path in these paths. A future caller supplying an untrusted phase would require separate review; quotes alone are not treated as traversal validation. Scan is incomplete; this source adjudication is diagnostic-only and earns no aggregate accuracy credit. |
| kotlin | [michaelbull/kotlin-retry kotlin-retry/src/commonTest/kotlin/com/github/michaelbull/retry/RetryTest.kt:72](https://github.com/michaelbull/kotlin-retry/blob/2f2617e85a18f5eee317328ba6c4f39e15c8175a/kotlin-retry/src/commonTest/kotlin/com/github/michaelbull/retry/RetryTest.kt#L72) | Frozen retained control; this is source proof, not a claim of complete extraction. `RetryTest` declares the method at RetryTest.kt:72 and registers it with `@Test` at :71 (the `kotlin.test.Test` import is at :15). The test framework is the root: kotlin-retry/build.gradle.kts:2 applies kotlin-conventions, and buildSrc/src/main/kotlin/kotlin-conventions.gradle.kts:56-70 configures the test source set/framework, including kotlin("test") at :56-60. |
| ruby | [collectiveidea/interactor lib/interactor/error.rb:26](https://github.com/collectiveidea/interactor/blob/c0e0079375e8d447eadcd062d7bb3b550fcb60bb/lib/interactor/error.rb#L26) | Confirmed false alert. Concrete constructor and exception path prove use of the reported owner and initializer; this is not a same-name match. Original scan is incomplete; this source verdict is diagnostic-only and earns no metric credit. |
| swift | [pointfreeco/swift-tagged Sources/Tagged/Tagged.swift:227](https://github.com/pointfreeco/swift-tagged/blob/6a8517578035408b6c14ccba00ee990a1435515c/Sources/Tagged/Tagged.swift#L227) | Frozen retained control; this is source proof, not a claim of complete extraction. Sources/Tagged/Tagged.swift:226-229 declares the public conditional conformance `extension Tagged: Strideable where RawValue: Strideable`; :227 implements its required `distance(to:)` witness, paired with `advanced(by:)` at :231. Package.swift:9 exports the Tagged library product, so this conformance is an API contract. The call at Tagged.swift:228 targets `rawValue.distance(to:)`, rather than this method, and is not counted as a caller. |
| shell | [basherpm/basher tests/lib/commands.bash:2](https://github.com/basherpm/basher/blob/7c3d238ce263856edbb99fee000613c01ba5712d/tests/lib/commands.bash#L2) | Confirmed false alert. The claimed user-controlled input is contradicted by the closed test callers and harness-owned fixture roots. This does not claim these generic helpers would validate arbitrary external inputs; no tests or fixture commands were executed. Original scan is incomplete; diagnostic-only verdict with no metric credit. |

These examples are post-scan warning judgments where an FP exists, and pre-scan retained controls otherwise. The full frozen label inventory and all emitted-warning reviews remain separate. Rust confidence-40 false alerts include compile-time assertion and object-safety carriers retained by the source-only adjudicator.

## What needs work next

1. **Dart reference and ownership analysis:** 200 source-level false alerts in the Dart files themselves. Preserve cross-file import/part relationships, constructors, overrides, getters/setters and actual receiver/parameter reads. Add the source-proven cases with same-name and genuinely unused negative controls before changing rules.
2. **C# symbol/ref binding:** 106 source-level false alerts. Fix attribute-name suffix binding, method-group lazy factories, nested generic cache consumers, extension members and actual parameter/constructor reads. Keep the 92 unused vendored annotation-catalog declarations separate from actionable application findings.
3. **Grammar and file admission:** all five C++ scopes were incomplete (four with parse errors; the header-only fifth lacks attested worker scope). Four Swift projects have parse failures. All Ruby scopes omit Gemfile/Rakefile/gemspec code; Shell scopes omit extensionless/dialect sources. These failures prevent whole-scope scoring even when individual findings can be reviewed.
4. **Shell syntax and operand semantics:** quoted arrows/JSON text are not redirections; `curl -V` has no URL. Preserve literal caller/temp-root/path guards, and treat intentional operator/API execution observations separately from proven injection.
5. **Framework and package roots:** preserve registered PHP stream-filter classes, Ruby constructors/prepended initializers, Java reflectively instantiated classes, ESM/CDN entrypoints and runner/type-test files using actual registration/export evidence.
6. **Shared CI and input context:** resolve finite hosted-runner matrices; account for pinned pnpm defaults and actual root build allowances; distinguish JSON metadata reads, fiction/test text and public alphabets from executable code, agent instructions or credentials.
7. **Benchmark evidence:** retain these 70 projects as a versioned regression set after fixing issues. Build a separate source-first holdout with real unused and unsafe positives, native dependency/toolchain closure and broader source candidate kinds. These already inspected repositories cannot become a new unseen score after tuning.

## Definition-coverage proof

The independent extraction audit checked all 562 frozen retained/live labels. It found 373 strict exact identities; 189 strict nonmatches split into **28 coordinate/symbol/kind mapping gaps, 132 intentional scope omissions, 18 parse/unread cases, and 11 observed missing declarations** (two Dart and nine Ruby). Missing abstract/DSL declarations are capability limits, not automatically actionable bugs. Mapping gaps receive no retroactive TN credit. Source excerpts, per-language counts and case evidence are in `extraction-gap-review.json` and `extraction-gap-cases/`.

| Language | Retained controls | Exact extracted identities | Mapping gaps | Deliberate scope omissions | Parse/unread | Absent declarations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| python | 45 | 41 | 4 | 0 | 0 | 0 |
| typescript | 45 | 20 | 8 | 17 | 0 | 0 |
| javascript | 38 | 23 | 0 | 15 | 0 | 0 |
| go | 42 | 16 | 0 | 26 | 0 | 0 |
| java | 36 | 26 | 0 | 10 | 0 | 0 |
| php | 41 | 41 | 0 | 0 | 0 | 0 |
| rust | 37 | 33 | 0 | 3 | 1 | 0 |
| dart | 44 | 42 | 0 | 0 | 0 | 2 |
| csharp | 45 | 40 | 3 | 2 | 0 | 0 |
| cpp | 26 | 2 | 0 | 20 | 4 | 0 |
| kotlin | 42 | 40 | 2 | 0 | 0 | 0 |
| ruby | 43 | 34 | 0 | 0 | 0 | 9 |
| swift | 39 | 15 | 11 | 0 | 13 | 0 |
| shell | 39 | 0 | 0 | 39 | 0 | 0 |

Extraction is per declaration; whole-scope incompleteness still prevents aggregate accuracy credit. The two Python import-probe repairs affect status only. Shell has no dead-code definition arm in this snapshot, so its 39 retained declaration controls are outside that capability.

## Guard-only repair and immutable history

Two original Python runs were marked incomplete when network isolation blocked a trusted urllib3 import-time IPv6 probe. The probe caught that PermissionError and the scanner completed, so this was a harness classification artifact. A separate pinned wrapper recognizes only the exact trusted file/code-object and loopback capability-probe call, **still blocks the bind and all networking**, and records it separately. Seven owned-fixture controls passed, including wrong callers/forged code, IPv4/Unix binds, connect and DNS blocking. The two replays have identical diagnostic identities and messages; source, labels, detector code and settings are unchanged. Both original failures and both full phase seals remain recorded. `combined-scores.json` explicitly links the replacements; `scores.json` retains the original phase.

## Concrete frozen-label disagreements with scanners

- **rust-02 / skylos-rust-conf40 / FP**: `src/race.rs:347` `_dummy` (dead_code). Expected `used`. Exact source proof is in the frozen adjudicated label; matching diagnostic indexes are retained in `scores.json`.
- **rust-02 / skylos-rust-conf40 / FP**: `src/lib.rs:1418` `_dummy` (dead_code). Expected `used`. Exact source proof is in the frozen adjudicated label; matching diagnostic indexes are retained in `scores.json`.
- **rust-02 / skylos-rust-conf40 / FP**: `src/race.rs:497` `_dummy` (dead_code). Expected `used`. Exact source proof is in the frozen adjudicated label; matching diagnostic indexes are retained in `scores.json`.
- **rust-05 / skylos-rust-conf40 / FP**: `src/lib.rs:2728` `_is_object_safe` (dead_code). Expected `used`. Exact source proof is in the frozen adjudicated label; matching diagnostic indexes are retained in `scores.json`.
- **dart-01 / skylos-conf60 / FP**: `lib/src/equatable_utils.dart:76` `_combine` (dead_code). Expected `used`. Exact source proof is in the frozen adjudicated label; matching diagnostic indexes are retained in `scores.json`.
- **csharp-05 / semgrep-csharp / FP**: `Semver.Test/SemVersionTests.cs:191` `BinaryFormatter` (security). Expected `safe`. Exact source proof is in the frozen adjudicated label; matching diagnostic indexes are retained in `scores.json`.

## Analysis and capability gaps

- **typescript-02 / knip-static**: output normalization/coverage incomplete: TypeError: 'list' object is not a mapping; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **typescript-04 / semgrep-typescript**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **javascript-01 / knip-static**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **go-01 / staticcheck**: tool reported analysis/parse/coverage errors; Staticcheck output contains an unadvertised check id; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **go-03 / staticcheck**: Staticcheck stderr requires package-loader completeness review; Staticcheck exited1 without valid finding records; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **go-02 / staticcheck**: tool reported analysis/parse/coverage errors; Staticcheck output contains an unadvertised check id; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **go-04 / staticcheck**: tool reported analysis/parse/coverage errors; Staticcheck output contains an unadvertised check id; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **go-05 / staticcheck**: tool reported analysis/parse/coverage errors; Staticcheck output contains an unadvertised check id; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **rust-01 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **rust-01 / skylos-rust-conf40**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **rust-01 / semgrep-rust**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **dart-01 / dart-analyzer**: trusted metadata preparation reports unresolved language/package scope; tool reported analysis/parse/coverage errors; Dart exited3; missing priority diagnostics or analyzer errors prevent completeness; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **dart-02 / dart-analyzer**: trusted metadata preparation reports unresolved language/package scope; tool reported analysis/parse/coverage errors; Dart exited3; missing priority diagnostics or analyzer errors prevent completeness; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **dart-03 / dart-analyzer**: trusted metadata preparation reports unresolved language/package scope; tool reported analysis/parse/coverage errors; Dart exited3; missing priority diagnostics or analyzer errors prevent completeness; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **dart-04 / dart-analyzer**: tool reported analysis/parse/coverage errors; Dart exited3; missing priority diagnostics or analyzer errors prevent completeness; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **dart-05 / dart-analyzer**: tool reported analysis/parse/coverage errors; Dart exited3; missing priority diagnostics or analyzer errors prevent completeness; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **csharp-03 / semgrep-csharp**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **csharp-04 / semgrep-csharp**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-01 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-02 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-03 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-01 / cppcheck**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: ParseError: no element found: line 2086, column 0; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-02 / cppcheck**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: ParseError: no element found: line 195, column 0; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-03 / cppcheck**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: ParseError: no element found: line 1114, column 0; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-04 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-05 / cppcheck**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-05 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **cpp-04 / cppcheck**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **ruby-01 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **ruby-02 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **ruby-03 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **ruby-04 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **ruby-05 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-01 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-01 / periphery**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: JSONDecodeError: Expecting value: line 1 column 1 (char 0); ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-02 / periphery**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: JSONDecodeError: Expecting value: line 1 column 1 (char 0); ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-03 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-03 / periphery**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: JSONDecodeError: Expecting value: line 1 column 1 (char 0); ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-03 / semgrep-swift**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-04 / periphery**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: JSONDecodeError: Expecting value: line 1 column 1 (char 0); ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-04 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-05 / skylos-conf60**: tool reported analysis/parse/coverage errors; Skylos counters report incomplete analysis; predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-05 / periphery**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: JSONDecodeError: Expecting value: line 1 column 1 (char 0); ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-01 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-01 / shellcheck**: predeclared label/source scope absent from explicit native tool inputs; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-02 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **swift-05 / semgrep-swift**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-02 / shellcheck**: tool reported analysis/parse/coverage errors; predeclared label/source scope absent from explicit native tool inputs; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-03 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-03 / semgrep-shell**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-04 / skylos-conf60**: Skylos Ruby security coverage reports unresolved/partial semantics; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-04 / shellcheck**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-05 / skylos-conf60**: predeclared source files lack successful worker coverage; reviewed labels need per-file qualification; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-05 / shellcheck**: tool reported analysis/parse/coverage errors; predeclared label/source scope absent from explicit native tool inputs; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-05 / semgrep-shell**: tool reported analysis/parse/coverage errors; ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.
- **shell-03 / shellcheck**: tool failed, timed out, or returned an unexpected exit code; output normalization/coverage incomplete: JSONDecodeError: Expecting value: line 1 column 1 (char 0); ValueError: arm did not complete scorable analysis. No aggregate accuracy credit.

## Execution timing

The original tool phase ran from `2026-11-08T13:25:06.095969Z` to `2026-11-08T14:23:22.674095Z`: **58.28 minutes wall time**. Its 185 executable arms accumulated 155.84 minutes of recorded arm time, with overlapping workers. The 70 original default Skylos attempts had median 43.40s and range 10.58–164.55s. This includes incomplete attempts and excludes acquisition, tool setup, labeling, post-scan review and the two separately recorded replays. Per-arm commands, exit status, elapsed time and raw stderr are retained in the phase receipts; differing scopes and native preparation prevent a speed ranking.

## Leakage controls, provenance and reproducibility

- “Unseen” means absent from the searched local evaluation records, identity mentions and cached origins. It is not a claim about either model’s pretraining. Conservative identity exclusions, aliases, fork-family checks and searched locations are recorded in `novelty-denylist.json`; all selected revisions and licenses are recorded before labeling.
- Claude used fresh tools-disabled sessions with safe mode, no customizations, no MCP, no session persistence and a source-only rubric. Codex labelers used fresh contexts without the parent conversation and were instructed to read only their source packets/acquired source, never peer answers or scanner output. The source adjudicator saw both original reviews only after completion and before scanning.
- Source-only review corrections preserve original artifacts/receipts or provisional-consensus history. No scanner-derived change may enter the frozen label set. Unresolved model disagreements remain unknown. Syntax-sampled non-declarations and compile-time-only contracts are not automatically deletion positives.
- Claude execution receipts identify models `claude-opus-5-5`. Every one of the 70 independent calls completed with input hashes matching the sealed packets. The global gate was sealed at `2026-11-08T13:22:55.794069Z`, before the first target batch began at `2026-11-08T13:25:06.095969Z`. Its SHA-256 is `cb90499186c07980a82030fce668b79fe5ac53e3e70d06a7238b4394140cc72c`.
- Skylos source is pinned to `60f383b1305c1f526ee82cf058b35a199e92c6b9`; engine and tool/runtime hashes are in `engine-frozen-v2.json`. The unchanged per-arm runner uses isolated tracked-file mirrors and trusted non-executable configurations. Target tests, package lifecycle scripts, applications, `Package.swift`, Cargo build scripts and runtime tracing are not executed.
- The batch driver validates all 70 source/label pairs and the complete tool/runtime seal before and after the phase, plus per-arm source/mirror checks. Final output hashes bind each result to the unique phase. A changed seal invalidates the batch. Raw failures and unavailable arms are preserved.
- Tool versions, official rule pack provenance, checksums, supported scopes and native runtime setup are in `tools/tools-manifest.json` and `tools/tools-manifest-v2-addendum.json`. Swift indexing remains bounded; missing native modules/macros and C++ headers or Dart dependencies are explicit gaps.

Raw private receipts, source inventories, label seals and detailed adjudications are retained locally and are not committed. Private prompts and raw model responses are omitted from these public documents.

Local artifact references elsewhere in this report identify retained evidence, not files included in the public repository.

Reproduction uses the frozen local inputs and a new output phase; original raw evidence must not be overwritten. During the original study, no product detector, source fixture or old regression expectation was changed, and no commit, push or publication was performed.
