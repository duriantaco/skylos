# Python source review and competitor reruns

Two fresh repositories were selected before scanning and reviewed from pinned source. No target code, tests, dependency installs, documentation builders, hooks or package scripts were executed. All tracked Python source and Python/docs/CI configuration was read: pyee 17 Python files (3,025 lines) plus seven config files; Blinker seven Python files (1,227 lines) plus eight config files. The [source label inventory](SOURCE_LABELS_PYTHON.json) preserves file hashes, all 346 declaration records and 116 selected facts. File review coverage does not imply exhaustive semantic ground truth.

| Repository | Frozen revision | Source-first facts |
| --- | --- | --- |
| jfhbrook/pyee | be2025fc579a033326157dd41b5ad1f319d7d827 | 74 used, two unknown API members, one safe-deserialization property |
| pallets-eco/blinker | c3364059663df1ddce32799d6b1922af89a345f6 | 36 used, one bounded unused private helper, two security-negative properties |

The parent agent reviewed key callback registrations and the private unused helper before accepting the freeze. Draft/final labels and hashes remain separate. These are nonrandom model-authored labels, reviewed by another model agent, not independent human adjudication. No exploitable security positives were established, so security recall is unmeasured.

## Frozen facts versus fresh scans

| Repository / scanner | Bounded dead-code TP | Frozen used controls retained | Frozen used controls flagged | Unsupported symbol facts |
| --- | ---: | ---: | ---: | ---: |
| pyee / Skylos | no positive labels | 73 | 1 | 0 |
| pyee / Vulture | no positive labels | 73 | 1 | 0 |
| pyee / Ruff F401,F841 | unmeasured | unmeasured | unmeasured | 74 |
| Blinker / Skylos | 1 | 36 | 0 | 0 |
| Blinker / Vulture | 1 | 36 | 0 | 0 |
| Blinker / Ruff F401,F841 | unmeasured | unmeasured | unmeasured | 37 |

Skylos parsed all individually labelled declarations. Its scan included tests/docs (17 and seven Python files), without source errors. Vulture locations on decorators were normalized to the underlying AST declaration; raw locations remain. Ruff F401/F841 does not detect unused functions/classes; quiet output earns no true-negative credit for these facts.

The confirmed fresh dead-code FP is pyee/executor.py:66, `_emit_run._callback`. Its decorator at line65 is `@future.add_done_callback`, registering the callback at definition time. Skylos reports confidence75; Vulture reports the decorator line. A precise improvement requires receiver/provider evidence that the decorator registers a callable. Treating every dotted decorator or every `add_done_callback` spelling as live could hide unregistered helpers and shadowed APIs. Preserve this blind mismatch even if a later development fix resolves it.

The bounded TP is Blinker `Signal._clear_state`, src/blinker/base.py:456. It has no in-repository references, string dispatch or documented public export. The label excludes external private-API consumers and requires review before removal. pyee `Handlers.reset` remains unknown because an external module consumer might use this importable class member.

Both scanners report pickle in local roundtrip tests. These immediately deserialize bytes from serializing locally constructed objects; no attacker-controlled byte source is present. The risky-API policy observation is accurate; an assertion of exploitable untrusted deserialization would be unsupported. Blinker uses an internal assertion rather than an authorization guard.

One frozen pyee security label has a location error: line369 constructs the emitter; `loads(dumps(ee))` is line370. The frozen result is **incomplete**, not a quiet true negative. The original remains immutable; correction is a separately versioned postscan adjudication.

## Every emitted warning retained and triaged

[Full postscan adjudication](PYTHON_POSTSCAN_ADJUDICATION.json) records 312 findings, including warnings outside frozen facts: 44 confirmed FP records across tools, two bounded TP records, 235 assertion-policy observations and explicit policy/test-control/unknown categories. Repeated tool reports are not distinct source defects. Postscan labels do not retroactively improve blind metrics.

Vulture reports 24 Sphinx conf.py attributes across the two repositories; configuration is externally consumed. Event-handler warnings are checked against local registration/emission, while intentionally uncalled descriptor controls remain retained test controls. Bandit emits 235 B101 assertions: test expectations or the reviewed internal invariant, without a demonstrated missing security guard under `-O`.

A fresh Skylos security FP, adjudicated after scanning, is Blinker .github/workflows/tests.yaml:11, SKY-D295. Its `matrix.os` fallback resolves to ubuntu-latest: all finite matrix entries specify only Python versions, with no `os`. A fix must retain warnings for possible self-hosted choices, dynamic includes or unresolved expressions.

Blinker's GITHUB_ENV warning at publish.yaml:17 is a policy observation: SOURCE_DATE_EPOCH comes from `git log --pretty=%ct`, a numeric timestamp without demonstrated newline injection. Missing permissions, unpinned actions, cache use and lax artifact uploads remain declaration-policy observations, not confirmed exploitable vulnerabilities.

## Existing Python development corpus rerun

**These counts use legacy retention labels, some of which source review found invalid or ambiguous. They do not establish source-grounded comparative accuracy; see the 44-label adjudication below.**

Synthetic cases developed with Skylos measure regression contracts, not independent deployment accuracy. Raw reports/full summaries: [original runs](existing_python), [pickle correction](existing_python_corrected), [final pickle/eval correction](existing_python_corrected_v2).

| Suite / scanner | Cases | TP | FP | FN | TN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Dead code / Skylos | 27 | 54 | 0 | 0 | 98 | 100% | 100% |
| Dead code / Vulture | 27 | 49 | 44 | 5 | 54 | 52.69% | 90.74% |
| Dead code / Ruff F401,F841 | 27 | 5 | 1 | 49 | 97 | 83.33% | 9.26% |
| Security / Skylos, legacy rules | 78 | 43 | 0 | 0 | 41 | 100% | 100% |
| Security / Bandit, original mapping | 78 | 10 | 5 | 33 | 36 | 66.67% | 23.26% |
| Security / Bandit, corrected pickle mapping | 78 | 11 | 7 | 32 | 34 | 61.11% | 25.58% |
| Security / Bandit, final pickle/eval mapping | 78 | 12 | 8 | 31 | 33 | 60% | 27.91% |

Ruff whole-symbol recall is outside its selected rule scope and shown only to expose the mismatched denominator. Vulture also has 20 unmatched findings, preserved as unreviewed. Legacy security scoring matches rule IDs without exact sink locations and ignores extra rules; it can credit the wrong site and is not deployment precision.

The original mapping treated B403 imports as deserialization sinks, B302 marshal as pickle.loads, and every B301 call as pickle.load despite covering several APIs. The narrow correction removes import/marshal equivalence and requires exact numbered source and AST column to distinguish `.loads` from `.load`/read_pickle. Ambiguous aliases, unsupported APIs and malformed/unavailable coordinates retain Bandit identity. Corrected scoring exposes one previously lost direct-pickle TP and two safe-rebinding disagreements. The unambiguous B307 builtin-eval identity is also mapped to D201, recovering the direct-eval detection and exposing another stale-alias safe-rebinding warning. B602 at the direct-shell sink is a general shell-use warning (D209), while the fixture expects taint-specific D212; an unmatched rule is not proof that Bandit missed the risky operation. Other scope mismatches remain; no blanket ranking follows.

Final focused mapping tests: [49 passed](python_mapping_final_focused_tests.txt). Broader checks with the matching Go engine: [107 passed](python_mapping_tests_verified.txt). The initial stale-default-engine attempt failed the shared core suite and is separately preserved in python_mapping_tests.txt. Versions/source hashes: [environment](PYTHON_EXECUTION_ENVIRONMENT.json). Commands/return codes/output hashes: [fresh receipts](fresh_python/receipts.json).

## Gaps and safe improvement contracts

- Receiver-proven callback decorators: concurrent.futures, asyncio, Twisted, with shadowed fake-registration siblings. pyee exposes the first.
- Framework-owned config values: Sphinx and analogous config require provider-specific contracts plus ordinary unused-module controls.
- Finite CI expressions: resolve bounded runner fallbacks; retain dynamic/self-hosted alternatives.
- Serialization policy versus vulnerability: local roundtrips require binding, byte-origin and object reconstruction evidence. Never suppress every pickle call or every test directory.
- Competitor matching: distinguish imports/sinks, exact locations, applicability and unknown extras. Broad mapping can hide genuine detections or invent matches.
- Real positive diversity: this fresh Python sample has one bounded private unused helper and no security-positive labels. Additional source-labelled application positives are needed before asserting real-world recall retention.

## Source audit invalidates treating legacy mismatch counts as truth

A subsequent full source review of all 44 Vulture-versus-legacy-used-label mismatches is preserved in [Python legacy-label adjudication](PYTHON_LEGACY_LABEL_ADJUDICATION.json). These are **legacy benchmark outcomes, not 44 independently confirmed false positives**. Only 17 have direct source-supported consumers; another five have explicit framework-entry registration contracts. Eight Django/Alembic facts rely on conventional external loader contracts but omit loader/app configuration. Six registrations have no reachable dispatcher, two parameters are unused required-signature bindings, two fields belong to classes themselves labelled unused, one bare id label merges three owners, and three used labels are invalid on this source.

The clearest invalid facts are:

- `_api_read` in string-named-backend-dispatch: read backends list cli before api, and the dispatcher returns from the first iteration. The API backend is unreachable despite appearing in a table.
- `_flush` in python-unnamed-receiver-methods: the protocol is unused, FileSink does not implement a called stdout flush method, and no code invokes `_flush`.
- `launch` in the same fixture: objects are added to a temporary list which is discarded; neither launch method is invoked.

Consequently the legacy table cannot establish comparative accuracy or confirm Skylos's perfect truth matching. It is retained as a reproducible historical contract with its label flaws exposed. The source audit covers these 44 mismatches, not every other positive/negative label, so recomputing a new whole-suite accuracy score would be unjustified. The fresh frozen sample has separate source facts and retains its callback false positive.
