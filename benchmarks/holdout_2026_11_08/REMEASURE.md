# Dart and C# fixes and remeasurement — 9 November 2026

On the same five repository pins per language, confirmed false-positive
warnings fell from **203 to 5 in the Dart repository group** and **106 to 15
in C#**. All three previously identified true-unused observations remain
reported. Twelve of the removed Dart warnings now explicitly abstain because
their import providers are unresolved; those are uncertainty handling, not
proof of correct binding.

This is a **post-scan regression remeasurement**. These projects were inspected
while developing the fixes and are no longer an unseen holdout. Original
source-first labels, initial scanner runs and prior judgments were preserved.
The historical [report](REPORT.md) and [diagnosis](DART_CSHARP_ANALYSIS.md) retain
their original results. The other twelve language strata were not remeasured
in this change. There is no independent positive denominator for population
recall here, and these results cannot rank scanners by general accuracy.

| Repository and exact pin | FPs before | FPs after | Total abstentions | Retained true-unused |
| --- | ---: | ---: | ---: | ---: |
| [felangel/equatable @ `832990678125`](https://github.com/felangel/equatable/tree/832990678125b10103b26500ce8ce7188d775925) | 8 | 0 | 2 | 0 |
| [tekartik/synchronized.dart @ `65b41ed7a313`](https://github.com/tekartik/synchronized.dart/tree/65b41ed7a31344a224431a2b1fd43792b1bc2b53) | 57 | 1 | 3 | 1 |
| [felangel/mocktail @ `d6a96e15b920`](https://github.com/felangel/mocktail/tree/d6a96e15b9203d33af61083e02e8c40ac07192d6) | 35 | 0 | 5 | 0 |
| [daegalus/dart-uuid @ `bf552fbad09f`](https://github.com/daegalus/dart-uuid/tree/bf552fbad09f15217e098a8082b86bb36c90fe0f) | 87 | 4 | 1 | 1 |
| [jogboms/flutter_offline @ `8062f547c666`](https://github.com/jogboms/flutter_offline/tree/8062f547c66677f14509185a90e5eb5f07fde52f) | 16 | 0 | 5 | 0 |
| [ardalis/GuardClauses @ `61dde6c9d3e1`](https://github.com/ardalis/GuardClauses/tree/61dde6c9d3e1715286bd100144a9edff1ad0664c) | 6 | 0 | 0 | 0 |
| [ardalis/SmartEnum @ `e06da550950b`](https://github.com/ardalis/SmartEnum/tree/e06da550950b347f0ee47b1ec370a7416e79b030) | 18 | 1 | 0 | 0 |
| [Tyrrrz/CliWrap @ `6d1c90bced37`](https://github.com/Tyrrrz/CliWrap/tree/6d1c90bced37aa384d609d2a31f891d8b3c33734) | 13 | 4 | 0 | 0 |
| [drewnoakes/figgle @ `804efc8e6527`](https://github.com/drewnoakes/figgle/tree/804efc8e65276154ff7d71e2062ecd475ccd4e9f) | 15 | 4 | 0 | 1 |
| [WalkerCodeRanger/semver @ `4e10217ce1fd`](https://github.com/WalkerCodeRanger/semver/tree/4e10217ce1fd5d51721ea3ca98cfe6abc0375c36) | 54 | 6 | 0 | 0 |
| Total | **309** | **20** | **16** | **3** |

Dart's group includes auxiliary JavaScript documentation and CI configuration.
Its five remaining FPs comprise one Dart public compatibility class, one Dart
process-launch finding and three JavaScript security findings. Dart dead-code
FPs alone fell **199 → 1**; C#'s fifteen remaining FPs are all dead code.

The accounting for the original 309 false-positive warnings is:

| Final disposition | Dart group | C# | Total |
| --- | ---: | ---: | ---: |
| Actual reference now bound to the declaration | 180 | 48 | 228 |
| Explicit export directive recognized | 6 | 0 | 6 |
| Invalid field declarations no longer invented | 0 | 43 | 43 |
| Explicit abstention, without accuracy credit | 12 | 0 | 12 |
| False positive still reported | 5 | 15 | 20 |
| Total | 203 | 106 | 309 |

The 43 C# extraction corrections are 39 signature parameters, three enum
members and one generic type-argument token that had been mislabeled as
fields. No valid old C# false-positive declaration disappeared from extraction.
All 205 old Dart dead-code declarations remain: 177 exact identities and 28
corrected identities. Dart has sixteen total import abstentions: twelve old
FPs, three old unknowns and one newly abstained import. They retain zero proven
references and an explicit unresolved-provider reason.

All **240** final dead-code/security warnings were accounted for: twenty FPs,
three true-unused observations, one unknown documentation-only import,
eighty-nine unused vendored annotation catalog entries outside the application
actionability scope, and 127 policy/review warnings. Another 127 quality
warnings remain unreviewed. A policy warning is not a confirmed exploitable
vulnerability. The preserved true-unused observations are `devPrint`, the
generated-JavaScript `initializeDeferredHunk`, and C# `SM_KERN`; intentional
retention and generated assets still require human judgment before removal.

**What changed.** Dart now binds imports to the names their libraries provide,
handles exports and parts, ordinary reads and callbacks, and distinguishes
constructors, mixins, extension dispatch and local/imported call identities.
Unresolved external providers produce explicit uncertainty. Test-only export
barrels no longer make every provider declaration live.

C# now excludes signature/type syntax from field extraction and resolves
attribute suffixes, method groups, generic/static receivers and owning types
using namespace, using, alias and receiver context. Source-proven instance
receivers and type/value shadowing remain distinct. Interpolation expressions
count as reads while literal generated code and format text remain data.
C# grep routing no longer falls through to Python strategies, and unbound
text cannot supply native reference proof. Shared confidence bookkeeping now
recognizes the encoded C# owner key. Reporting thresholds and original test
oracles were preserved.

**Concrete source proofs.** The machine-readable
[evidence ledger](REMEASURE_EVIDENCE.json) lists every original FP site with its
pinned source URL, source hash, final disposition and available binding counts.
It also lists every final dead-code/security warning and its review category.
Reference counts describe scanner evidence, including graph propagation; they
are not counts of distinct textual occurrences.
Representative corrections include:

| Declaration/directive | Final evidence | Consumer proof |
| --- | --- | --- |
| [equatable_utils](https://github.com/felangel/equatable/blob/832990678125b10103b26500ce8ce7188d775925/lib/src/equatable.dart#L2) | Import binds supplied mapPropsToHashCode; one proven import reference | [source use](https://github.com/felangel/equatable/blob/832990678125b10103b26500ce8ce7188d775925/lib/src/equatable.dart#L58) |
| [_combine](https://github.com/felangel/equatable/blob/832990678125b10103b26500ce8ce7188d775925/lib/src/equatable_utils.dart#L76) | Callback read now binds; three references | [source use](https://github.com/felangel/equatable/blob/832990678125b10103b26500ce8ce7188d775925/lib/src/equatable_utils.dart#L6) |
| [GlobalLock](https://github.com/tekartik/synchronized.dart/blob/65b41ed7a31344a224431a2b1fd43792b1bc2b53/synchronized/lib/global_lock.dart#L18) | Explicit export retained; zero executable references is not an unused import | Export directive itself |
| [smartEnumType](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum/SmartEnumNameAttribute.cs#L40) | Signature parameter no longer invented as a field | [source use](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum/SmartEnumNameAttribute.cs#L46) |
| [CallerArgumentExpressionAttribute](https://github.com/ardalis/GuardClauses/blob/61dde6c9d3e1715286bd100144a9edff1ad0664c/src/GuardClauses/CompilerFixes/CallerArgumentExpressionAttribute.cs#L10) | Omitted Attribute suffix resolves; 39 references | [source use](https://github.com/ardalis/GuardClauses/blob/61dde6c9d3e1715286bd100144a9edff1ad0664c/src/GuardClauses/GuardAgainstZeroExtensions.cs#L22) |
| [SmartEnum.GetAllOptions](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum/SmartEnum.cs#L70) | Lazy factory method group binds; one reference | [source use](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum/SmartEnum.cs#L49) |
| [FormatterCache](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum.MessagePack/SmartEnumNameResolver.cs#L29) | Generic static receiver keeps its exact nested type; two references | [source use](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum.MessagePack/SmartEnumNameResolver.cs#L27) |

**Native competitors.** We executed native tools rather than interpreting
missing toolchains or empty security scans as unused-code wins.

| Comparator | Measured execution | Result and limits |
| --- | --- | --- |
| Official Dart Analyzer 3.12.2 | Dart 01–04: eleven successful package-root analyses covering 91 unique owned Dart files | Zero diagnostics. Native unused-import/private-element scope does not cover all public API reachability, JavaScript assets or CI security |
| Dart Analyzer, Dart 05 strict original lock | Both package roots attempted with `--enforce-lockfile` | Both dependency resolutions exited 65; no analyzer accuracy result |
| Dart Analyzer, Dart 05 supplementary pubspec-resolved profile | Temporary dependency locks changed; acquired source unchanged | Example completed with zero diagnostics; root analysis timed out after 300.87 seconds. This does not replace the strict profile |
| Microsoft Roslyn 5.0.0.0, static .NET 8 profile | 46 project compilations: fourteen error-free, 32 with compiler errors | Nine native diagnostics; only nineteen of the original 106 Skylos FP sites support category-matched silence in an error-free owning compilation |

Dart analysis used official image
`sha256:5ac89dbcae4327278b257920e2786df0f22c87adc630017266b67cfcceef8348`,
Flutter framework `6b182d2c7585eba26d4edce0f97630effd256c33` and engine
`5a2a6a42cce67f965cf540fcecf616faca624aa1`. Neutral options disabled target
plugins, includes and lints; normal language diagnostics remained enabled.
Dependency acquisition used `pub get --no-precompile`; analysis ran without
network access. Earlier analyzer startup and temporary-lock permission
failures were retained separately and earned no correctness credit.

The Roslyn driver ran IDE0051/0052/0059/0060 and compiler
CS0168/0219/0414/8321 using SDK 8.0.427, runtime/reference pack 8.0.33 and
explicit source/reference/define inputs. Target MSBuild, analyzers and
generators were not executed. Its original 106-site comparison splits into
nineteen supported clean-project sites with no native warning, 58 unsupported
type-declaration sites, ten compiler-error sites, thirteen parameters excluded
by the configured public visibility policy, two signature-contract exclusions
and four nonbinding enum/type-argument tokens. These are disjoint categories.
In particular, selected Roslyn rules do not diagnose general unused classes.

The nine native diagnostics elsewhere are not nine confirmed deletion
opportunities: four GuardClauses extension-receiver parameters serve signature
contracts; one local-function warning has an unresolved compilation profile;
SmartEnum contributes a negative-test constructor contract and an unused
result binding whose initializer/test call must remain; two CliWrap parameters
belong to a source-generated native contract. Their contexts differ from the
Skylos FP cohort.

The useful native design is binding actual symbols within a supported semantic
scope. Skylos implements that principle here with source-based binding and
explicit uncertainty. Native scope descriptions are documented by
[Dart unused_import](https://dart.dev/tools/diagnostics/unused_import),
[Dart unused_element](https://dart.dev/tools/diagnostics/unused_element),
[Roslyn IDE0051](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules/ide0051)
and [IDE0060](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules/ide0060).
Scope documentation is not a measured comparative accuracy score.

**What to tackle next, in order.**

1. Finish C# extension-method receiver/owner binding. Eleven of the fifteen
   remaining C# FPs are extension containers. Require receiver/type/import
   proof and retain same-name and unused-extension controls.
2. Address the other four C# gaps: one callback method group, one nested record
   type, and two generator registration/output contracts. Model registration
   as evidence or uncertainty without executing target generators.
3. Model the documented exported Dart compatibility API, then tighten the
   remaining process-launch and JavaScript sanitizer evidence. The four
   security FPs were measured but their detectors were outside this fix.
4. Resolve external Dart import namespaces and Dart 05's toolchain/lock
   contract. Improve C# target-framework/conditional/generated-declaration
   profiles before treating native silence as negative evidence.
5. Freeze this version and collect a separate fresh, independently labeled
   holdout with genuine unused and unsafe positives, resolved native tools and
   matched capabilities. Use the current ten pins as regression cases.

**Validation and provenance.** Baseline
`60f383b1305c1f526ee82cf058b35a199e92c6b9` was replayed first and reproduced
the original finding identities. Both versions used confidence 60, grep
verification enabled without cache, danger and quality enabled, secrets and
custom rules disabled, generated-file skip policy enabled, and one scanner
job per repository. All ten final scans completed with declared-file coverage
and no analysis-incomplete result. Target applications, tests, plugins,
generators and build scripts were not executed.

**819 focused checks passed** in 101.63 seconds. New controls cover real-unused declarations, same-named
sibling owners, namespace/alias ambiguity, shadowed receivers, import/export
identity, unused extensions, generated string literals and cross-language
grep lookalikes. An independent challenge caught `??`/`??=` interpolation
format text incorrectly treated as a field read; owned valid C# examples were
confirmed against Roslyn, failed before the correction and passed afterward.
Ruff and Git whitespace checks passed. Existing fixture/oracle files were
preserved. The private regression registry was attempted before and after;
pre-existing catalog/input/expectation drift prevented it from executing its
checks, so it is not reported as a pass.

The final receipts verify that all seventy acquired repository snapshots,
12,064 original study artifacts, the installed Python runtime and scanner
controls remained unchanged. The candidate inventory includes all 1,011
runtime files, including newly added modules. The portable ledger records
receipt hashes; raw outputs, intermediate failed candidates and independent
review details remain in the local study archive. Public documents contain
source links and result evidence; private instructions and model prompts are
not included.

Candidate runtime manifest SHA-256: `7e70d5dfc9da04bc51d5ef4820d3c0a3ca67019d9519a102842f1902b517228a`.

Final phase receipt SHA-256: `053bd5b2b1286eb1b4f54903a1f3d9f64166a3c299b895bde8ec865032abd93a`.

Evidence ledger SHA-256: `78198ab616fc0ba81e28aeaee7a9f2bc09527d1b87acc290c6ad1847d9bff9fd`.
