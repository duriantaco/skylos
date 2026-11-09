# Why Dart and C# produced false alerts

> Historical baseline from 8 November 2026. See [REMEASURE.md](REMEASURE.md) for the subsequent fixes and remeasurement; the results below retain their original scopes and limitations.

This is a post-scan source investigation of the snapshot tested in
[REPORT.md](REPORT.md), commit `60f383b1305c1f526ee82cf058b35a199e92c6b9`.
It does not change the frozen labels, scanner output, scoring or detectors.
Implementation causes below are read-only source traces supported by retained
outputs; no fix was executed or measured.

The concentration comes from repeated extraction and binding defects. Parsing
all declared files successfully does not prove correct symbol resolution.

| Emitted false-alert kind | Dart | C# |
| --- | ---: | ---: |
| Imports | 113 | 0 |
| Variables | 48 | 43 |
| Methods/functions | 23 | 5 |
| Classes | 15 | 58 |
| Total dead code | 199 | 106 |

Dart's repository-group total of 203 also includes one Dart `Process.start`
security FP and three JavaScript documentation security FPs. All 106 C# FPs are
dead-code findings. The 92 unused vendored annotation declarations excluded in
the original report are still excluded. Kind counts are disjoint diagnostic
counts, not an assignment of every warning to a single independent root cause.

## Dart: declaration extraction is ahead of use resolution

**Imports are represented by filename-derived names rather than supplied
symbols.** For an unprefixed import, the visitor invents an import definition
such as `equatable_utils`, `collection` or `meta`. Code actually uses names such
as `mapPropsToHashCode`, `sorted` and `immutable`. There is no binding back to
the import that provides them. Shared aggregation collects raw imports for
Python and TS/JS, without equivalent Dart integration. See
[import construction](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/dart/core.py#L243)
and [aggregation](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/analyzer.py#L5117).
Concrete proof: the import at
[equatable.dart:2](https://github.com/felangel/equatable/blob/832990678125b10103b26500ce8ce7188d775925/lib/src/equatable.dart#L2)
is reported unused while that file calls its provided `mapPropsToHashCode` at
line 58. This family deserves first attention: 113 of 199 dead-code FPs are
imports, although a measured fix must still validate each affected identity.

**Exports can become unused imports.** `show` names are emitted as import
definitions for both import and export directives, while the Dart worker
returns empty export sets. Thus
[global_lock.dart:18](https://github.com/tekartik/synchronized.dart/blob/65b41ed7a31344a224431a2b1fd43792b1bc2b53/synchronized/lib/global_lock.dart#L18),
an explicit export of `GlobalLock` and `GlobalLockHandle`, generates unused-import
warnings. See [directive handling](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/dart/core.py#L231)
and [worker result](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/dart/__init__.py#L72).

**Ordinary reads and function values are missed.** The reference walker collects
call syntax, without general identifier-read handling. This misses backing-field
reads, property accesses, annotations, and callbacks passed as values. For
example, `_combine` is passed to `fold` at
[equatable_utils.dart:6](https://github.com/felangel/equatable/blob/832990678125b10103b26500ce8ce7188d775925/lib/src/equatable_utils.dart#L6).
Its recursive calls cannot rescue it because self references are deliberately
excluded. See [reference walker](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/dart/core.py#L506)
and [self-reference exclusion](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/dart/core.py#L159).

**The call graph and reporting counts can disagree.** The retained result for
`MathRNG._generateInternal`, `CryptoRNG._generateInternal` and
`LegacyRNG._generateInternal` records `called_by=["RNG.generate"]` alongside
`references=0`, and reports them unused. The call-graph builder falls back by
simple name while shared reference counting skips ambiguous bare names. See
[graph fallback](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/dart/core.py#L738)
and [reference matching](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/analyzer.py#L3412).
Constructor declarations and references also use different identities:
`Class.Class` versus `Class`.

## C#: incorrect declarations and incomplete language binding

**The field regex misclassifies signature content.** Multiline parameters ending
in commas can match the field pattern. Because their positions precede the
method's opening brace, they can pass the direct-class-member check. Their real
body reads are subsequently excluded as parameter shadowing. See
[field extraction](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/csharp/core.py#L311)
and [shadow exclusion](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/csharp/core.py#L345).
For example,
[smartEnumType:40](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum/SmartEnumNameAttribute.cs#L40)
is checked at lines 46/50 and assigned at line 52, yet appears as a zero-reference
variable. The regex also invents a variable named `CancellationToken` from a
[generic type argument](https://github.com/drewnoakes/figgle/blob/804efc8e65276154ff7d71e2062ecd475ccd4e9f/src/Figgle.Generator/IncrementalGeneratorExtensions.cs#L57).
The 43 variable FPs include this failure family; they are not 43 proven unused
parameters. The dedicated `unused_parameters` arrays are empty.

**Attributes do not receive proper attribute-name resolution.** The collectors
handle calls, `new` and selected type positions, without an attribute-use
collector or omitted-`Attribute` suffix binding. Therefore the actual
[CallerArgumentExpression use](https://github.com/ardalis/GuardClauses/blob/61dde6c9d3e1715286bd100144a9edff1ad0664c/src/GuardClauses/GuardAgainstZeroExtensions.cs#L22)
does not keep `CallerArgumentExpressionAttribute` live. See
[reference collectors](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/csharp/core.py#L541).
The same problem affects used annotation types in the vendored catalog; the
unused catalog entries remain a separate scope category.

**Method groups and generic receiver types lose edges.** Calls require an
opening parenthesis, so passing
[GetAllOptions as a Lazy factory](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum/SmartEnum.cs#L49)
is missed. In
[FormatterCache<T>.Formatter](https://github.com/ardalis/SmartEnum/blob/e06da550950b347f0ee47b1ec370a7416e79b030/src/SmartEnum.MessagePack/SmartEnumNameResolver.cs#L27),
the generic collector records argument `T` without the receiver type
`FormatterCache`. See [generic reference collection](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/csharp/core.py#L691).

**A used member does not consistently preserve its owning type.** Shared C#
resolution credits methods and classes independently, allowing used static or
extension containers to be reported unused. The application policy can likewise
retain `Program.Main` while demoting its containing `Program` class. See
[shared resolution](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/analyzer.py#L3216)
and [application policy](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/visitors/languages/csharp/reachability.py#L224).

There is also a confidence bookkeeping mismatch: C# types are stored under
`csharp:type:<qualified-name>`, while the class-attribute factor looks up the
unencoded owner name. This can omit a confidence adjustment; it does not explain
the incorrect read result or independently fix default-threshold inclusion.

**The enabled grep rescue also lacks C# routing.** `.cs` is absent from language
detection and search globs, so the fallback selects Python strategies. Its local
binding helper attempts Python `ast.parse`, returns no binding after a syntax
error, and the Python source globs exclude `.cs`. This concerns the rescue stage;
the primary C# extractor remains the C# regex implementation. The benchmark
enabled grep verification, and retained C# counters show zero rescues. See
[language detection](https://github.com/duriantaco/skylos/blob/60f383b1305c1f526ee82cf058b35a199e92c6b9/skylos/core/grep_verify_common.py#L311).
Dart is recognized as Dart and does not share this Python-fallback cause.

## What competitors actually did

**This study did not establish better native dead-code precision for either
language.**

| Comparator | Retained execution | What its silence establishes |
| --- | --- | --- |
| Dart analyzer 3.10.9 | All five incomplete, with missing packages/undefined symbols; some package language versions exceeded the available SDK | No clean unused-code result; no correctness credit at these sites |
| Semgrep C# official local configuration | Three complete, two with parse errors; 52 rules: 48 security, one best-practice, three correctness; no dead-code rules | It did not test these unused-code claims |
| Native C# / Roslyn arm | Unavailable; dotnet/Roslyn were absent and target MSBuild/generator execution was excluded | No comparison result |

The relevant native-tool design difference is semantic binding and narrower
claims. Dart documents import checks in terms of the imported names referenced
by a library, and its unused-element diagnostic covers private declarations.
See [unused_import](https://dart.dev/tools/diagnostics/unused_import) and
[unused_element](https://dart.dev/tools/diagnostics/unused_element).
Roslyn exposes symbol and semantic models;
[IDE0051](https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/style-rules/ide0051)
checks unused private members rather than claiming all public library types are
dead. See the [semantic-model documentation](https://learn.microsoft.com/en-us/dotnet/csharp/roslyn-sdk/work-with-semantics).
These official documents explain architecture and scope; they are not measured
precision results for the incomplete/unavailable study arms.

## Fix order and validation

1. Fix Dart import/export ownership, C# false field extraction and C# grep
   routing first.
2. Add ordinary reads, callback/method-group references, generic receiver and
   attribute binding; make live members preserve their owning type.
3. Reconcile call-graph edges, declaration identities and reporting reference
   counts. Represent unresolved binding as uncertainty before claiming dead code.
4. Validate exact finding identities against these now-seen regression cases,
   with real-unused and same-name negative controls. Do not globally preserve
   every import, field or same-named member.
5. Prepare a separate fresh holdout with resolved Dart dependencies, an actual
   Roslyn-based dead-code comparator, and matched private/public capability
   scopes before making competitive accuracy claims.

Raising the confidence threshold alone is insufficient: 137 of Dart's 199
dead-code FPs and 95 of C#'s 106 FPs already carry confidence score 100. Those
are heuristic scores, not calibrated probabilities. Raw sources, indices and
judgments remain in `.skylos/holdout-20261108/postscan-review/` and `runs/`.
Those private receipts are retained locally and are not committed.
