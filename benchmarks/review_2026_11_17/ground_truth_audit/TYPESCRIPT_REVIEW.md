# JavaScript / TypeScript source review and competitor evidence

> This records the initial source-audit phase. Subsequent detector repairs now
> detect both incorrectly retained files, expose RGX/MAP and preserve duplicate
> declaration sites. The corrected TS/JS suite passes38/38, all20 fresh selected
> facts have complete extraction, and166 focused tests pass. See
> [the final repair evidence](fixes_2026_11_17/typescript/FIX_REVIEW.md). Initial
> outputs and ground-truth corrections below remain preserved.

Two genuinely fresh repository snapshots were source-labelled before their first
scanner run. All 23 tracked files, including production code, tests, manifests,
CI and documentation, were inspected. No target source, tests, builds, scripts
or dependency lifecycle scripts were executed. The two projects are related:
Trouter depends on regexparam. They are not an independent random sample.

| Repository | Frozen revision | Tracked files | Source facts |
| --- | --- | ---: | ---: |
| lukeed/regexparam | d05da2631beb7c5620774dae207cb09c7cbf24cc | 11 | 8 used declarations, 1 narrow security negative |
| lukeed/trouter | c5176edd1cd94b439a341c6b009f2f7b3d42d5a6 | 12 | 10 used declarations, 1 narrow security negative |

[SOURCE_LABELS_TYPESCRIPT.json](SOURCE_LABELS_TYPESCRIPT.json) contains file
hashes, exact source evidence and caller-dependent unknowns. The unchanged draft
hash is `98aca5cf07106c98276d48b0575027f1c056dce2836c2545c495bb466ac20cf7`.
The parent independently read both implementations and approved the evidence
before scanning; [freeze receipt](TYPESCRIPT_FREEZE_RECEIPT.json).

No actionable unused production declaration or confirmed application security
vulnerability was established by this review. This does not prove none exist.
There is no positive denominator for fresh-repository recall. Intentional unused
placeholder arguments/destructurings were not called removal opportunities.

## Fresh scans and source adjudication

Skylos retained 16 exactly parsed used declarations and kept both selected
RegExp.exec command-execution negative controls quiet. The RGX and MAP live
variable labels are **incomplete**, because their exact declarations were not
extracted into the output definition map. They earn no true-negative credit.
Both security controls concern command execution only; they do not assert regex
complexity safety. Trouter's control is qualified on the dependency API contract.

Knip 6.45.1 retained the three comparable public exports. Local functions,
local variables and methods are outside this selected export-based comparison.
Its default run also reported all three uvu test files as unused. Source proves
these are intended entrypoints: each package's test script is
`uvu -r esm test`, and the files register callbacks and call `test.run()`.
An external source-justified entry configuration including `test/**/*.js`
removed all three warnings. Both default and configured outputs are preserved.
This is a missing default test-entry convention, not evidence Knip cannot be
configured correctly.

Skylos emitted 11 additional security diagnostics: six correctly identified
unpinned action references, two omitted token-permission settings whose actual
privilege depends on unavailable repository settings, two lifecycle-install
posture warnings, and one Unicode character warning in package metadata. These
are not 11 confirmed exploitable vulnerabilities. The last HIGH warning is an
emoji-associated U+200D in regexparam's ordinary package description; character
presence is real, while no hidden instruction or prompt injection is present.
Treat that presentation as security noise, with the syntax fact preserved.

ESLint 10.15.0 with eslint-plugin-security 4.2.1 and TypeScript parser 8.73.0
scanned every supported tracked file through a trusted external flat config.
No target configuration modules were imported. Its two command-execution
controls stayed quiet. Its 11 additional diagnostics concern dynamic regex
construction, broad object-indexing patterns and test regex shapes. Each is
source-adjudicated as test/read-only-indexing noise or caller-dependent review;
none is promoted into a confirmed application vulnerability.

All 25 emitted Skylos/Knip/ESLint diagnostics are separately adjudicated in
[JAVASCRIPT_POSTSCAN_ADJUDICATION.json](JAVASCRIPT_POSTSCAN_ADJUDICATION.json).
These are post-scan judgments, not retroactively frozen blind labels. Raw
outputs and [fresh scores](FRESH_JAVASCRIPT_RESULTS.json) remain unchanged.

## Existing corpus comparison and its ground-truth problems

All 38 default JS/TS dead-code cases were attempted with normal Knip plugins.
Three asset-only fixtures have no package.json and Knip could not analyze them.
Fifty labels concern imports/local declarations outside the export/file units
matched here. On the remaining 125 legacy labels, raw matching yields:

| Legacy contract result | TP | FP-shaped mismatches | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| Skylos | 63 | 0 | 0 | 62 |
| Knip normal defaults | 62 | 28 | 1 | 34 |

**The 28 are not 28 independently confirmed false positives.** Every mismatch
was inspected against its fixture source and actual consumer evidence. The
source review found six confirmed false-positive labels, two incorrect existing
used labels, one incompatible diagnostic unit, nineteen uncertain retention
contracts, and one genuine Knip miss. See the complete 29-row evidence ledger:
[KNIP_SOURCE_ADJUDICATION.json](KNIP_SOURCE_ADJUDICATION.json).

The important corrections are:

- `javascript-path-join-literal-files`: `tasks/gen.js` constructs paths to
  `tools/input.ts` and `src/bundle.ts`, then passes them into `shared.run`.
  `lib/shared.js` implements `run() {}`. Neither file is loaded or executed
  anywhere in the fixture. The legacy labels call these used, masking two
  Skylos dead-file misses and penalizing Knip's correct warnings.
- `typescript-loaded-import-consumers`: `prepare()` runs locally, while its
  exported binding has no importer. Knip's unused-export warning and Skylos's
  retained-function decision concern different units. Knip exposes
  [ignoreExportsUsedInFile](https://knip.dev/reference/configuration#ignoreexportsusedinfile)
  for this distinction. A blanket symbol-name match creates an artificial FP.
- Exact `tsconfig.include` roots establish compilation inclusion, not runtime
  use. Package `files` establishes shipment, and custom manifest metadata does
  not prove a host invokes an export. Returned command strings require an
  actual caller, argument binding and executor before claiming liveness.
- The fixture using legacy Storybook config/addons names declares Storybook6.4;
  a version-specific loader proof is missing. Its conservative retention
  assertions must not be advertised as confirmed source execution.
- Native `.ios`/`.android` implementations have a real platform resolution
  contract under the fixture's React Native dependency and App import; see
  [React Native's documented selection](https://reactnative.dev/docs/platform-specific-code#platform-specific-extensions).
  The separate web variant requires a proven web resolver configuration.
- The unrelated `leftover` export in `wdio.conf.ts` is unreferenced; the
  framework reads `config`. Knip's entry-export exemption hides this miss.

On **only the nine mismatch-selected facts with enough semantic evidence**, the
corrected outcomes are:

| Reviewed mismatch subset; not population accuracy | TP | FP | FN | TN |
| --- | ---: | ---: | ---: | ---: |
| Skylos | 1 | 0 | 2 | 6 |
| Knip | 2 | 6 | 1 | 0 |

This subset was selected from disagreements, so it cannot estimate overall
precision, recall or rank either tool. The original labels and raw scores are
preserved, not silently overwritten. Other legacy TP/TN labels still need a
full independent semantic review before a corrected full-corpus table exists.

A supplementary plugins-disabled static profile is also saved. Its worse
framework outcomes must not be used as a full-capability competitor headline.

## Existing security comparison

ESLint's recommended security rules scanned all 58 default JS/TS security cases.
The 16 original labels concerning eval and Node command-execution families
produce **TP2 / FP0 / FN7 / TN7**. The installed command rule recognizes dynamic
`child_process.exec`; seven shell-enabled spawn/execFile variants fall outside
its implementation and are misses within this family-level comparison.
Other security families remain unsupported and do not earn negative credit.

This follows the original case-level rule-presence benchmark semantics. It is
not an exact-location or real-world exploit-validation score. Raw diagnostics,
versions, limitations and individual outcomes are in
[ESLINT_SECURITY_COMPARISON.json](ESLINT_SECURITY_COMPARISON.json).

## Changes worth considering

The immediate improvement is benchmark integrity: split semantic live/dead
labels, conservative retention policies, compilation/publication inputs and
unknown dynamic consumers. Each framework claim needs a pinned valid consumer
contract, plus a nearby truly unused control. Correcting labels reveals misses
without suppressing findings or weakening rules.

A conservative future detector improvement could distinguish emoji metadata
from suspicious hidden instruction text for Unicode severity, with malicious
lookalikes retained. The supplied fresh evidence does not justify broad
suppression, nor a claim that changing that rule preserves security recall.
The missing variable declaration extraction should be fixed or explicitly
reported before variable controls can earn passing benchmark credit.

The parent scoring diff was independently reviewed. Exact file/rule/line
matching and zero-F1 correction are sound. Review identified the additional need
to reject nonexistent files and lines beyond EOF in negative labels; the parent
added those checks. The original focused location-scoring tests passed15 before
that extension; the parent's final validation records cover the extension.
