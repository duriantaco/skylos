# Fresh repository study — 8 November 2026

> Historical baseline from 8 November 2026. See [REMEASURE.md](REMEASURE.md) for the subsequent fixes and remeasurement; the results below retain their original scopes and limitations.

## Objective and scope

Evaluate five previously unevaluated public repositories for each of Python,
TypeScript, JavaScript, Go, Java, PHP, Rust, Dart, C#, C++, Kotlin, Ruby, Swift,
and Shell: 70 distinct upstream projects. TypeScript and JavaScript are separate
strata. Report dead-code and security results separately, plus analysis and
capability gaps. Quality diagnostics remain a separate category where supported.

“Unseen” means no prior evaluation located in the local benchmark provenance,
regression memory, repository metadata, or cached target origins searched for
this study. It does not mean absent from either model's pretraining. Record
search coverage and rejected overlaps. Exclude forks, mirrors and upstream
families already evaluated. Select repositories before seeing scanner output;
never replace a selected repository because it has difficult or empty results.

## Sequence and leakage controls

1. Inventory earlier evaluated upstreams and available comparison tools. Choose
   five repositories per language using source size, language, license and
   independent project ownership, with reserves for inaccessible, duplicate or
   wrong-language selections. Record all replacements before analysis.
2. Fetch public source only. Pin exact commits, licenses and tracked-file
   SHA-256 inventories. Freeze the Skylos source tree, engine binaries, settings,
   tool versions and comparator configurations before any target scan. Do not
   change detectors during the study.
3. Create source-only review packets and a deterministic candidate inventory.
   Include source, public entrypoint/build metadata and reference context;
   exclude analyzer implementations, scanner outputs, earlier benchmark answers,
   local skills/memory, and the other labeler's answers. Fixed review scopes and
   any size exclusions are declared before labeling. Whole-repository scan
   counts and reviewed-subset accuracy have separate denominators.
4. Codex and the actual Claude CLI independently label the same candidates.
   Claude runs in a fresh session with customizations, memory, tools and MCP
   disabled. Codex labeler agents receive no parent conversation. Both must cite
   source locations and give a liveness/root or source-to-sink explanation.
   Missing context, public API uncertainty and unsupported semantics are unknown,
   never safe by default. Do not invent unused positives or vulnerabilities.
5. Preserve both original label sets, adjudicate disagreements from source,
   record unresolved cases, and seal source, prompt, candidate and label hashes
   with UTC timestamps. Require all 70 packets and both independent reviews to
   be accounted for before opening the scanner phase. No scanner-derived label
   may be added to this frozen initial label set.
6. Run static Skylos and appropriate installed competitors against identical
   pinned scopes. Prefer Vulture/Ruff/Bandit for Python; Knip for TS/JS; native
   static tools where safely available; and an explicitly pinned official
   Semgrep configuration for supported security languages. Shell uses ShellCheck
   when available. Record unavailable or unsupported arms without a score. Do
   not run target tests, lifecycle scripts, plugins, runtime traces or apps.
7. Preserve raw stdout/stderr, commands, exit codes, coverage/errors, normalized
   identities and before/after source hashes. Failed, missing and partial output
   is unscored, never a clean result. Classify findings outside the frozen labels
   separately; subsequent source review is post-scan adjudication and does not
   retroactively become blinded holdout ground truth.
8. Write `REPORT.md` alongside this plan with all 70 repository rows, per-language
   and per-tool TP/FP/FN/TN, unknown and unreviewed counts, extraction/completeness
   gaps, timings and specific next work. Retain machine-readable evidence under
   `.skylos/holdout-20261108/`. Do not commit, push or publish private artifacts.

## Label and scoring contract

Each label records repository/commit, language, file/span, symbol or sink,
category, expected outcome, source evidence, scope and uncertainty. Live labels
require a real extracted definition and source-backed use/root where the tool
exposes extraction; quiet output alone is insufficient proof. Unused labels need
a bounded complete ownership/reference argument. Security labels distinguish
unsafe, safe, conditional and unknown, with specific source/sink behavior.

Score only comparable categories and explicitly reviewed labels. Report
`precision = TP/(TP+FP)` and `recall = TP/(TP+FN)`; zero denominators are N/A.
F1 is zero when both defined precision and recall are zero. A warning outside
the labeled set is unreviewed until adjudicated, not automatically FP. Separate
duplicate warnings, unsupported capabilities, unresolved labels and parse gaps.
Report per-repository and per-language results before aggregate counts; do not
claim whole-repository recall from selected labels or a universal scanner winner.

## Execution status

Plan written before repository selection, source labeling or target scanning.
Claude CLI 2.1.319 is installed; authentication and clean-session availability
are being checked. Any unavailable dependency or identity limitation will be
recorded explicitly rather than substituted silently.

Completion note: the study has now run. The original plan above is retained;
execution outcomes, incomplete/unavailable arms and the separate guard-only
replays are recorded in [REPORT.md](REPORT.md). All 70 independent label pairs
were frozen before the first target batch.
