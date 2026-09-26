# Benchmark: Skylos vs Semgrep CE vs Bandit on Agent-Written Code

This page describes `benchmarks/agent-pr-bench`, a reproducible comparison of
static analyzers on code changes written by coding agents. It reports what each
tool found, what it missed, and how it behaved when it could not analyze a file.
All numbers on this page come from `benchmarks/agent-pr-bench/results/`, which
`bench.py score` generates from the tools' actual output plus the checked-in
labels.

**Conflict of interest.** The benchmark was built and labeled by the Skylos
project (an AI agent working in the Skylos repository). The corpus, the
defect categories and the labels were written by the same party that develops
one of the tools. Read the [threats to validity](#threats-to-validity) before
using any number here.

## Results at a glance (before 3.8)

The numbers in this section and in [Results](#results) are from the original
run, before the plan 3.8 fixes to Skylos. They are kept unchanged for
comparison. See [Skylos after plan 3.8b](#skylos-after-plan-38b-false-positive-fixes)
for the re-run.

Run on 2026-09-25 with Skylos 4.39.1 (source), Semgrep CE 1.178.0 and
Bandit 1.9.4. SonarQube was not run (no server; see [SonarQube](#sonarqube)).

| | Skylos | Semgrep CE | Bandit |
|---|---|---|---|
| Seeded recall, all 58 defects | 31 (0.53) | 18 (0.31) | 10 (0.17) |
| Seeded recall, 37 security defects (injection, insecure config, secrets, auth removal) | 19 (0.51) | 18 (0.49) | 10 (0.27) |
| Seeded recall, injection only (17) | 10 (0.59) | 13 (0.76) | 5 (0.29) |
| Seeded precision (in-scope findings) | 51/67 (0.76) | 28/30 (0.93) | 15/22 (0.68) |
| Findings on 7 clean controls | 3 (1 tp) | 0 | 6 (0 tp) |
| Real commits: findings / changed kLOC | 28.2 | 0.62 | 22.6 |
| Real commits: precision | 19/182 (0.10) | 0/4 (0.00) | 4/146 (0.03) |
| Real commits: median / max wall time | 30.5 s / 399.7 s | 10.2 s / 31.5 s | 0.4 s / 1.3 s |
| Runs that failed | 1 of 95 (segfault) | 0 of 95 | 0 of 59 applicable |

Main points:

- On the seeded **security** defects, Skylos and Semgrep CE are close
  (19 vs 18 of 37). Semgrep CE detects more **injection** defects (13 vs 10),
  and its seeded precision is higher (0.93 vs 0.76).
- Skylos' lead in overall seeded recall comes from categories Semgrep CE and
  Bandit do not target: dead code (6/6), hallucinated packages (3/3), and
  skipped tests (2 of 6 weakened-test defects). The category mix was chosen by
  the Skylos project.
- All three tools miss most **removed authorization checks** (Skylos 1/6;
  Semgrep CE and Bandit 0/6) and all **hallucinated APIs** (0/2).
- On real agent commits, Skylos produces the most findings (28 per changed
  kLOC), and 90% of them are false positives under the labeling rules. 120 of
  its 182 findings are quality findings, and 79 of those are size, complexity
  or style metrics. Bandit's volume is 89% `assert` in
  tests (130 of 146). Semgrep CE is nearly silent (4 findings, none true).
- Skylos is the slowest on real repositories because `--diff-base` parses the
  whole repository. It crashed once, with a segfault in its C++ scanner on
  `onnx/onnx`.

## Skylos after plan 3.8b (false-positive fixes)

Plan 3.8b fixed the false-positive causes listed under
[Skylos detection bugs found](#skylos-detection-bugs-found) (items 11 to 21),
and it changed how diff-scoped scans report metrics (see
[Code health metrics in diff scans](./cli-output.md#code-health-metrics-in-diff-scans)). Only Skylos was
re-run. Semgrep CE and Bandit did not change, so their numbers above still
apply.

**What was re-run.** The full run needs about 5 GB of clones, and the
benchmark machine had less than 5 GB of free disk. The re-run was therefore
limited to:

- all 59 seeded workspaces;
- 20 of the 36 real commits: the 19 Python commits except `onnx/onnx`
  (real-11, which crashes in the C++ scanner, a plan 3.8a item), plus real-33
  (`heroui`, Storybook).

The 16 TypeScript commits other than real-33 were not re-run. Skylos was run
the same way as in the original run (`--danger --secrets --quality
--ai-defects --diff-base <parent> --format json`). Both sides were scored
against the same labels, with the same scope rules.

- **"Before"** is the working tree of 2026-09-25, snapshotted before the 3.8b
  changes. That snapshot already contained part of the concurrent plan 3.8a
  and 3.8c work (crash handling and new detections), so it is not exactly the
  4.39.1 run above. On the 20 real commits it produced 173 labeled findings,
  against 182 on 36 commits in the original run.
- **"After"** is the same tree with the 3.8b changes and the finished 3.8a and
  3.8c changes.

**Labels.** 23 findings had no label: 22 new seeded detections (most of them
from the 3.8a and 3.8c rule work) and one Storybook "unused file" finding. They
were labeled with the same rules as before and a written reason. The labels
are in `labels/findings.json`, and each reason names plan 3.8b. As before, the
labeling was not blind.

| Skylos | Before | After |
|---|---|---|
| Real commits (20): precision | 19/173 (0.11) | 19/74 (0.26) |
| Real commits (20): false positives | 154 | 55 |
| Real commits (20): in-scope findings / changed kLOC (4,556 added lines) | 38.0 | 16.2 |
| Real commits (20): true positives lost | - | 0 |
| Seeded: precision | 58/74 (0.78) | 73/75 (0.97) |
| Seeded: false positives | 16 | 2 |
| Seeded: defects detected (of 58) | 36 | 51 |
| Real commits (20): median / max wall time | 14.2 s / 125.8 s | 19.4 s / 95.8 s |

Real-commit false positives by category (before → after): quality 100 → 25,
security 30 → 22, dead code 12 → 7, AI defect 12 → 1. True positives are
unchanged in every category (quality 10, security 4, AI defect 4, dead code 1).

Attribution:

- The **3.8b** changes removed 99 false positives on the 20 real commits and
  14 on the seeded corpus, and removed no true positives. Each removed finding
  was compared by fingerprint. An intermediate version of the new SSRF rule
  lost the two real-15 SSRF true positives (MCP command-table arguments). They
  were restored before the final run, by treating command-dispatch handlers as
  untrusted sources.
- The seeded **recall gain** (36 → 51 detected defects) comes from the plan
  3.8a and 3.8c rule work: SQL/command/XSS/path sinks in TypeScript, SSTI,
  debug mode, CORS, TLS, removed-auth regressions, credential fallbacks,
  unknown keyword arguments and weakened assertions. It does not come from
  3.8b.
- Most of the metric reduction comes from the new diff-scope rule, not from
  better detection. In a diff scan, size, complexity and style metrics are now
  reported in a separate `code_health` list, which is not a finding list and is
  never gated. The benchmark harness reads only the finding lists, so these
  entries no longer count. Across the 20 real commits, `code_health` listed
  140 metrics: 41 introduced by the commit, 47 worsened and 52 unverified
  (TypeScript, or no measurable base). It dropped 1,606 metrics that were
  already over their threshold before the commit and did not get worse.
- Wall time is from single runs on a shared machine, and other benchmark jobs
  were running at the same time. The median grew by about 5 s, partly because
  changed Python files are now re-measured at the merge base. Treat the timing
  row as approximate.

False positives that remain on the 20 real commits (55): symlink or
path-traversal claims on paths from configuration, CLI arguments or directory
listings (SKY-D325, D324 and D215: 19), sampled debug `print()` in CLI entry
points (L009: 9), nested-loop warnings (P403: 7), and interface-required
parameters (U006: 7, which are `*args` of `rembg` session overrides and an
unused backend parameter). The rest are single findings: suppressed cleanup
errors (L007), SHA-1 and MD5 for change detection without
`usedforsecurity=False` (D208, D207), and one each of D223, F102, L006, L017,
P401 (an HTTP error body) and L026.

## Questions

1. **Recall on known defects.** When an agent change contains a specific,
   known defect, does the tool report it?
2. **Precision.** What fraction of the tool's findings on the changed lines are
   correct and worth acting on in review?
3. **Volume on real agent commits.** How many findings per thousand changed
   lines does each tool produce on real, merged agent commits, and how many of
   those are true?
4. **Latency.** Wall time for one change, in the configuration a PR check would use.
5. **Incomplete analysis.** When a file cannot be parsed, does the tool say so,
   or does it return a clean result?

## Tools and configuration

| Tool | Version | Invocation |
|---|---|---|
| Skylos | 4.39.1, run from source (`PYTHONPATH=<repo> python3 -m skylos.entry`); the exact commit and a digest of `skylos/` are in `results/summary.json` | `skylos . --danger --secrets --quality --ai-defects --diff-base <base> --format json --no-upload` from the repository root |
| Semgrep CE | 1.178.0 (`pip install semgrep==1.178.0`) | `semgrep scan --config <snapshot> ... --json --metrics off --no-git-ignore -- <changed files>` |
| Bandit | 1.9.4 (`pip install bandit==1.9.4`) | `bandit -f json -q <changed .py files>` (default profile: every test, every severity and confidence) |
| SonarQube Community Build | not run | see [SonarQube](#sonarqube) |

Configuration choices:

- **Skylos** runs the source analyzers of `-a` except `--sca`. `--sca` looks up
  dependency CVEs in OSV; neither Semgrep CE nor Bandit does that, and it adds
  network-bound latency to every run. Dead-code analysis is on by default.
  `--diff-base` is Skylos' PR mode: it parses the whole repository (dead code
  needs cross-file references) and reports findings only for changed files.
  The dependency-hallucination rule (SKY-D222) queries PyPI or npm for package
  names in changed manifests.
- **Semgrep CE** uses the registry packs `p/python`, `p/javascript`,
  `p/typescript`, `p/security-audit` and `p/secrets`. The harness downloads each
  pack once from `https://semgrep.dev/c/<pack>` into the work directory and
  every run reads that snapshot, so all runs in one benchmark use identical
  rules. The snapshot's rule counts and SHA-256 digests are recorded in
  `results/summary.json` (`environment.semgrep_rules`). Registry packs change
  over time; a later re-run fetches the current packs, and the digests show
  whether they differ. The packs are not redistributed in this repository.
  `--config auto` was not used because it requires sending metrics.
  Semgrep receives the changed files as explicit targets; its community rules
  are file-local, so scanning only changed files gives the same results as a
  repository scan filtered to those files.
- **Bandit** receives the changed `.py` files. It has no TypeScript support, so
  TypeScript cases count as misses in the overall recall and are listed as
  "not applicable" in the run table. Per-language recall is reported
  separately.
- All three tools run on Python 3.14.4 (the FastAPI base repository uses
  Python 3.14-only `except A, B:` syntax, so an older interpreter would make
  Bandit fail to parse it).
- No project dependencies are installed in the analyzed repositories. This is
  the usual setup for a scanner job in CI. It matters for rules that inspect
  installed packages (see [Where Skylos loses](#where-skylos-loses)).
- Tools run one at a time on the same machine (Apple M-series, 8 cores,
  macOS 13). Timing is the wall time of the tool's process, including
  interpreter start-up and rule loading.

### SonarQube

SonarQube was **not run**: it requires a SonarQube server (Docker or a
standalone install), and the Docker daemon on the benchmark machine was not
running. The harness includes a SonarQube runner that is used when
`SONAR_HOST_URL`, `SONAR_TOKEN` and a `sonar-scanner` binary are available. It
analyzes each workspace as its own project restricted to the changed files,
waits for the compute-engine task (`api/ce/task`), then reads
`api/issues/search` and `api/hotspots/search` and normalizes both
(`harness/tools.py`, class `Sonar`). Only the normalizer is covered by an
offline test; that test uses a response written to the documented API schema,
not one captured from a server. The runner has not been exercised against a
live server, so there are no SonarQube numbers.

## Corpus

### Real agent commits (36)

Selected by `scripts/select_real_commits.py` on 2026-09-25 with read-only GitHub
API calls. The output is pinned by SHA in `corpus/real_commits.json`, and the
benchmark never re-selects commits.

1. Repository frame: the 300 most-starred Python and 300 most-starred
   TypeScript repositories with 300 to 60,000 stars, pushed since 2026-06-01,
   not archived, not forks, and under 150 MB. 399 repositories remained after
   de-duplication and the size filter.
2. Commit frame: default-branch commits between 2026-06-01 and 2026-09-20, up
   to 200 per repository.
3. Agent attribution: a `Co-authored-by: Claude` trailer or a "Generated with
   Claude Code" line; the `copilot-swe-agent[bot]` author or a
   `Co-authored-by: Copilot` trailer; a `cursoragent@cursor.com` co-author; the
   `devin-ai-integration[bot]` author; or a `Co-authored-by: Codex` trailer.
   This matched 3,502 commits.
4. Change filter: one parent, 15 to 1,200 added lines in `.py`, `.ts`, `.tsx`,
   or `.js` files (excluding vendored, built and `.d.ts` files), and at most 40
   files. One commit per repository. This left 168 eligible commits.
5. Sampling: eligible commits are ordered by `sha256(repo@sha)` and taken
   round-robin across (agent, language) buckets. Buckets with few candidates
   (Copilot, Codex, Devin) are exhausted first, and Claude and Cursor fill the
   rest.

Result: 20 Python and 16 TypeScript/JavaScript commits (14 Claude, 13 Cursor,
5 Copilot, 3 Codex, 1 Devin) with 6,453 added source lines.

| ID | Commit | Agent | Language | Added lines |
|---|---|---|---|---|
| real-01 | [HKUDS/LightRAG@ebff65342f](https://github.com/HKUDS/LightRAG/commit/ebff65342f50ff431ba5164882ba426e4eabee28) | claude | python | 20 |
| real-02 | [HKUDS/RAG-Anything@0fd61f3ee4](https://github.com/HKUDS/RAG-Anything/commit/0fd61f3ee4fe19b7f18dfae9485316b9731f16d8) | claude | python | 438 |
| real-03 | [MadsLorentzen/ai-job-search@8c81edc330](https://github.com/MadsLorentzen/ai-job-search/commit/8c81edc330b98db0473dcb016e34db835c2fd378) | claude | python | 334 |
| real-04 | [hugohe3/ppt-master@92be041470](https://github.com/hugohe3/ppt-master/commit/92be041470473c0300f753c4ce1ffcfb240b1238) | claude | python | 22 |
| real-05 | [jamiepine/voicebox@f750596364](https://github.com/jamiepine/voicebox/commit/f750596364d12a732c5aa626db67e2ca7a1af1ef) | claude | python | 55 |
| real-06 | [teng-lin/notebooklm-py@1b8d325d92](https://github.com/teng-lin/notebooklm-py/commit/1b8d325d929a59dced59866eea3fa6a06362ffff) | claude | python | 121 |
| real-07 | [virgiliojr94/book-to-skill@7bcfcd5262](https://github.com/virgiliojr94/book-to-skill/commit/7bcfcd5262329f8d57a385903f18a98bc6705e4e) | claude | python | 128 |
| real-08 | [tanweai/pua@e6e6cd237a](https://github.com/tanweai/pua/commit/e6e6cd237ad17750d179674bff52f8184abea8fd) | codex | python | 133 |
| real-09 | [verl-project/verl@5cfb74fa04](https://github.com/verl-project/verl/commit/5cfb74fa04c7f6e5d98260b8f05157c6a9402695) | codex | python | 54 |
| real-10 | [microsoft/agent-lightning@ee707b6626](https://github.com/microsoft/agent-lightning/commit/ee707b662617d52fc46be2a04d2a716a3eb0a521) | copilot | python | 1039 |
| real-11 | [onnx/onnx@b023681795](https://github.com/onnx/onnx/commit/b0236817953cbb06a13a0fb2cd2c457b79e2ec85) | copilot | python | 702 |
| real-12 | [python-poetry/poetry@9be6dd6e75](https://github.com/python-poetry/poetry/commit/9be6dd6e75906312c5dc477907e6901fa81ae024) | copilot | python | 53 |
| real-13 | [Huanshere/VideoLingo@043aa7a7fd](https://github.com/Huanshere/VideoLingo/commit/043aa7a7fd1bb36fce9ce405d9d8d7bc499c7178) | cursor | python | 241 |
| real-14 | [NVIDIA/SkillSpector@76f4beb589](https://github.com/NVIDIA/SkillSpector/commit/76f4beb589d9028e630b3105ca8fcbb595fb883e) | cursor | python | 185 |
| real-15 | [ahujasid/mcp-for-blender@fd95e6509d](https://github.com/ahujasid/mcp-for-blender/commit/fd95e6509d2b2c0812b2d83b75f53443da44c325) | cursor | python | 267 |
| real-16 | [danielgatis/rembg@b60806e9e7](https://github.com/danielgatis/rembg/commit/b60806e9e7025c7fe2f8edad8bdc6a2d216ba54f) | cursor | python | 270 |
| real-17 | [huggingface/peft@78bce7cb48](https://github.com/huggingface/peft/commit/78bce7cb48f800a7ad0d352b68a46302e13e1687) | cursor | python | 128 |
| real-18 | [muratcankoylan/Agent-Skills-for-Context-Engineering@9749e5cbda](https://github.com/muratcankoylan/Agent-Skills-for-Context-Engineering/commit/9749e5cbda17b03725ef366a40bacc5db7bcac8e) | cursor | python | 592 |
| real-19 | [titanwings/distilly@63044e3393](https://github.com/titanwings/distilly/commit/63044e3393ce5f1da7d202323e7aca5bac416c4f) | cursor | python | 91 |
| real-20 | [locustio/locust@3c324d8ff9](https://github.com/locustio/locust/commit/3c324d8ff9668e792bd239ed8a87e4d96dc15b2f) | devin | python | 29 |
| real-21 | [abhigyanpatwari/GitNexus@376ed3bb4a](https://github.com/abhigyanpatwari/GitNexus/commit/376ed3bb4abda80f7a57cf963822002b5304f2f9) | claude | typescript | 71 |
| real-22 | [coleam00/Archon@908a6dc35b](https://github.com/coleam00/Archon/commit/908a6dc35bf41b754252c37e2bc1559ddc6fc277) | claude | typescript | 160 |
| real-23 | [emberjs/ember.js@14f95cea45](https://github.com/emberjs/ember.js/commit/14f95cea45a0e666939b718490b571f8faddd4a1) | claude | typescript | 79 |
| real-24 | [ether/etherpad@4d95a12845](https://github.com/ether/etherpad/commit/4d95a12845d42ce4cbc1f5cda5460a44269c2574) | claude | typescript | 125 |
| real-25 | [homebridge/homebridge@18c0a9128a](https://github.com/homebridge/homebridge/commit/18c0a9128af4b8b860a31870b2f81e51857602b1) | claude | typescript | 106 |
| real-26 | [trpc/trpc@3d21d2c136](https://github.com/trpc/trpc/commit/3d21d2c1364139938f1d7924802af67b506ca544) | claude | typescript | 93 |
| real-27 | [usablica/intro.js@97b87acefc](https://github.com/usablica/intro.js/commit/97b87acefcc22372a0d99cf8aea99685a42dd2dd) | claude | typescript | 20 |
| real-28 | [neoclide/coc.nvim@cf1e7ea283](https://github.com/neoclide/coc.nvim/commit/cf1e7ea283e6627d7c4d90d6b14f0d4094ae67f6) | codex | typescript | 18 |
| real-29 | [TanStack/query@b4368c4379](https://github.com/TanStack/query/commit/b4368c43792349f6c29d1fb41f7ee1ef3a8bdd2c) | copilot | typescript | 111 |
| real-30 | [desktop/desktop@00fe682ee9](https://github.com/desktop/desktop/commit/00fe682ee9a77dc098b051108b76adaab42ecf04) | copilot | typescript | 155 |
| real-31 | [KaTeX/KaTeX@87a2b304af](https://github.com/KaTeX/KaTeX/commit/87a2b304aff601ad1c3d930d47d6833d123ad210) | cursor | typescript | 37 |
| real-32 | [dubinc/dub@a3f695b149](https://github.com/dubinc/dub/commit/a3f695b1493220fc5da3bdfa81d43fe4fccae2e8) | cursor | typescript | 55 |
| real-33 | [heroui-inc/heroui@646597e87f](https://github.com/heroui-inc/heroui/commit/646597e87f2107a6f90fb13917c6802a6ae911b6) | cursor | typescript | 356 |
| real-34 | [solidjs/solid@5086b27e6a](https://github.com/solidjs/solid/commit/5086b27e6a8e03750d987854247d87647cfc195e) | cursor | typescript | 35 |
| real-35 | [unocss/unocss@e74667e8c4](https://github.com/unocss/unocss/commit/e74667e8c4f003664f7d7a1820b7eb86f6d4cdd9) | cursor | typescript | 109 |
| real-36 | [xtermjs/xterm.js@2fe3fd13a1](https://github.com/xtermjs/xterm.js/commit/2fe3fd13a164f956d0c6a2365fa89feaf4366074) | cursor | typescript | 21 |

These commits have **no ground truth**. They measure finding volume and
precision on real agent output, not recall.

### Seeded agent mistakes (59 cases, 58 defects)

Three small, pinned MIT-licensed applications (`corpus/seeded/bases.toml`):

| Base | Pinned commit | Language |
|---|---|---|
| [miguelgrinberg/microblog](https://github.com/miguelgrinberg/microblog) | `a975ef6` | Python (Flask) |
| [fastapi/full-stack-fastapi-template](https://github.com/fastapi/full-stack-fastapi-template) | `cb740b6` | Python 3.14 (FastAPI, SQLModel) |
| [gothinkster/node-express-realworld-example-app](https://github.com/gothinkster/node-express-realworld-example-app) | `30b68e1` | TypeScript (Express, Prisma) |

Each case in `corpus/seeded/cases/<id>.toml` is a small edit to one base, a
short "story" (the task the agent was plausibly given), and the ground-truth
defects with their anchored locations. The edits are applied to a fresh
checkout of the pinned commit and left uncommitted, so the change is measured
against `HEAD`. The harness requires each `old` snippet to occur exactly once
and each location anchor to match exactly one line, so a case cannot silently
move.

| Defect category | Defects | Cases |
|---|---|---|
| injection (SQL, command, code eval, SSRF, path traversal, SSTI/XSS, deserialization, open redirect) | 17 | mb-06..11, mb-20, fa-08, fa-11, fa-12, ex-06..08, ex-11..13, ex-16 |
| insecure_config (TLS verification off, debug server, weak randomness, JWT verification off, wildcard CORS, MD5 passwords) | 8 | mb-15..17, fa-03, fa-13, fa-14, ex-17, ex-18 |
| auth_removed (deleted authn decorator/middleware, deleted ownership check, new unauthenticated admin route) | 6 | mb-04, mb-05, fa-01, fa-02, ex-01, ex-02 |
| secret (password default, provider API key, GitHub token, JWT signing key, AWS keys) | 6 | mb-12..14, fa-07, ex-09, ex-10 |
| weakened_test (assertions replaced by weaker ones, tests skipped) | 6 | mb-18, fa-09, ex-14 |
| dead_code (unused helper, unused import) | 6 | mb-19, fa-10, ex-15 |
| hallucinated_import (non-existent module or export) | 4 | mb-01, fa-04, ex-03, ex-04 |
| hallucinated_package (dependency not on PyPI/npm, verified 404 on 2026-09-25) | 3 | mb-03, fa-06, ex-05 |
| hallucinated_api (non-existent method or keyword argument) | 2 | mb-02, fa-05 |
| clean controls (no defect) | 0 | mb-c1..c3, fa-c1, fa-c2, ex-c1, ex-c2 |

Two cases (`mb-20`, `ex-16`) contain a syntax error (a truncated edit) in the
same file as an injection. They test incomplete-analysis handling.

Synthetic credentials that match provider formats (the `ghp_` token and the AWS
keys) are stored as split parts (`[materialize]` in the case file) and joined
when the case is applied, so this repository does not trigger secret-scanning
push protection. The joined values are the ones the tools see.

The category mix was chosen by the Skylos project and overlaps with Skylos'
feature set (dead code, hallucinated dependencies, weakened tests have no
counterpart in Semgrep CE or Bandit). The "ALL" recall row therefore favors
Skylos by construction. Use the per-category rows.

## Scope: which findings count

Every tool's findings are normalized to `(tool, rule, file, line, category)`,
de-duplicated on `(tool, rule, file, line)` (the same rule twice on one line
counts once, for every tool), then filtered to the change:

- A finding is **in scope** if its line is a changed line of a changed file:
  an added or modified line, or either neighbour of a pure deletion. Lines come
  from the edit application (seeded) or `git diff -U0 parent sha` (real).
- For seeded cases, a finding is also in scope if it falls within 3 lines of a
  ground-truth defect location. This lets a tool report a removed check at the
  enclosing function instead of the deleted line.
- Findings outside scope (pre-existing code) are ignored for every tool.

Normalized categories: `security`, `secret`, `ai_defect`, `dead_code`,
`quality`, `dependency`. Semgrep rules map to `secret` for the `p/secrets` /
`generic.secrets` family, `security` for `metadata.category: security`, and
`quality` otherwise. Bandit B105-B107 map to `secret`, and everything else maps
to `security`. Skylos rules keep their report bucket, and `SKY-S*` rules map to
`secret`.

## Labeling rules

Every in-scope finding has a label in `labels/findings.json`, keyed by a
fingerprint of `(workspace, tool, rule, file, line)`, with a verdict and a
written reason.

- **tp**: the claim the finding makes is correct for this code, *and* a
  reviewer of this change would reasonably act on it (change the code or
  verify something specific).
- **fp**: anything else, including:
  - the claim is wrong (for example, "unused" when the symbol is used, or "SSRF"
    when the host is a constant);
  - the claim is correct but concerns code the change did not introduce;
  - the finding is a file- or module-level metric (such as main-sequence
    distance) with no actionable link to the change;
  - the finding is a generic advisory whose trigger condition is absent (for
    example, `subprocess` with a fixed argument list and no shell);
  - the finding comes from a rule for a different framework that does not
    apply (for example, a Django password-validation rule on a Flask test);
  - `assert` in pytest tests.
- **Maintainability and performance findings.** Size, complexity and style
  metrics are always **fp**: function length, cyclomatic or cognitive
  complexity, nesting depth, return and parameter counts, class cohesion,
  main-sequence or coupling metrics, repeated literals, boolean positional
  parameters, and missing type annotations. They describe style, not a
  defect, and this benchmark asks about defects. Performance heuristics
  (nested loops, `await` in a loop, whole-file `read()`) are tp only when the
  cost they describe actually exists. Findings that name a concrete defect
  risk are tp when the claim is correct for new, non-test code: unused code,
  a missing network timeout, an unclosed resource, a swallowed exception that
  hides failures, debug output in library code, or a type-checker suppression
  or `any` in a new exported API. This rule affects only Skylos, because
  Semgrep CE's `p/` packs and Bandit produced no findings of these kinds.
- **detects**: for seeded cases, a tp finding additionally *detects* a seeded
  defect when (a) it lies inside that defect's location window (enforced by the
  scorer) and (b) its message identifies the defect class or the risky
  construct at that location. A correct but different finding on the same line
  (for example, "requests call without timeout" on the SSRF line) is tp but
  does not detect the defect.
- A defect counts as **recalled** by a tool if at least one of the tool's
  findings detects it.

The labeling was **not blind**. The worksheet (`bench.py worksheet`) hides tool
names and interleaves tools by location, but rule IDs and message styles still
reveal the tool, and there was a single labeler. Each label's reason is
recorded so it can be disputed line by line.

## Metrics

- **Recall** (seeded only): recalled defects / seeded defects, per category and
  per language.
- **Precision**: tp / (tp + fp) over in-scope findings, separately for the
  seeded and real corpora.
- **Findings per changed kLOC** (real only): in-scope findings / (added lines
  in `.py/.ts/.tsx/.js/.jsx/.mjs/.cjs` files / 1000). Findings in non-source
  changed files (such as manifests) count in the numerator.
- **Wall time**: per workspace, for runs with status `ok`.
- All ratios are reported with Wilson 95% confidence intervals. With 2 to 17
  defects per category, most intervals are wide.

## Results

The tables below are copied from `results/tables.md` (same run). Cells show
k/n = ratio [Wilson 95% CI].

### Seeded corpus: recall by defect category

| Category | n | skylos | semgrep | bandit |
|---|---|---|---|---|
| auth_removed | 6 | 1/6 = 0.17 [0.03-0.56] | 0/6 = 0.00 [0.00-0.39] | 0/6 = 0.00 [0.00-0.39] |
| dead_code | 6 | 6/6 = 1.00 [0.61-1.00] | 0/6 = 0.00 [0.00-0.39] | 0/6 = 0.00 [0.00-0.39] |
| hallucinated_api | 2 | 0/2 = 0.00 [0.00-0.66] | 0/2 = 0.00 [0.00-0.66] | 0/2 = 0.00 [0.00-0.66] |
| hallucinated_import | 4 | 1/4 = 0.25 [0.05-0.70] | 0/4 = 0.00 [0.00-0.49] | 0/4 = 0.00 [0.00-0.49] |
| hallucinated_package | 3 | 3/3 = 1.00 [0.44-1.00] | 0/3 = 0.00 [0.00-0.56] | 0/3 = 0.00 [0.00-0.56] |
| injection | 17 | 10/17 = 0.59 [0.36-0.78] | 13/17 = 0.76 [0.53-0.90] | 5/17 = 0.29 [0.13-0.53] |
| insecure_config | 8 | 5/8 = 0.62 [0.31-0.86] | 4/8 = 0.50 [0.21-0.79] | 4/8 = 0.50 [0.21-0.79] |
| secret | 6 | 3/6 = 0.50 [0.19-0.81] | 1/6 = 0.17 [0.03-0.56] | 1/6 = 0.17 [0.03-0.56] |
| weakened_test | 6 | 2/6 = 0.33 [0.10-0.70] | 0/6 = 0.00 [0.00-0.39] | 0/6 = 0.00 [0.00-0.39] |
| ALL | 58 | 31/58 = 0.53 [0.41-0.66] | 18/58 = 0.31 [0.21-0.44] | 10/58 = 0.17 [0.10-0.29] |

Recall by language. Bandit does not analyze TypeScript.

| Language | skylos | semgrep | bandit |
|---|---|---|---|
| python | 21/38 = 0.55 [0.40-0.70] | 12/38 = 0.32 [0.19-0.47] | 10/38 = 0.26 [0.15-0.42] |
| typescript | 10/20 = 0.50 [0.30-0.70] | 6/20 = 0.30 [0.14-0.52] | 0/20 = 0.00 [0.00-0.16] |

Per-defect detection (`yes` = at least one finding labeled as detecting it):

| Defect | Category | Skylos | Semgrep CE | Bandit |
|---|---|---|---|---|
| ex-01-auth-removed/d1 | auth_removed | - | - | - |
| ex-02-unauth-admin-route/d1 | auth_removed | - | - | - |
| ex-03-hallucinated-member/d1 | hallucinated_import | - | - | - |
| ex-04-phantom-local-export/d1 | hallucinated_import | yes | - | - |
| ex-05-hallucinated-package/d1 | hallucinated_package | yes | - | - |
| ex-06-sqli/d1 | injection / sqli | - | - | - |
| ex-07-cmdi/d1 | injection / command_injection | - | yes | - |
| ex-08-eval/d1 | injection / code_injection | yes | yes | - |
| ex-09-secret-jwt/d1 | secret | yes | - | - |
| ex-10-secret-aws/d1 | secret | yes | yes | - |
| ex-11-xss/d1 | injection / xss | - | yes | - |
| ex-12-open-redirect/d1 | injection / open_redirect | yes | - | - |
| ex-13-path-traversal/d1 | injection / path_traversal | - | yes | - |
| ex-14-weakened-tests/d1 | weakened_test | - | - | - |
| ex-14-weakened-tests/d2 | weakened_test | yes | - | - |
| ex-15-dead-code/d1 | dead_code | yes | - | - |
| ex-15-dead-code/d2 | dead_code | yes | - | - |
| ex-16-unparseable/d1 | injection / command_injection | - | yes | - |
| ex-17-tls-disabled/d1 | insecure_config / tls_verification_disabled | - | - | - |
| ex-18-insecure-random/d1 | insecure_config / insecure_randomness | yes | - | - |
| fa-01-authz-removed/d1 | auth_removed | - | - | - |
| fa-02-admin-guard-removed/d1 | auth_removed | - | - | - |
| fa-03-jwt-unverified/d1 | insecure_config / jwt_verification_disabled | yes | yes | - |
| fa-04-hallucinated-import/d1 | hallucinated_import | - | - | - |
| fa-05-hallucinated-kwarg/d1 | hallucinated_api | - | - | - |
| fa-06-hallucinated-package/d1 | hallucinated_package | yes | - | - |
| fa-07-secret-key/d1 | secret | - | - | - |
| fa-08-sqli/d1 | injection / sqli | yes | yes | yes |
| fa-09-weakened-tests/d1 | weakened_test | - | - | - |
| fa-09-weakened-tests/d2 | weakened_test | yes | - | - |
| fa-10-dead-code/d1 | dead_code | yes | - | - |
| fa-10-dead-code/d2 | dead_code | yes | - | - |
| fa-11-cmdi/d1 | injection / command_injection | yes | yes | yes |
| fa-12-xss/d1 | injection / xss | yes | - | - |
| fa-13-cors/d1 | insecure_config / cors_wildcard_credentials | - | yes | - |
| fa-14-weak-hash/d1 | insecure_config / weak_password_hash | yes | yes | yes |
| mb-01-hallucinated-import/d1 | hallucinated_import | - | - | - |
| mb-02-hallucinated-api/d1 | hallucinated_api | - | - | - |
| mb-03-hallucinated-package/d1 | hallucinated_package | yes | - | - |
| mb-04-authz-removed/d1 | auth_removed | - | - | - |
| mb-05-authn-removed/d1 | auth_removed | yes | - | - |
| mb-06-sqli/d1 | injection / sqli | yes | yes | yes |
| mb-07-cmdi/d1 | injection / command_injection | yes | yes | yes |
| mb-08-ssrf/d1 | injection / ssrf | yes | yes | - |
| mb-09-path-traversal/d1 | injection / path_traversal | yes | - | - |
| mb-10-ssti/d1 | injection / ssti_xss | - | yes | - |
| mb-11-pickle/d1 | injection / deserialization | yes | yes | yes |
| mb-12-secret-password/d1 | secret | - | - | - |
| mb-13-secret-apikey/d1 | secret | - | - | - |
| mb-14-secret-token/d1 | secret | yes | - | yes |
| mb-15-tls-disabled/d1 | insecure_config / tls_verification_disabled | yes | - | yes |
| mb-16-insecure-random/d1 | insecure_config / insecure_randomness | yes | - | yes |
| mb-17-debug-mode/d1 | insecure_config / debug_enabled | - | yes | yes |
| mb-18-weakened-tests/d1 | weakened_test | - | - | - |
| mb-18-weakened-tests/d2 | weakened_test | - | - | - |
| mb-19-dead-code/d1 | dead_code | yes | - | - |
| mb-19-dead-code/d2 | dead_code | yes | - | - |
| mb-20-unparseable/d1 | injection / code_injection | - | yes | - |

### Precision

Seeded corpus (in-scope findings on the 59 seeded workspaces, including the
clean controls):

| Category | skylos | semgrep | bandit |
|---|---|---|---|
| ALL | 51/67 = 0.76 [0.65-0.85] | 28/30 = 0.93 [0.79-0.98] | 15/22 = 0.68 [0.47-0.84] |
| security | 18/22 = 0.82 [0.61-0.93] | 27/29 = 0.93 [0.78-0.98] | 14/21 = 0.67 [0.45-0.83] |
| secret | 4/4 = 1.00 [0.51-1.00] | 1/1 = 1.00 [0.21-1.00] | 1/1 = 1.00 [0.21-1.00] |
| ai_defect | 8/9 = 0.89 [0.56-0.98] | - | - |
| dead_code | 13/14 = 0.93 [0.69-0.99] | - | - |
| quality | 8/18 = 0.44 [0.25-0.66] | - | - |
| dependency | - | - | - |

Real agent commits:

| Category | skylos | semgrep | bandit |
|---|---|---|---|
| ALL | 19/182 = 0.10 [0.07-0.16] | 0/4 = 0.00 [0.00-0.49] | 4/146 = 0.03 [0.01-0.07] |
| security | 4/34 = 0.12 [0.05-0.27] | 0/4 = 0.00 [0.00-0.49] | 4/146 = 0.03 [0.01-0.07] |
| secret | - | - | - |
| ai_defect | 4/16 = 0.25 [0.10-0.49] | - | - |
| dead_code | 1/12 = 0.08 [0.01-0.35] | - | - |
| quality | 10/120 = 0.08 [0.05-0.15] | - | - |
| dependency | - | - | - |

The true positives on real commits were:

- **Skylos (19):** an agent-added method that nothing calls
  (`BatchParser._file_signature`, real-02); four imports whose packages are
  not declared (`pytest` and `mlx_lm` in real-05, and `openai` and `faiss` in
  real-10); eight sampled debug `print()` calls in a reward function (real-10);
  two `requests.get` calls without a timeout, and two SSRF findings on an MCP
  tool argument used as a download URL (real-15); and two Hugging Face
  `from_pretrained(..., trust_remote_code=True)` calls without a pinned
  revision (real-10).
- **Bandit (4):** the same two missing timeouts (real-15) and the same two
  unpinned `from_pretrained` calls (real-10).
- **Semgrep CE (0):** its four findings are MD5/SHA-1 used for change
  detection and a `urlopen` of a constant HTTPS URL.

Skylos' 163 false positives on real commits break down as follows (from
`labels/findings.json`):

| Group | Count |
|---|---|
| Maintainability metrics: length, complexity, nesting, return count, parameter count, cohesion, literal repetition, boolean parameters, annotations | 79 |
| Path-traversal and symlink claims on paths from configuration, CLI arguments, directory listings or hashes | 14 |
| Nested-loop and await-in-loop performance warnings | 11 |
| `print()` in CLI entry points reported as debug leftovers | 9 |
| Interface-required parameters reported as unused | 7 |
| Test fixtures (temp files, subprocess of `sys.executable`) | 5 |
| Other: suppressed cleanup errors, non-security hashes, local packages taken for PyPI packages, star-import names reported as phantom, Storybook exports, chunked reads | 38 |

### Volume on real agent commits

| Tool | Findings | Findings / changed kLOC | TP / changed kLOC | Commits with >=1 finding | security | secret | ai_defect | dead_code | quality | dependency |
|---|---|---|---|---|---|---|---|---|---|---|
| skylos | 182 | 28.2 | 2.94 | 21 | 34 | 0 | 16 | 12 | 120 | 0 |
| semgrep | 4 | 0.62 | 0.0 | 3 | 4 | 0 | 0 | 0 | 0 | 0 |
| bandit | 146 | 22.63 | 0.62 | 14 | 146 | 0 | 0 | 0 | 0 | 0 |

### Wall time per change

| Tool | Corpus | Runs | Median s | p90 s | Max s | Total s |
|---|---|---|---|---|---|---|
| skylos | seeded | 59 | 8.81 | 20.69 | 29.99 | 642.3 |
| skylos | real | 35 | 30.51 | 153.01 | 399.65 | 2379.2 |
| semgrep | seeded | 59 | 7.46 | 18.01 | 34.1 | 607.4 |
| semgrep | real | 36 | 10.15 | 22.21 | 31.52 | 427.7 |
| bandit | seeded | 39 | 0.23 | 0.4 | 0.51 | 9.3 |
| bandit | real | 20 | 0.41 | 0.96 | 1.34 | 10.5 |

Skylos' slowest real runs were `dubinc/dub` (400 s), `teng-lin/notebooklm-py`
(243 s) and `abhigyanpatwari/GitNexus` (235 s). All three are repositories where
`--diff-base` parses the entire tree. Semgrep CE's time is dominated by
loading about 570 rules from YAML on every run.

### Incomplete and unknown handling

| Tool | Run status counts | Workspaces where the tool reported analysis errors |
|---|---|---|
| skylos | {'ok': 94, 'error': 1} | 4: mb-20-unparseable, real-17, real-21, real-36 |
| semgrep | {'ok': 95} | 4: mb-20-unparseable, real-11, real-31, real-34 |
| bandit | {'not_applicable': 36, 'ok': 59} | 1: mb-20-unparseable |

| Unparseable seeded file | Skylos | Semgrep CE | Bandit |
|---|---|---|---|
| ex-16-unparseable | silent: no finding and no parse error for the broken file | defect reported despite syntax error | not applicable (language not supported) |
| mb-20-unparseable | reported the file as not analyzed (parse error surfaced) | defect reported despite syntax error | reported the file as not analyzed (parse error surfaced) |

- **Skylos** exits `2` (incomplete) and lists `SKY-ANALYSIS-INCOMPLETE` in
  `analysis_errors` when a Python file does not parse. For the broken
  **TypeScript** file (ex-16), it reported nothing, recorded no analysis
  error, and exited `0`. On real-11 (`onnx/onnx`), it crashed with SIGSEGV
  and produced no report. Unparseable files **outside** the change also made
  it exit `2`: a C++ test fixture in real-21 and a Python 2 fixture in
  real-36. In real-17, it reported that its grep-verification budget ran out
  and that some dead-code findings were withheld.
- **Semgrep CE** reported both seeded injections from partially parsed files,
  recording the Python syntax error in `errors` and recovering from the
  TypeScript one silently. It also recorded a rule timeout (real-11), a parse
  failure on a TypeScript test file (real-31), and partial parsing of valid
  TypeScript variance annotations (`out T`, real-34).
- **Bandit** recorded the Python syntax error in `errors` and skipped the
  file.

## Where Skylos loses

- **Injection recall.** Semgrep CE detected 13 of 17 seeded injections;
  Skylos detected 10. Skylos missed a TypeScript `child_process.exec` with
  request input (ex-07), TypeScript `res.send` HTML with request input
  (ex-11), TypeScript `res.sendFile(path.join(..., req.params.name))` (ex-13),
  Flask `render_template_string` with request input (mb-10), and both
  injections in unparseable files (mb-20, ex-16). Semgrep CE detected all of
  these. Neither tool detected `prisma.$queryRawUnsafe` with interpolated input
  (ex-06).
- **Insecure configuration.** Skylos missed Flask `app.run(host='0.0.0.0',
  debug=True)` (mb-17) and wildcard CORS with credentials (fa-13); Semgrep CE
  detected both. For mb-17, Semgrep CE and Bandit flag the `0.0.0.0` bind on
  the seeded line, and no tool flags `debug=True` itself. The label counts the
  bind finding as a detection because the seeded defect is defined as both. No tool detected `NODE_TLS_REJECT_UNAUTHORIZED = '0'` (ex-17).
- **Precision.** Semgrep CE's seeded precision was 0.93 and Skylos' was 0.76.
  On real agent commits, Skylos produced 163 false positives in 36 commits,
  more than any other tool and 44 times Semgrep CE's volume, for 19 true
  positives.
- **Latency.** On real repositories, Skylos' median was 30.5 s against
  Semgrep CE's 10.2 s, and its maximum was 400 s against 31.5 s.
- **Robustness.** Skylos is the only tool that crashed (1 of 95 runs), and the
  only tool that stayed silent on a syntax error in a supported language.
- **Hallucinations it targets but missed.** `from requests.retry import
  RetryPolicy` (mb-01) and `jwt.encode(..., expires_in=...)` (fa-05) were both
  missed, even though `requests` and `PyJWT` were installed in the Skylos
  interpreter. Two other misses, `sqlmodel.paginate` (fa-04) and
  `request.get_json_or_400()` (mb-02), involve packages that were not
  installed, so the harness setup may account for them.
- **Secrets.** Skylos missed a hardcoded password fallback
  (`os.environ.get(...) or '<literal>'`, mb-12), a 32-hex API key fallback
  (mb-13), and a 48-hex `SECRET_KEY: str = "..."` class default (fa-07). The
  other tools missed these too.
- **Weakened tests.** SKY-A101 detected the two added skips. It missed all
  four weakened assertions: `assertIsNotNone` replacing two password checks,
  `assertEqual(len(f1), 3)` replacing an ordered equality, `status_code in
  (200, 403)`, and `rejects.toBeDefined()`.

## Skylos detection bugs found

Each item below is reproducible from the pinned workspaces with the
invocation shown under [Tools and configuration](#tools-and-configuration).

Crash and incompleteness:

1. **Segfault in the C++ scanner.**
   `scan_cpp_file("onnx/defs/parser.cc")` at onnx@b023681795 (also
   `onnx/defs/schema.cc` and `onnx/shape_inference/implementation.cc`) kills
   the process with SIGSEGV in `skylos/visitors/languages/cpp/core.py` `_text`
   (called from `scan_symbols` and `_is_file_local_function`), with
   tree-sitter 0.26.0 and tree-sitter-cpp 0.23.4 on Python 3.14.4. The
   parallel worker's retry-in-parent then crashes the parent too, so the whole
   scan exits -11 with no report.
2. **TypeScript syntax errors are not surfaced.** ex-16 (unclosed call in a
   `.ts` file) gives exit `0`, no `analysis_errors`, and no findings.
3. **Unparseable files outside the diff mark a `--diff-base` scan incomplete**
   (real-21 C++ fixture, real-36 Python 2 fixture) even though every changed
   file was analyzed. This may be intended, but it gates PRs on files they did
   not touch.

False negatives (seeded):

4. TypeScript: `exec(\`...${req.body.x}\`)` (ex-07), `res.send(\`<h1>${req.params.x}</h1>\`)`
   (ex-11), `res.sendFile(path.join(__dirname, ..., req.params.name))` (ex-13),
   and `prisma.$queryRawUnsafe` with a template literal (ex-06).
5. Flask `render_template_string('...' + request.args[...] + '...')` (mb-10).
6. `app.run(debug=True)` (mb-17); Starlette `CORSMiddleware(allow_origins=["*"],
   allow_credentials=True)` (fa-13); `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` (ex-17).
7. Secrets: `os.environ.get('X') or '<literal password>'` (mb-12), a 32-hex key
   fallback (mb-13), and an annotated class attribute `SECRET_KEY: str = "<48 hex>"` (fa-07).
8. SKY-L012 misses `from requests.retry import RetryPolicy` when `requests` is
   installed (mb-01). SKY-D224 misses an unknown keyword argument
   (`expires_in`) to installed `jwt.encode` (fa-05). The latter is outside the
   rule's documented scope, which covers only APIs that take no parameters.
9. SKY-L021 catches a removed decorator (mb-05) but not a removed ownership
   check (mb-04, fa-01), removed `dependencies=[Depends(...)]` (fa-02), removed
   Express `auth.required` middleware (ex-01), or a new unauthenticated
   destructive Express route (ex-02).
10. SKY-A101 detects skips but not weakened assertions (mb-18 d1/d2,
    fa-09 d1, ex-14 d1).

False positives:

11. SKY-D230 (open redirect) on `redirect(url_for('main.user', username=...))`
    (mb-07; the same pattern fires on unchanged microblog routes).
12. SKY-D216 (SSRF) when the host is constant or configured: the Microsoft
    Translator endpoint (mb-01), an S3 bucket URL builder (ex-10), FastAPI
    `TestClient.get` in tests (fa-c2), operator-configured URLs (real-10), and
    `curl "$url"` with script constants (real-10).
13. SKY-F102 ignores route-decorator `dependencies=[Depends(get_current_active_superuser)]` (fa-11).
14. SKY-U006 flags FastAPI `Depends()` parameters (fa-01, where following the
    advice would remove authentication) and `*args` required by an overridden
    interface (real-13, real-16).
15. SKY-D222 reports repository-local modules imported after `sys.path.insert`
    as hallucinated PyPI packages (real-03 `job_key`, real-18 `skill_frontmatter`).
16. SKY-D223 maps the repository's own `examples` package to the `tweepy`
    distribution (real-10), and does not read `requirements-*.txt` (real-05 `mlx`).
17. SKY-L012 reports `load_key`/`update_key` as phantom when they come from
    `from core.utils import *` and the package `__init__` imports them inside
    `try:` (real-13).
18. SKY-D207 flags `hashlib.md5(usedforsecurity=False)` (real-13). SKY-P401
    flags chunked `read(1024 * 1024)` loops (real-02, real-13).
19. SKY-D228 (XSS) on string concatenation with `"</search>"` in non-HTML model
    output handling (real-10).
20. SKY-U003 flags Storybook CSF story exports as unused variables (real-33).
21. SKY-D345 flags `datasets.load_dataset("json", data_files=<local path>)` as
    an unpinned Hub download (real-10).

Status after plan 3.8b (all fixes have regression tests):

- Fixed: 11 (`url_for`/`reverse`/`url_path_for` redirects are internal), 13
  (route-level and router-level `dependencies=[Depends(...)]` count as
  guards), 15 and 16 (repository modules made importable through `sys.path`,
  root namespace packages, and `requirements*.txt` variants, including in
  nested directories), 17 (star imports are resolved against local modules;
  names from an unresolvable star import are unknown, not phantom), 18
  (`usedforsecurity=False`; bounded `read(n)`), 19 (HTML detection requires a
  real HTML tag), 20 (Storybook `*.stories.*` exports and files), and 21
  (packaged `datasets` builders with local files).
- 12 fixed for Python and shell. Python SSRF now requires an untrusted source:
  a route, CLI or MCP-tool argument, request data, `input()`, `argv`, stdin,
  or an argument of a string-keyed command-dispatch handler. It also requires
  a host that the literal URL prefix does not fix. Environment variables are
  treated as operator configuration. In shell scripts, `$1` inside a function
  is tainted only when a call site passes untrusted data. The TypeScript S3
  URL builder (ex-10, axios) still fires. TypeScript is outside 3.8b's scope.
- 14 fixed for FastAPI (`Depends`/`Security` defaults, `Annotated[...,
  Depends()]`, and dependency aliases imported from other modules). `*args`
  required by an overridden interface (real-13, real-16) is **not** fixed. A
  blanket exemption for variadic parameters on subclass methods conflicted
  with the existing signature-contract rules, which deliberately report some
  of them, so it was reverted.


## Threats to validity

- **Author bias.** The Skylos project built the harness, chose the seeded
  categories, wrote the seeded cases and labeled every finding. The seeded
  categories include areas (dead code, hallucinated packages, weakened tests)
  that Semgrep CE and Bandit do not target. The injection and insecure-config
  categories, where the tools overlap, are a better basis for a head-to-head
  comparison.
- **Seeded realism.** The seeded defects are plausible agent mistakes written
  by hand, not mistakes observed in the wild. They are small, local, and
  mostly single-file. Real agent defects can be subtler or spread across files.
- **Small samples.** Two to seventeen defects per category, and 36 real
  commits. The confidence intervals overlap in most categories.
- **Single, non-blind labeler.** See [Labeling rules](#labeling-rules). The
  reasons are in `labels/findings.json` for audit.
- **Real-commit attribution.** Trailers and bot authors identify agent
  involvement, but a squash-merged PR may include human edits. The frame is
  popular repositories only, so commits in small or private projects are not
  represented.
- **Rule drift.** Semgrep registry packs are fetched live and are not
  versioned. `results/summary.json` records their SHA-256 digests. Skylos is
  measured at a specific working-tree state of this repository (digest
  recorded), and other work on `skylos/` was in progress while this ran.
- **Network-dependent rule.** SKY-D222 queries package registries. A package
  name that is registered later (for example, by a slopsquatter) would change
  the result.
- **No installed dependencies.** Rules that inspect installed packages behave
  differently when project dependencies are installed.
- **Scope rule.** Findings are counted on changed lines only (plus the
  defect-location window for seeded cases). A tool that reports a real problem
  one line outside the change gets no credit, and pre-existing issues are not
  measured.
- **Timing** comes from one machine, with one sequential run per workspace and
  no repetitions. Semgrep's time includes loading about 570 rules from YAML on
  every run. Skylos parses the whole repository in `--diff-base` mode, while
  Semgrep and Bandit parse only the changed files.

## Reproduce

From a checkout of this repository, with Skylos' dependencies installed
(`pip install -e .`):

```bash
benchmarks/agent-pr-bench/run.sh
```

`run.sh` creates a venv with `semgrep==1.178.0` and `bandit==1.9.4`, clones the
pinned commits into `$AGENT_PR_BENCH_WORK` (default `$TMPDIR/agent-pr-bench`),
applies the seeded cases, runs every tool on every workspace one at a time,
and writes `results/tables.md`, `results/summary.json`,
`results/findings.jsonl`, `results/runs.json` and `results/workspaces.json`.
Real-commit checkouts are deleted after their runs, keeping copies of the
changed files for the labeling worksheet. Add `--strict` to fail when any
in-scope finding has no label. That happens when a tool or rule version change
produces findings the checked-in labels do not cover. Label them with
`bench.py worksheet`.

To include SonarQube, start a SonarQube server, then:

```bash
export SONAR_HOST_URL=http://localhost:9000 SONAR_TOKEN=<token>
export SONAR_SCANNER=/path/to/sonar-scanner   # or put it on PATH
benchmarks/agent-pr-bench/run.sh
```

Offline harness tests: `python3 -m pytest benchmarks/agent-pr-bench/tests -q`.
