# Real-World Skylos Results

**21 dead-code cleanup PRs merged into the default branch in 19 open-source projects.**

This page records 43 Skylos-assisted cleanup and quality-fix pull requests
we opened in 38 open-source projects between March and November 2026, including
the PRs that were closed, reverted, never reached the default branch or are
still waiting. It covers these cleanup contributions, not our unrelated
feature work or submissions to tool directories.

These are maintainer decisions on cleanup PRs. These contributions do not
establish that any listed project endorsed or adopted Skylos; a merged PR
does not mean a project uses it.

PR states, merge targets, closure actors and linked maintainer reviews were
checked on GitHub on 16 November 2026. The default-branch total excludes the
known Glances revert and the Flagsmith/yfinance merges outside their default
branches below. This records merge outcomes, not a fresh audit
of whether every removed symbol remains absent from the current code.

| Outcome | PRs |
|:---|---:|
| Default-branch dead-code merges (excluding the known revert) | 21 (19 projects) |
| Merged outside the default branch; the change has not reached `main` | 2 |
| Merged: other fix (mutable default arguments) | 1 |
| Merged, then reverted by the maintainer | 1 |
| Closed by a maintainer | 4 |
| Closed by us | 8 |
| Still open | 6 |
| **Total** | **43 (38 projects)** |

## How the candidates were found

- Every PR started from a Skylos static scan of the project.
- For at least 9 of the original 26 PRs, including both Black PRs, pdm and
  isort, we also triaged the findings with `skylos agent verify`, which uses an LLM
  (we used Anthropic's) to review each static finding against the code. Our
  notes do not record the method for every PR.
- The descriptions of the 17 newly recorded PRs opened in November credit
  deterministic Skylos scans and report no AI use by the submitter.
- We checked each candidate by hand before opening a PR. That did not catch
  everything: one merged PR broke the project and was reverted, and a
  maintainer's review of another found a `NameError` on startup (both below).
- Most raw findings did not make it into a PR. In our notes, isort went from
  88 findings to 1 removal, and celery from 300 findings to 56 confirmed, of
  which 15 went into the PR.

## Dead-code cleanups merged into the default branch

| Project | PR | Merged | Final GitHub diff | What was removed |
|:---|:---|:---|:---|:---|
| Black | [psf/black#5041](https://github.com/psf/black/pull/5041) | 2026-03-11 | 3 files, +0, −24 | unused internal parsing/node helpers |
| pypdf | [py-pdf/pypdf#3685](https://github.com/py-pdf/pypdf/pull/3685) | 2026-03-16 | 1 file, +0, −4 | unused reverse encoding dictionaries |
| mitmproxy | [mitmproxy/mitmproxy#8136](https://github.com/mitmproxy/mitmproxy/pull/8136) | 2026-03-18 | 8 files, +2, −44 | unused console helpers, bit utilities and stale imports; we put `save_settings()` back during review |
| NetworkX | [networkx/networkx#8572](https://github.com/networkx/networkx/pull/8572) | 2026-03-18 | 5 files, +1, −31 | an unused private function and imports |
| Optuna | [optuna/optuna#6547](https://github.com/optuna/optuna/pull/6547) | 2026-03-23 | 5 files, +2, −37 | unused helper functions, a method, a constant and unpacked variables |
| Black | [psf/black#5052](https://github.com/psf/black/pull/5052) | 2026-03-29 | 3 files, +0, −36 | unused token helpers, parser debug methods and a stale attribute |
| beets | [beetbox/beets#6473](https://github.com/beetbox/beets/pull/6473) | 2026-03-30 | 4 files, +0, −38 | unused plugin helpers and a dead database type |
| pdm | [pdm-project/pdm#3774](https://github.com/pdm-project/pdm/pull/3774) | 2026-04-30 | 8 files, +2, −47 | unused classes, constants and a method; the maintainer asked us to keep `Version.MIN`/`Version.MAX`, which we restored before merge |
| isort | [PyCQA/isort#2525](https://github.com/PyCQA/isort/pull/2525) | 2026-04-30 | 1 file, +0, −3 | an unused `_ENCODING_PATTERN` regex and its `re` import |
| react-error-boundary | [bvaughn/react-error-boundary#243](https://github.com/bvaughn/react-error-boundary/pull/243) | 2026-06-20 | 7 files, +0, −102 | unused docs and Vite integration helpers (TypeScript) |
| rembg | [danielgatis/rembg#863](https://github.com/danielgatis/rembg/pull/863) | 2026-11-02 | 2 files, +0, −7 | an unused `IO` import and embedding dictionary |
| Buzz | [chidiwilliams/buzz#1691](https://github.com/chidiwilliams/buzz/pull/1691) | 2026-11-02 | 21 files, +2, −46 | unused imports, constants, class attributes and local variables |
| packaging | [pypa/packaging#1488](https://github.com/pypa/packaging/pull/1488) | 2026-11-04 | 1 file, +0, −7 | unused `_DICT_FIELDS` and `_NOT_FOUND` constants |
| Supervision | [roboflow/supervision#2865](https://github.com/roboflow/supervision/pull/2865) | 2026-11-04 | 3 files, +0, −34 | two private metric helpers and an unloaded docs script; merged into `develop`, its default branch |
| Altair | [vega/altair#4204](https://github.com/vega/altair/pull/4204) | 2026-11-05 | 4 files, +0, −37 | unused import-availability, Sphinx and tooling helpers/constants |
| pipenv | [pypa/pipenv#6776](https://github.com/pypa/pipenv/pull/6776) | 2026-11-05 | 12 files, +9, −146 | unused functions and unpacked variable bindings |
| Locust | [locustio/locust#3586](https://github.com/locustio/locust/pull/3586) | 2026-11-05 | 6 files, +2, −97 | unused exception/event classes, a docs helper and two web UI components |
| Maigret | [soxoj/maigret#3315](https://github.com/soxoj/maigret/pull/3315) | 2026-11-06 | 10 files, +6, −50 | unused imports, functions and variables; also fixed the stale `QueryStatus` import that broke `site_check.py` |
| tomlkit | [python-poetry/tomlkit#703](https://github.com/python-poetry/tomlkit/pull/703) | 2026-11-06 | 1 file, +0, −50 | unused `_NOT_SET` and `Container._insert_after` |
| Tortoise ORM | [tortoise/tortoise-orm#2399](https://github.com/tortoise/tortoise-orm/pull/2399) | 2026-11-07 | 3 files, +29, −31 | unused unpacked bindings and dictionary keys; maintainer refactors included and `_RED` restored; merged into default branch `develop` |
| Tortoise ORM | [tortoise/tortoise-orm#2397](https://github.com/tortoise/tortoise-orm/pull/2397) | 2026-11-09 | 5 files, +133, −122 | `_convert_second_fraction` and empty `BasePostgresPool`; docs formatting and Ruff configuration changes included; merged into default branch `develop` |

Total final GitHub diff across these 21 PRs:

| PRs | Files changed | Additions | Deletions | Net change |
|---:|---:|---:|---:|---:|
| 21 | 113 | 188 | 993 | −805 |

These are full PR diffs, including tests, changelogs, formatting and other
edits, not a count of dead lines removed. Maigret combines cleanup with a
functional fix. The Tortoise PRs were split at the maintainer's request;
[#2399's final changes](https://github.com/tortoise/tortoise-orm/pull/2399#issuecomment-6701895597)
include maintainer refactors and
[restoration of the `_RED` constant](https://github.com/tortoise/tortoise-orm/pull/2399#issuecomment-6700243147).

## Merged outside the default branch

- [Flagsmith/flagsmith#6953](https://github.com/Flagsmith/flagsmith/pull/6953)
  (10 files, +0, −56: unused exceptions, serializers, response classes and
  helper code) was merged on 2026-03-16 into `chore/remove-dead-code`, a
  branch in Flagsmith's own repository. The maintainer moved it there so the
  project's CI could run, and noted that some of the code might be needed by
  private packages installed at build time. The follow-up PR from that branch
  to `main`, [#6955](https://github.com/Flagsmith/flagsmith/pull/6955), was
  approved by another maintainer and then closed unmerged on 2026-03-23, with
  no reason posted. The change did not reach `main`, so it is not in the
  count above.
- [ranaroussi/yfinance#3032](https://github.com/ranaroussi/yfinance/pull/3032)
  (3 files, +0, −45: unused cache dummy classes and holder URL constants)
  was merged on 2026-11-15 into `dev`. Its default branch is `main`, where
  the removed cache dummy classes were still present when checked on
  2026-11-16. The merge commit has
  [not reached `main`](https://github.com/ranaroussi/yfinance/compare/8dde0cec8a8cbeabedf1126a8ebd4ae07047c15b...main),
  so this accepted cleanup is recorded separately from the default-branch total.

## Other merged fix

| Project | PR | Merged | Final GitHub diff | What changed |
|:---|:---|:---|:---|:---|
| MechanicalSoup | [MechanicalSoup/MechanicalSoup#473](https://github.com/MechanicalSoup/MechanicalSoup/pull/473) | 2026-07-24 | 3 files, +21, −6 | mutable default arguments replaced with `None`; a quality fix, not dead code, so it is not in the count above |

## Merged, then reverted

- [nicolargo/glances#3507](https://github.com/nicolargo/glances/pull/3507)
  (5 files, +5, −88) was merged on 2026-04-04 and reverted by the maintainer
  the same day (commit
  [f72edef](https://github.com/nicolargo/glances/commit/f72edef56a9759b5824fead73bd0462d5298df51)).
  The maintainer wrote: "Sorry @duriantaco but i have to revert your commiy
  because it brak Glances (Lot's of indentation issues)."
  Our corrected version, [#3515](https://github.com/nicolargo/glances/pull/3515),
  was left with only a whitespace change after we resolved conflicts with
  `develop`, so we closed it. A smaller follow-up,
  [#3517](https://github.com/nicolargo/glances/pull/3517), got no response and
  we closed it too.

## Closed by a maintainer

- [pallets/flask#5946](https://github.com/pallets/flask/pull/5946)
  (3 files, −15): closed by a maintainer the same day, without a comment.
- [Point72/csp#690](https://github.com/Point72/csp/pull/690)
  (14 files, +3, −32): "If you would like to contribute to the project,
  please work on a pressing issue. An AI generated PR like this which doesn't
  provide utility to the library (and also does not follow our lint rules)
  will not be approved."
- [justrach/turboAPI#54](https://github.com/justrach/turboAPI/pull/54)
  (6 files, +16, −156; as opened, it also changed exception handling and
  debug prints): the maintainer's review found that the PR removed imports
  still used in more than 20 places, which would raise a `NameError` on
  startup. We fixed that,
  and the PR was then closed: "The branch is stale enough that the code marked
  as dead is no longer safely dead on current main, and there are no reported
  CI checks on the submitted branch."
- [crewAIInc/crewAI#5002](https://github.com/crewAIInc/crewAI/pull/5002)
  (12 files, +2, −682): closed by a maintainer without a comment.

## Closed by us

- No maintainer response:
  [spotify/luigi#3408](https://github.com/spotify/luigi/pull/3408) (closed
  after almost three months),
  [excalidraw/excalidraw#11000](https://github.com/excalidraw/excalidraw/pull/11000)
  (two months) and
  [joerick/pyinstrument#440](https://github.com/joerick/pyinstrument/pull/440)
  (three weeks).
- [httpie/cli#1836](https://github.com/httpie/cli/pull/1836): we closed it 13
  minutes after opening it.
- [celery/celery#10200](https://github.com/celery/celery/pull/10200):
  replaced by #10201 a few minutes later (its title was a pasted `git commit`
  command).
- [celery/celery#10201](https://github.com/celery/celery/pull/10201)
  (8 files, +21, −42): we closed it unmerged on 2026-11-02, with no closure
  reason posted. During the PR we put back the `asynpool.py` removals:
  those methods override `multiprocessing.pool.Pool` internals that run
  during worker shutdown, and Skylos could not trace calls into the
  standard library's parent classes.
- [nicolargo/glances#3515](https://github.com/nicolargo/glances/pull/3515) and
  [#3517](https://github.com/nicolargo/glances/pull/3517): see "Merged, then
  reverted".

## Still open

- [pypa/twine#1316](https://github.com/pypa/twine/pull/1316)
  (3 files, +1, −9), open since 2026-04-30: approved by woodruffw on
  9 May 2026, who noted that both removed names are technically public API,
  and [approved by sigmavirus24 on 4 November](https://github.com/pypa/twine/pull/1316#pullrequestreview-5767929233).
  It remains unmerged despite both approvals.
- [docling-project/docling#5137](https://github.com/docling-project/docling/pull/5137)
  (7 files, +0, −73), open since 2026-11-02: private helper cleanup.
  Changes were requested on 13 November; the reviewer
  [asked whether `_select_best_cluster()` is needed downstream by `docling-inner`](https://github.com/docling-project/docling/pull/5137#discussion_r4560023765).
  That question remains unresolved in the published discussion.
- [piccolo-orm/piccolo#1452](https://github.com/piccolo-orm/piccolo/pull/1452)
  (3 files, +0, −14), open since 2026-11-02: unused trigger/migration helpers
  and a dataclass.
- [fishaudio/fish-speech#1370](https://github.com/fishaudio/fish-speech/pull/1370)
  (10 files, +2, −65), open since 2026-11-01: unused imports, schema classes,
  a conversation helper and constants.
- [NanmiCoder/MediaCrawler#997](https://github.com/NanmiCoder/MediaCrawler/pull/997)
  (41 files, +20, −446), open since 2026-11-01: unused imports and obsolete
  scraping/signing helpers.
- [robotframework/robotframework#5851](https://github.com/robotframework/robotframework/pull/5851)
  (2 files, +0, −9), open since 2026-11-06: three unused private methods.

## What the misses taught us

- Public API is not dead code just because nothing in the repository calls
  it (twine, pdm).
- A public repository may not show every caller: a maintainer warned that
  private packages installed at build time might use code we removed
  (Flagsmith).
- Private names can also raise downstream compatibility concerns: Docling's
  reviewer asked whether a private helper was needed by `docling-inner`.
- A stale branch can make dead code live again. Re-check the findings on
  current main on the day you submit (turboAPI).
- Run the project's formatter, linters and tests before submitting (glances,
  csp).
- Overrides of standard-library or third-party base classes can look unused
  to a static scan (celery).
- Some maintainers do not want unsolicited AI-assisted cleanup PRs (csp).

## What this does and does not show

- It supports Skylos as a practical way to find dead-code candidates in
  mature projects, when a person checks every candidate before acting on it.
- It does not show that every finding is correct: many raw findings were
  false positives or not worth removing.
- It does not show that Skylos is better than other analyzers.
- It does not mean the listed projects use Skylos.

The suites in [BENCHMARK.md](./BENCHMARK.md) are checked-in regression gates,
not independent benchmarks.
