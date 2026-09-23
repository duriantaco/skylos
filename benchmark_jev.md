# Jev dead-code benchmark: four-way comparison

Run on 2026-09-22 from the main Skylos checkout. The frozen `hard_suite_59`
has 59 labeled Python functions across five synthetic projects: 28 truly
unused and 31 truly used. It combines 40 newly authored labels with the
earlier 19-label dispatch challenge. The manifest SHA-256 is
`7c5e5b981914f7771efd222bfdf99e8782c5ab900ab4b56b9d43d75bc165ba90`.

**Current-code follow-up:** after two safety fixes (preserving deterministic
suppression audits and preventing Jev-only "used" decisions from suppressing
other findings transitively), a separate paid **judge-only** run scored
**51/59 (86.4%)**: TP=22, FP=2, FN=6, TN=29, with 8 broad LLM calls and
15,023 broad LLM tokens. Its raw report is
`jev-dead-code-hard-suite-59-judge-only-final-20260922-results.json`.
This is the result for the final implementation, **not a paired four-arm
comparison**. The four-arm table below is the earlier, pre-safety-fix run.
Both reports used the same frozen source and labels; hosted-model answers
varied between runs, so the score change cannot be assigned to the fixes.

## Total accuracy

Accuracy is **(true positives + true negatives) / all 59 frozen labels**;
"unused" is positive. A symbol Skylos never flags still counts: it is a
false negative if truly unused, or a true negative if truly used. All 53
static candidate findings have labels. The other six labels are directly
referenced live callbacks, absent from the static candidate set.

| Arm | Correct / 59 | Accuracy | TP | FP | FN | TN | F1 | Broad LLM calls | Broad LLM tokens |
| :-- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |
| Pure Skylos (no LLM, no Jev) | 34 / 59 | **57.6%** | 28 | 25 | 0 | 6 | 69.1% | 0 | 0 |
| Skylos + LLM only | 41 / 59 | **69.5%** | 24 | 14 | 4 | 17 | 72.7% | 41 | 81,652 |
| Skylos + Jev precheck + LLM | 40 / 59 | **67.8%** | 24 | 15 | 4 | 16 | 71.6% | 36 | 62,933 |
| Skylos + Jev judge + LLM fallback (before safety fixes) | 52 / 59 | **88.1%** | 23 | 2 | 5 | 29 | 86.8% | 10 | 17,137 |

These four rows come from **one paid run of the same frozen labels and source
bytes**. In that run, Jev judge improved the total by 11 labels / 18.6
percentage points over LLM-only. Broad LLM calls fell from 41 to 10 and broad
LLM tokens from 81,652 to 17,137. The current-code follow-up had 8 calls and
15,023 tokens, but has no same-run LLM-only arm. These counters **exclude Jev
API usage**, so they are not a net price or total-token comparison. The judge arm also omits broad-LLM
entry discovery, the Haiku prefilter, and survivor challenge for candidates
Jev has decided; the result is a whole-policy comparison, not an isolated
estimate of Jev's model quality.

The earlier three-arm run, retained in
`jev-dead-code-hard-suite-59-live-20260922-results.json`, gave 40/59 (67.8%)
for both LLM-only and the precheck. Its scores differ slightly from this
run; do not mix rows across runs when comparing policies. Likewise, an
earlier Jev-only accuracy/coverage number was **not** the accuracy of the
end-to-end Skylos+LLM pipeline: precheck used Jev only to route candidates,
and the broad LLM could still make the final wrong call.

## What Jev decided—and missed

The old `--jev-precheck` mode accepts only confident Jev agreement that a
static candidate is unused; all other candidates go to the broad LLM.
The new, opt-in `--jev-judge` mode accepts Jev's confident **used or unused**
answer as final for the dead-code report. It requires both Jev's confidence
and its chosen-answer probability to be at least 0.9. Uncertain answers,
unavailable Jev, and ineligible/unsafe inputs fall back to the broad LLM.
Jev never deletes code, and a Jev-only unused decision is not eligible for
automatic `--fix`.

In the paired run, of the 53 static candidates in the judge arm, Jev confidently marked 12 as
unused and 27 as used; 14 fell back as uncertain. All 12 Jev-unused answers
were correct, and 23 of the 27 Jev-used answers were correct. The **four
confidently wrong "used" answers hid four truly unused symbols**. On the 14
uncertain candidates, the broad-LLM path reported 11 of 12 truly unused
symbols and incorrectly reported both truly used symbols. That yields five
false negatives and two false positives overall. A high confidence threshold
is therefore **not** a correctness guarantee; judge mode trades recall for
much higher precision on this suite (92.0% precision, 82.1% recall).

In the current-code follow-up, Jev confidently marked 10 as unused (all
correct) and 28 as used (23 correct, **five wrong**), leaving 15 uncertain.
The fallback missed one truly unused symbol and reported two truly used
symbols. Thus the final implementation's 51/59 score has 91.7% precision and
78.6% recall. The five confident Jev "used" errors are a material limitation.

| Case | Labels | Pure Skylos | + LLM | + Jev precheck + LLM | + Jev judge + fallback |
| :-- | --: | --: | --: | --: | --: |
| Reachable state flow, with a disconnected chain | 14 | 7/14 | 9/14 | 8/14 | 9/14 |
| Indirect module/function pair matrix | 14 | 7/14 | 7/14 | 7/14 | 14/14 |
| Closed callback table and sequence | 12 | 12/12 | 12/12 | 12/12 | 12/12 |
| JSON-configured command routing | 10 | 4/10 | 4/10 | 4/10 | 8/10 |
| Constructed event callback names | 9 | 4/9 | 9/9 | 9/9 | 9/9 |

The main gain is suppression of live module-pair functions that the general
LLM reported as dead. The JSON-configured case still has two live handlers
incorrectly reported in judge mode; the state-flow case has five missed
unused functions. The aggregate 88.1% must not obscure those failures.

On the final-code follow-up, case accuracies were 8/14 state flow, 13/14
module matrix, 12/12 closed callbacks, 9/10 JSON-configured routing, and
9/9 constructed event callbacks. That run is separate from the paired table.

## Expanded repository-style suite (v2; no paid results yet)

The new frozen-development manifest
`benchmarks/dead_code/jev_hard_suite_v2_manifest.json` expands the suite to
**125 labels across eight cases** (59 truly unused, 66 truly used), adding
66 labels in three source-only repository-style projects:

| New case | Labels | Known-unused / known-used | Static Skylos correct | Static false positives |
| :-- | --: | --: | --: | --: |
| Cross-file workflow, JSON dispatch, and plugin registry | 32 | 16 / 16 | 16/32 | 16 |
| Installable package with TOML entry points, packaged JSON, and tests | 16 | 6 / 10 | 12/16 | 3 |
| Async event queue with finite published topics | 18 | 9 / 9 | 9/18 | 9 |

The **no-model baseline** on all 125 labels is **71/125 (56.8%)**: TP=58,
FP=53, FN=1, TN=13. In the package case, static Skylos flags three actually
reachable entry-point/config handlers and misses one transitive dead helper
that is called only by another dead function. The other two new cases put
balanced live/dead symbols behind finite config or event dispatch, rather
than treating every definition with no direct text call as dead.

This is a **local static result only**. There is no v2 LLM-only, Jev-router,
or Jev-judge score yet, and the 59-label paid results above must not be
presented as v2 results. V2 uses each case's declared `scan.confidence=0` and
`grep_verify=true`; the historical paid 59-label runner actually used
confidence 60 (and grep verification enabled), so even the older cases are
not guaranteed to have identical policy in a new run. The v2 manifest digest
is `a4ef654fcfb4f1d0eba4915d800419f44b589b28efea8e41274c020624fb3c5e`.

The hardened runner checks before any paid request that every static candidate
maps to exactly one label, rejects duplicate/ambiguous matches, compares
candidate inventories across arms, and records the effective scan policy,
source digest, and candidate inventory digest. Tests also derive the new
fixtures' reachability sets from their config, package metadata, and source
structure without executing the fixture. These remain small, public synthetic
repos under Jev's 64 KB complete-snapshot limit, **not a real-world holdout**.
The Jev-only offline plan finds 125 blind decisions in eight original-arm
requests. Identifier neutralization is marked `not_applicable` for all eight
cases because the current neutralizer finds no answer-signaling identifier
words to rewrite. Lexical robustness is therefore not measured by a
neutralized arm here. The new
fixtures deliberately avoid the old used/dead declaration alternation.

To inspect the expanded suite without either API key:

```bash
python scripts/jev_cascade_benchmark.py \
  --manifest benchmarks/dead_code/jev_hard_suite_v2_manifest.json \
  --expect-manifest-digest a4ef654fcfb4f1d0eba4915d800419f44b589b28efea8e41274c020624fb3c5e
python scripts/jev_cascade_benchmark.py --static-only \
  --manifest benchmarks/dead_code/jev_hard_suite_v2_manifest.json \
  --expect-manifest-digest a4ef654fcfb4f1d0eba4915d800419f44b589b28efea8e41274c020624fb3c5e \
  --output jev-dead-code-hard-suite-v2-static-results.json
```

The completed local baseline report is
`jev-dead-code-hard-suite-v2-125-static-20260922-results.json` (ignored,
not committed). A future paid four-arm run should use a new output path and
pin the manifest digest above; it will incur both TypeSafe and OpenAI usage.

## Method and reproducibility

Each arm scans an isolated copy of the **same source bytes** with the same
static scanner. The LLM-only arm uses the `gpt-4.1` verifier. Both Jev arms
use pinned `jev-1.13.0` before any broad LLM call. Paid arms use
`judge_all`, `max_verify=50`, and `max_challenge=20` per case. This matches
`skylos agent verify`'s default verification mode but not every ordinary scan
configuration. Neither arm executes fixture code or auto-deletes symbols.

Source files are small, synthetic, and contain no secrets. Ground-truth
labels and manifest descriptions are joined locally after inference and are
not sent to either model. The 19 older labels were previously probed, and
the 0.9 judge threshold was chosen after inspecting an earlier run on this
suite. **This is an in-sample policy comparison, not an untouched holdout or
an estimate of production accuracy.** It is one run, not a confidence
interval. There is also ordinary hosted-model run-to-run variation.

To reproduce, use a Python environment with `.[llm]` installed and set
`TYPESAFE_API_KEY` and `OPENAI_API_KEY` in the environment for the paid run;
do not pass keys as command arguments or commit them. From the repository
root:

```bash
python scripts/jev_cascade_benchmark.py \
  --manifest benchmarks/dead_code/jev_hard_suite_manifest.json
python scripts/jev_cascade_benchmark.py --static-only \
  --manifest benchmarks/dead_code/jev_hard_suite_manifest.json \
  --output jev-dead-code-hard-suite-static-results.json
python scripts/jev_cascade_benchmark.py --live \
  --manifest benchmarks/dead_code/jev_hard_suite_manifest.json \
  --output jev-dead-code-hard-suite-live-results.json
python scripts/jev_cascade_benchmark.py --live --judge-only \
  --manifest benchmarks/dead_code/jev_hard_suite_manifest.json \
  --output jev-dead-code-hard-suite-judge-only-results.json
```

The four-arm raw report is
`jev-dead-code-hard-suite-59-judge-live-20260922-results.json`; the final-code
judge-only report is named above. Both are ignored local artifacts, not
committed benchmark claims. Both have
`status=complete` and the manifest digest above. The current local `.venv`
uses Python 3.14 without `litellm`, so this paid run used a separate Python
3.13 environment with `.[llm]`. That environment and source copies were
temporary; the runner, fixtures, and this report are in the main checkout.
Broad-LLM token and timing figures do not include TypeSafe's billable usage
or isolate server-side latency.
