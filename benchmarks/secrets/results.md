# Offline secrets results — 2026-11-07

These are deterministic, non-issued credential shapes, with remote verification
disabled. They measure this small filesystem corpus, not live-secret validity or
general production precision and recall. Reproduce using the commands in
[README.md](README.md).

| Frozen original cohort | Positive detections | Safe controls quiet | Incomplete/errors | Extra duplicate alerts |
| --- | ---: | ---: | ---: | ---: |
| Skylos before scope fixes (`830f913f`) | 8/13 | 7/7 | 0 | 0 |
| Skylos after scope fixes | 13/13 | 7/7 | 0 | 0 |
| TruffleHog 3.99.8 | 12/13 | 7/7 | 0 | 0 |

All 12 GitHub-shaped positives now match in both tools. Skylos also detects the
generic dotenv password case. The five repaired native scope cases are
HTML, a Python test path, README, a text file and a key file. All detected provider
labels and reviewed source lines match. The original 20 inputs and expectations
are unchanged. The TruffleHog result reuses its earlier valid run against those
identical inputs; it was not rerun or used for the separate cohort below.

| Separate cross-language cohort | Positive detections | Safe controls quiet | Incomplete/errors |
| --- | ---: | ---: | ---: |
| Skylos before scope fixes (`830f913f`) | 5/8 | 8/8 | 0 |
| Skylos after scope fixes | 8/8 | 8/8 | 0 |

The separately frozen 16 cases cover `.ts`, `.tsx`, `.js`, `.mjs` and `.cjs`,
including three test-directory positives. Their expectations were fixed before
execution. They supplement the original cohort and are not mixed into its score.

Additional native and CLI regressions cover direct files and projects with no
language source file, actual successful secret-file counts, explicit exclusions,
changed paths, symlinks, FIFOs, invalid UTF-8 and oversized input. An independent
review passed 29 native cases. Unreadable selected inputs are incomplete, never
treated as successfully checked or as safe.

The after-run package SHA256 is
`cf16c6220d4df213d9ef5a065236482a2ad5dcaf13d2dbc5532fc7fed6bf570a`.
The original manifest SHA256 is
`b432c7071cd8c78dbdcc1e7e4d2543fc0344aba17c4bad97435aea6e88c76b14`.
The analyzer, harness and input hashes remained stable within each run. Raw
scanner output and synthetic fixture material remain in local `.skylos/` receipts;
no credential was verified or sent to a provider.
