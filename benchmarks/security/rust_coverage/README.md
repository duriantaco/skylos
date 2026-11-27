# Rust security coverage

Skylos detected at least one labeled example in 18 of the 20 security categories in GitHub's Rust query index. The two unmeasured categories cover invalid pointers and pointers used after their lifetime. Each measured category has a small number of examples. A supported category can still miss other Rust APIs or data flows. [GitHub's Rust query index](https://codeql.github.com/codeql-query-help/rust/)

## Generated cases

Each score requires the expected rule at the marked file and line. The baseline is `4ec7c5da`. Both scanners used the normal CLI at default confidence. The fixtures were read as source code.

| Suite | Expected warnings found | Safe sites quiet |
|---|---:|---:|
| Development cases, baseline | 7/34 | 20/20 |
| Development cases, final | 32/34 | 20/20 |
| Held-out cases, baseline | 4/17 | 18/19 |
| Held-out cases, first unseen run | 16/17 | 18/19 |
| Same cases after two fixes | 17/17 | 19/19 |

In the development cases, Skylos flagged single DES at the encryption call, one line after the marked constructor. The other miss was plain HTTP without credentials. The cleartext transport rule requires a sensitive value. On the first held-out run Skylos missed an unbounded TCP read into a string later parsed as a JSON array. It also warned about an integer string length written into HTML. Those two cases are now regression tests.

The case file preserves the original labels and the reviewed labels. Two development labels and one held-out label assumed that Actix decodes the raw URI query. Review of the API established that it returns the encoded query, so these sites count as quiet. The held-out set was sealed after the first development run. An evaluator also contributed to implementation. [Cases and labels](cases.json) · [Actix request query](https://docs.rs/actix-web/latest/actix_web/struct.HttpRequest.html#method.query_string)

To replay from the repository root using a Skylos executable installed from this checkout, run

```sh
python benchmarks/security/holdout_2026_11_26/replay.py skylos --cases benchmarks/security/rust_coverage/cases.json
```

## Published fixtures

These results compare Skylos output with the source and expected results at GitHub CodeQL revision `43fb30bb443c04731009218f39cba97cd93dd6fe`. This comparison used the published fixtures without running the CodeQL executable.

| Fixture | Result |
|---|---|
| TLS verification | 18/18 expected warnings and 5/5 safe sites quiet. A separate generated set gave 7/7 warnings and 8/8 safe sites quiet. [TLS fixture](https://github.com/github/codeql/tree/43fb30bb443c04731009218f39cba97cd93dd6fe/rust/ql/test/query-tests/security/CWE-295) |
| SQL injection | 27/33 expected warnings and 32/32 safe sites quiet. The six misses were one command-line input, two prepared statements that never ran, and three discarded streams or futures. Skylos also caught 5/6 additional cases marked as missing in the upstream fixture. [SQL fixtures](https://github.com/github/codeql/tree/43fb30bb443c04731009218f39cba97cd93dd6fe/rust/ql/test/query-tests/security/CWE-089) |
| Insecure cookies | Skylos caught 1/67 upstream alert sites, the one where an identifiable session cookie was issued. Two secure session controls stayed quiet. Of the other sites, 30 constructed or printed generic cookies, 31 issued generic cookies, three recorded an existing cookie, and two constructed and discarded session middleware. The Skylos rule currently covers identifiable outgoing session cookies. [Cookie fixture](https://github.com/github/codeql/tree/43fb30bb443c04731009218f39cba97cd93dd6fe/rust/ql/test/query-tests/security/CWE-614) |

## Blind repository replay

Repository commits and safe operations were labeled before comparing the two scanners. The ten fresh repositories were new to this Rust benchmark and included a web framework, CLI tools, a database driver, TLS and cryptographic libraries. The scans used a trusted empty config and read the original source without compiling or running it. [Pinned commits and labeled source locations](public-repos.json)

| Cohort | Repositories | Rust files in snapshots | Safe sites quiet on both | Files partially checked |
|---|---:|---:|---:|---:|
| Previous repository pins | 13 | 638 | 16/16 | 0 |
| Fresh general repositories | 7 | 157 | 15/15 | 1 |
| Fresh database, TLS and crypto repositories | 3 | 202 | 9/9 | 0 |

Across the ten fresh repositories, each scanner listed 112 other danger findings across all languages. One of those came from a changed Rust rule on both versions. These findings have no ground-truth labels. On the 13 repeated repositories, the same 20 raw review items appeared at the same locations and none reached the reporting threshold. Both scanners partially checked the same file in `ariadne`, outside the labeled controls.

These source labels measure noise at selected operations. Five of the nine specialist controls are in upstream tests. Three exercise a database driver the SQL rule does not model and two are in tests excluded by the TLS rule. The repository sets have no pre-labeled positive security cases from which to estimate real-world recall.
