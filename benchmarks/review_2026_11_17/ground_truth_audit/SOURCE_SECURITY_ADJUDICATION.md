# Source adjudication of the Python security competitor mismatches

All 39 mismatching fixture cases were reviewed from source, including every local helper/caller: 43 files. Original Bandit output, legacy benchmark expectations and raw scores remain unchanged. This is a postscan source review of authored development fixtures, not a fresh blind study.

This audit uses the preserved pickle-only corrected comparison arm. The later
final adapter additionally maps B307 eval correctly; its separate v2 output
has TP12/FP8/FN31/TN33. References below to the missing eval mapping describe
the audited arm, not the final code.

The raw comparison reported 32 false-negative expectation slots and 7 false-positive slots. Those numbers mix actual missed operations, unsupported capabilities, missing rule mappings, policy warnings and uncertain ground truth. They should not be presented as 32 independently confirmed missed vulnerabilities.

| Legacy bucket | Source adjudication | Cases |
| --- | --- | ---: |
| FN | Source-supported missed dangerous operation/configuration, including unsupported Bandit capabilities | 18 |
| FN | Exact operation detected; comparator lacks rule mapping | 4 |
| FN | Command sink detected under related rule; separate stronger-rule slot fails | 2 |
| FN | Policy fact without established vulnerability | 3 |
| FN | TLS monkey-patch depends on module import identity | 1 |
| FN | Legacy final TLS insecurity claim invalid | 1 |
| FN | Path traversal depends on platform/caller/routing assumptions | 2 |
| FN | Related bind-all policy warning present, stronger MCP auth claim unresolved | 1 |
| FP | Semantic false positive confirmed | 5 |
| FP | Broad RNG API warning on nonsecurity/discarded use | 2 |

Examples supporting the correction:

- `xss_mark_safe/app.py:5`: Bandit B704 reports the exact Markup interpolation. The adapter leaves B704 unmapped, so SKY-D226 expectation fails despite detection.
- `security_depth_python_eval_direct_unsafe/app.py:5`: B307 reports exact native eval on request text; no SKY-D201 mapping exists.
- `noise_python_hf_local_checkpoint_path/load.py:7` and `noise_python_hf_string_reference/load.py:5`: B615 reports unpinned Hugging Face operations, but SKY-D345 is unmapped. Remote-reference risk is conditional on caller input, not guaranteed by a string/Path annotation.
- `security_depth_python_command_direct_unsafe/app.py:6` and captured-provider variant `:7`: B602/B604 report the exact shell sink. They map SKY-D209; a separate SKY-D212 expectation remains unsatisfied. The warning exists, although it does not provide the same taint proof as SKY-D212.
- `tls_corpus_context_required_tampered/client.py:7`: the final `context.check_hostname=True` automatically changes CERT_NONE to CERT_REQUIRED in the native context. The fixture's preceding module-constant mutation does not bypass this native setter. A standard-library-only check confirmed state `{verify_mode:0, check_hostname:false}` changes to `{verify_mode:2, check_hostname:true}`; no target imported or network used. Python documents this behavior in [SSLContext.check_hostname](https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname). The legacy positive is not valid as a final-handler TLS-verification-disable ground truth.
- FastAPI `noise_python_path_prefix_match_name` and `noise_python_path_search_checked_name` use ordinary `{name}` routing, rather than `:path`. Regex checks are insufficient for arbitrary path strings, but the supplied fixture does not establish the described POSIX endpoint path escape. Windows backslash paths or an alternate caller change the analysis. FastAPI documents the separate path converter in [path parameters containing paths](https://fastapi.tiangolo.com/tutorial/path-params/#path-parameters-containing-paths). Keep these conditional until platform/routing assumptions are declared.

The five semantic false positives are constant-only SQL construction, a `random` alias rebound to `secrets.SystemRandom`, a `pickle` alias rebound to JSON, a source-owned UTF-8 decoder misidentified as pickle, and a source-owned method that returns text misidentified as subprocess. The other two warnings target `random` calls used only for retry delay or overwritten before the cookie sink; these are noise for security outcomes but match Bandit's broader risky-API policy.

An additional unscored false positive was found: B615 flags `noise_python_hf_local_checkpoint_path/load.py:11` despite explicit `local_files_only=True`. The legacy manifest only asks for the positive rule somewhere in that directory, so this safe-sibling error is invisible to its score. Exact-location negative controls prevent this loss of evidence.

The detailed JSON records each case, original mismatch, every raw finding, all source file hashes, adjudication, assumptions and primary references. No revised percentage is derived: a fair score needs explicit matched operation/rule semantics and adjudicated endpoint/control assumptions first. Missing mappings must be corrected without treating import-only or generic warnings as proof of unrelated taint claims.
