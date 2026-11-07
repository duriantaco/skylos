# Secrets scanning

`skylos . --secrets` performs local, static detection. A finding identifies a
credential-shaped value or exposure pattern; it does not establish that a service
accepted the credential. Scanning does not contact credential providers.

## Detection pipeline

1. Discover source/configuration files and a separate set of secret-bearing text
   files, including HTML, Markdown, text, PEM/key files and common SSH key names.
2. Match known provider formats and retain the existing generic credential checks.
3. Inspect bounded decoded text for provider signatures, including Base64,
   Base64URL, numeric Unicode escapes and HTML entities.
4. Apply the existing placeholder, public-key, checksum and context controls.
5. Prefer the provider classification when a generic finding describes the same
   credential occurrence. Keep distinct values, locations and larger credentials.
6. Report masked previews, original source locations and decoding evidence.

The general staged approach is informed by
[TruffleHog's process flow](https://github.com/trufflesecurity/trufflehog/blob/v3.99.8/docs/process_flow.md).
The implementation is independent. Provider formats are recognition inputs, not
proof of validity. For example, GitHub documents the
[`github_pat_` prefix](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github#githubs-token-formats);
Skylos recognizes its currently supported fine-grained form while preserving
existing classic-token behavior.

## Decoding and noise controls

Decoded text goes through provider-specific checks. Decoding does not lower the
generic entropy threshold or turn arbitrary encoded strings into findings.
Decoding evidence refers to the original encoded source and distinguishes nested
occurrences; it does not attach plaintext credentials to findings.

The default decoding depth is two transformations. Recursive candidate work and
decoded bytes are bounded, including shared limits across a file. Exhaustion is
reported as incomplete analysis, while ordinary raw detection continues. A limit
is not evidence that the unchecked content is safe. Binary UTF-16 files and
archive extraction are outside this text-decoding stage.

Masked previews remain available for review. Audit output also redacts
fine-grained GitHub tokens appearing in ordinary text or dictionary keys.

## Evaluation and remaining coverage

The [offline secrets benchmark](../benchmarks/secrets/README.md) uses deterministic,
non-issued credential shapes and benign controls. It compares the same files with
Skylos and an explicitly supplied TruffleHog binary, with remote verification and
update checks disabled. Detection, provider classification, duplicate alerts and
incomplete execution are reported separately. These cases do not establish
live-credential validity or production precision and recall.

Normal scans retain provider signatures in test paths. The internal
`ignore_tests=True` option remains an explicit opt-out. New document/key scopes
and native HTML scanning use provider-only detection: they retain known provider
formats and private-key material while avoiding generic entropy noise. Production
source/configuration generic checks and existing direct HTML checks keep their
behavior.

For synthetic test credentials, construct the value at runtime or use adjacent
string literals rather than storing a contiguous provider-shaped key in source.
The scanner does not infer safety from a test filename or fixture label.

Secret-only files do not require a Python or other language file in the project.
They do not enter language parsing or inflate source/AST counts. The JSON
`analysis_summary.secrets_files_scanned` counts files read and submitted to the
secret scanner, including empty files. Check analysis errors as well: decoding
limits can still make a submitted file incomplete. Selected new text that cannot
be read safely is reported as incomplete and does not increment the count.
Explicit exclusions, changed-file scope, containment and bounded no-follow reads
remain enforced.

This implementation does not add Git-history, cloud-storage or
collaboration-service collection.

Provider-side verification remains separate work. A future verifier should
distinguish success, rejected credentials, unavailable verification and a skipped
attempt. Failed or skipped verification must not erase a static candidate.
