# Secrets scanning

`skylos . --secrets` performs local, static detection. A finding identifies a
credential-shaped value or exposure pattern; it does not establish that a service
accepted the credential. Scanning does not contact credential providers.

## Detection pipeline

1. Discover source/configuration files and a separate set of secret-bearing text
   files, including HTML, Markdown, text, PEM/key files and common SSH key names.
2. Match known provider formats, complete structured credentials and private JWK
   material, retaining the existing generic credential checks.
3. Inspect bounded decoded text for provider signatures, including Base64,
   Base64URL, percent encoding, JSON string escapes, numeric Unicode escapes and
   HTML entities. Structured records retain their sibling-field context.
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
is not evidence that the unchecked content is safe. A Base64 carrier containing
BOM-led UTF-16 consumes two transformation slots and charges both intermediate
and final decoded bytes. Percent decoding preserves literal `+` characters and
rejects malformed escapes and invalid UTF-8. Provider and structured-credential
validators inspect decoded views; generic entropy is not broadened.

Secret/configuration text files support strict BOM-led UTF-16LE and UTF-16BE.
Unmarked binary fragments are not combined or interpreted as guessed byte orders.
The existing read cap applies to original file bytes. Malformed UTF-16 and
unsupported UTF-32 marks produce incomplete analysis. Findings from these files
include `source_encoding`; their line/column positions refer to the interpreted
text. Language parsing retains its existing encoding support. Archive extraction
is separate from text decoding.

Masked previews remain available for review. Audit output also redacts
fine-grained GitHub tokens appearing in ordinary text or dictionary keys.

## Provider depth and precision

The independently specified provider profiles cover npm, PyPI, DigitalOcean,
Hugging Face, additional GitLab token families, Stripe restricted/organization
keys, and Slack/GovSlack incoming webhook URLs. Existing provider checks remain.
Routed GitLab credentials are retained as complete occurrences, including their
dot-separated fields. Public Stripe publishable keys are not made secret findings.

Profiles use issuer documentation, not another scanner's expressions:

- [npm](https://api-docs.npmjs.com/) documents a fixed 36-character alphanumeric
  payload after its prefix.
- [PyPI](https://docs.pypi.org/api/secrets/#detecting-the-pypi-secret-format)
  documents a Base64URL Macaroon payload with a minimum length. Recognition does
  not impose an arbitrary upper token length or prove issuance.
- [GitLab](https://docs.gitlab.com/security/tokens/#token-prefixes) identifies its
  token families; [routable tokens](https://handbook.gitlab.com/handbook/engineering/architecture/design-documents/cells/routable_tokens/)
  contain additional fields. Custom instance prefixes remain a coverage limit.
- [DigitalOcean](https://docs.digitalocean.com/reference/api/reference/dedicated-inference/)
  and [Hugging Face](https://huggingface.co/docs/hub/security-tokens) document
  identifying prefixes. The selected hexadecimal/alphanumeric body profiles are
  conservative recognition heuristics, not permanent format guarantees.
- [Stripe](https://docs.stripe.com/keys) distinguishes secret, restricted and
  organization keys from public publishable keys. [Slack](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/)
  documents credential-bearing webhook URLs. Matching checks the actual host and
  service path, including GovSlack, rather than a hostname inside a lookalike URL.

AWS access-key detection distinguishes `AKIA`/`ASIA` from public IAM resource
identifiers. [AWS's identifier table](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html)
identifies the group/user/role/profile prefixes. Existing broad output masking
is preserved even where credential classification becomes narrower.

## Structured credentials and private keys

Structured checks require literal fields in one complete record. They do not
pair arbitrary nearby identifiers and secrets or execute the scanned program.

- Azure Storage connection strings require an account name and canonical Base64
  account key representing 512 bits, within one semicolon-delimited string.
  The exact published Azurite emulator key is excluded. An emulator account name
  does not exempt a different key. See [Microsoft's connection-string format](https://learn.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string)
  and [account-key documentation](https://learn.microsoft.com/en-us/azure/storage/common/storage-account-keys-manage).
- AWS credential pairing uses direct JSON siblings or a single INI profile. A
  temporary `ASIA` record also requires a session token. Existing standalone
  access-key and secret-key checks remain; their pairing evidence contains
  component locations without literal values. Project-local `.aws/credentials`
  and `.aws/config` enter the bounded secrets collector with provider-only
  detection. Scanning a repository does not read the user's home credentials.
  See [AWS's shared credentials/config formats](https://docs.aws.amazon.com/sdkref/latest/guide/file-format.html).
- Google service-account JSON requires the service-account type, matching record
  fields and a complete structurally recognized RSA private key. The record
  enriches its existing private-key alert instead of adding another alert.
  See [Google's service-account key format](https://cloud.google.com/iam/docs/keys-create-delete).
- Private JWK detection supports RSA (including its optional complete CRT
  group), EC P-256/P-384/P-521, OKP Ed25519/Ed448/X25519/X448 and symmetric `oct`
  keys of at least 128 bits. Public-only keys do not become findings. Canonical
  Base64URL, required members, supported widths and scalar/component constraints
  reduce lookalike matches. Profiles follow [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-6)
  and [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html#section-2).

The private-key helper recognizes supported PKCS1, SEC1, PKCS8 and encrypted
PBES2 container structure for record evidence. This does not prove issuer
acceptance, complete mathematical key validity or successful decryption. An
unrecognized structure never suppresses a legacy PEM finding. OpenSSH and other
legacy private-key detection retain their existing behavior.

Structured findings use `structured_credential` for safe evidence. Parsing and
record-count limits produce incomplete analysis; ordinary raw checks continue.
Distinct decoded records keep separate source paths even when their outer
encoded container occupies the same source columns. Audit and CI redaction also
mask private JWK fields in truncated display snippets, without weakening the
complete-record requirements used to create findings.

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
