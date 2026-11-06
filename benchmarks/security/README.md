# Security Benchmark

This benchmark suite measures deterministic Skylos security-analysis behavior against labeled fixtures.

It is intentionally separate from `/Users/oha/skylos-demo`. The demo repo is useful for whole-repo comparisons, but this suite is designed to produce precise TP/FP/FN/TN metrics for individual vulnerability classes and rule IDs.

## Metrics

- TP: an expected finding appeared.
- FN: an expected finding was missed.
- FP: a finding appeared where the manifest says it must be absent.
- TN: an absent expectation stayed quiet.
- Precision: `TP / (TP + FP)`.
- Recall: `TP / (TP + FN)`.
- F1: harmonic mean of precision and recall.

The benchmark uses two expectation modes:

- `present`: required findings. Missing these creates false negatives.
- `absent`: forbidden findings. Seeing these creates false positives.

Labels are scanner-independent ground truth: they describe the vulnerable or
safe behavior in the fixture, not the current Skylos output. Positive and
negative fixtures should be paired when a rule has realistic sanitizer or guard
logic.

Incomplete or malformed native scans are `UNSCORED` failures and contribute no
TP/FP/FN/TN. Scored/unscored counts and metric scope remain visible in comparisons.
With no valid cases, scores are zero and marked `no_valid_cases`. Bandit does not
need Skylos metadata, but its explicit errors and invalid payloads also fail.
Canonical `SKY-*` expectations match the finding's rule ID; a message or filename
containing that text cannot impersonate a rule.

## Run

```bash
python scripts/security_benchmark.py
python scripts/security_benchmark.py --json
python scripts/security_benchmark.py --case sql-tainted-param
python scripts/security_benchmark.py --scanner bandit
python scripts/security_compare_scanners.py
```

Competitor scanners are optional local tools, not project dependencies. If a
competitor such as Bandit is unavailable, the comparison script reports it as
skipped and still prints the Skylos scorecard. Python-only scanners are scored
only on Python cases; Go, Java, TypeScript, C#, Kotlin, PHP, Rust, and Dart cases are
reported as skipped for that scanner instead of being counted as false
negatives.

Each Skylos case is scanned as an isolated complete snapshot, including its own
workflow or config files. It does not inherit parent config, coverage or traces,
and does not request a Git comparison against a history the fixture does not have.

## Kotlin coverage

Twelve default Kotlin cases cover SQL interpolation/binding, shell commands,
fixed and request-controlled destinations, and path guards. They include seven
required findings and five safe controls, with lookalikes that must still report.
That Kotlin stage had 84 cases; all 72 earlier cases retain their
expectations. These are local request-source/API flow contracts, not deployed
applications or remote exploit proofs. Fixture programs are never executed.

One extra case remains in `adversarial_manifest.json`: a trusted standard
`printf` executable with fixed `%s` format and request data in a separate argument
is still reported as command injection. Its safe expectation remains unchanged.
This does not claim that arbitrary arguments to every fixed executable are safe.
The case follows the separate program/argument contract of
[ProcessBuilder](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/lang/ProcessBuilder.html)
and the fixed-format/data distinction documented for
[GNU printf](https://www.gnu.org/software/coreutils/manual/html_node/printf-invocation.html).

```bash
python scripts/security_benchmark.py \
  --manifest benchmarks/security/adversarial_manifest.json --json
```

That optional challenge currently exits nonzero to expose the known false
positive. Its label must not be changed just to obtain a passing score.

## Adding Cases

1. Add a minimal fixture under `benchmarks/security/fixtures/`.
2. Add a manifest entry in `benchmarks/security/manifest.json`.
3. Keep expectations rule-specific where possible.
4. Prefer one semantic claim per fixture.
5. Add both positive and negative cases for risky rule changes.

Current golden cases cover SQL injection, SSRF, command injection, YAML loader
precision, path traversal, XSS, open redirect, JWT verification bypass, and CORS
misconfiguration. The cross-language cases currently cover Go Zip Slip
path traversal, Java servlet path traversal, TypeScript unsafe eval, C# command
execution/SQL/SSRF/path/open-redirect flows, and PHP unsafe
deserialization/path traversal with matched safe guards.

### Additional paired controls

The default suite has 139 cases and 148 expectations: 74 required findings
and 74 absence controls. All 132 cases from the preceding stage retain their
original labels.

Rust now pairs its command finding with a fixed-command control and includes a
path-argument finding. Dart adds command unsafe/safe and path unsafe/basename
pairs. Ruby adds explicit Kernel command-string and shell-payload findings with
literal-command and fixed `printf`/literal `%s`/separate-data argument controls.
Other executable argument semantics remain unresolved.

Ruby provider overrides and dynamic selectors have separate unknown contracts
in `test/test_ruby.py`; they are deliberately excluded from ordinary safe
labels. This first Ruby engine does not claim Rails SQL, request provenance,
path, SSRF, or quality coverage. Cloud policy contracts have their own
[file/resource-based runner](../cloud/README.md), since application source-file
counts cannot validate Terraform-only inputs.

### TLS, hashes, randomness and logging

The 38 TLS/hash/randomness/logging cases contain 17 required warnings and 23
absence controls. They cover
TLS verification in Python and TypeScript, Python MD5/SHA1 use, security-sensitive
random values, and credentials reaching logs. Controls include real providers
and similarly named helpers, explicit nonsecurity hash use, strong generators,
redaction, response metadata, and container alias changes. An absence label
applies to the named rule, not every possible security property of the program.

The random-generator pairs exposed stale import identities after reassignment.
Both a weak provider replaced with `SystemRandom` and a `secrets` alias replaced
with `random.Random` now use the actual binding at the credential sink. Separate
tests cover local shadows, branches, later assignments and visible mutations.
Opaque replacements do not certify cryptographic safety. See Python's
[random](https://docs.python.org/3/library/random.html) and
[secrets](https://docs.python.org/3/library/secrets.html) provider contracts.
One direct imported-module method capture before alias rebinding remains a
documented miss in the [gap inventory](../GAPS.md), with its unsafe expectation
preserved as a strict expected-failure test.

The optional Bandit adapter maps B501 and B311 to the corresponding native rule
families. B324 maps to MD5/SHA1 only when its exact algorithm-specific message
identifies that hash. Ambiguous algorithms stay unmapped. Adapter tests use
recorded-format JSON; they do not establish a live Bandit comparison score.

Independent, pinned Ruby and Terraform facts have an
[offline runner](../holdouts/README.md). Those are selected upstream facts, not
additional synthetic cases or whole-repository accuracy labels.

Seven PHP/C# review cases add strict versus loose include guards,
attacker-controlled allowlists, actual Json.NET settings, data-only JSON and
harmless classes with serializer-like names. Dangerous providers still warn;
matching a local class/property spelling alone does not establish unsafe
deserialization. PHP loose comparisons remain conservative until operand types
are proved; strict literal allowlists and constant path maps remain supported.
