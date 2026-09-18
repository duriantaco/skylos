# Container-image vulnerability scanning

Skylos can run an installed Trivy scanner for a built container image, then
show its reported vulnerabilities as JSON or SARIF:

```bash
skylos image scan "$IMAGE_REF" \
  --platform linux/amd64 \
  --fail-on high \
  --output image-results.json \
  --sarif image.sarif \
  --timeout-seconds 300
```

Set `IMAGE_REF` to the full repository reference from your trusted build, such
as `registry.example.com/team/app@sha256:<64-hex-digest>`. Install Trivy
separately before using `skylos image scan`. The command scans
the pinned image from a remote registry and lets Trivy access its vulnerability
databases over the network. It does not start the scanned container or upload
results to Skylos Cloud. Skylos checks that Trivy's report names the exact
repository digest and platform requested (accounting for Trivy's Docker Hub
name shortening), then applies the severity threshold.
Without `--output`, normalized JSON goes to stdout.

The command supplies an isolated Trivy configuration and ignore file and removes
inherited `TRIVY_*` environment settings, so settings in the working repository
cannot silently filter the scan. It does not prove that the vulnerability
database is fresh or that every package was checked. The result's
`receipt.scan_complete` remains `null`.

## Scan an image with the GitHub Action

The Skylos composite GitHub Action can run an image-only scan instead of its
usual repository scan. Install a reviewed, pinned Trivy version in the caller's
job before the Skylos Action step (see the
[Trivy installation guide](https://trivy.dev/docs/latest/getting-started/installation/)).
Then pass the immutable image reference from a trusted build or push step:

```yaml
with:
  image: ${{ needs.build.outputs.image_ref }}
  image-platform: linux/amd64
  image-fail-on: high
  mode: gate
```

`image` must be a full `repository@sha256:<64-hex-digest>` reference; a mutable
tag is not accepted. `image-platform` is required whenever `image` is set.
`image-fail-on` defaults to `high` and accepts `low`, `medium`, `high`, or
`critical`. With `mode: gate`, findings at or above that severity fail the job.
With `mode: scan`, findings are reported without a severity gate, but an
incomplete scan still fails. `mode: review` is not supported for image scans.
When `image` is set, the Action does not run repository analysis.

Supply the digest and platform from trusted build configuration, not a PR title,
branch name, mutable tag, or other pull-request-controlled value. Do not run a
`pull_request_target` job with secrets against untrusted PR code. The Action
reads the image from the registry; it does not start the container. It stores
normalized JSON in runner temporary storage and uploads it as a workflow
artifact, including when a severity gate fails. Treat the artifact as
potentially sensitive and review who can access it. Image mode does not upload
to Skylos Cloud, post source-code annotations or review comments, or upload
SARIF to GitHub code scanning. It does not install Trivy or configure registry
credentials for you.

## Import an existing Trivy report

If Trivy runs in a separate job or environment, import its JSON report instead:

```bash
skylos ingest trivy --input trivy.json --output image-results.json --sarif image.sarif
```

`skylos ingest trivy` reads an existing report. It does not install or run
Trivy, pull an image, start a container, contact a vulnerability service, or
upload data.
Trivy remains responsible for scanning the image; Skylos checks and normalizes
the supplied results. Without `--output`, normalized JSON goes to stdout.

## Check an imported report against a specific image

Use the repository and digest produced by your trusted build or release job,
not a mutable image tag or a value copied from the report being checked:

```bash
skylos ingest trivy --input trivy.json \
  --expect-image "$IMAGE_REF" \
  --expect-platform linux/amd64 \
  --fail-on high \
  --output image-results.json \
  --sarif image.sarif
```

`IMAGE_REF` must be a full reference such as
`registry.example.com/team/app@sha256:<64-hex-digest>`. Skylos requires an exact
match in the report's `Metadata.RepoDigests`. A tag, matching digest under a
different repository, or `Metadata.ImageID` is not a substitute: the image
configuration digest is not the registry manifest digest.

For direct scans, pass this reference as the image argument. For imports,
`--expect-image` checks it against the report. `--expect-platform` checks an
imported report's image OS and architecture, for example `linux/amd64`; direct
scans use `--platform`. Check each deployment platform separately; one platform's
report does not establish coverage of a multi-platform release. For imports,
the identity checks compare reported metadata with the requested values; they
do not authenticate the report or independently fetch the image.

`--fail-on` accepts `low`, `medium`, `high`, or `critical`. It includes the
selected severity and higher severities. An imported report's severity check
requires `--expect-image`; the direct command uses its required pinned image.

| Exit | Meaning |
| --- | --- |
| `0` | The report was handled; if requested, its identity and severity checks passed. This does not certify the image as safe or the scan as complete. |
| `1` | At least one reported vulnerability met the requested severity threshold. |
| `2` | The scan, import, or check could not be completed, such as missing Trivy, a scanner error or timeout, malformed input, an identity mismatch, an unclassifiable severity, or a read/write failure. A severity check also fails with `2` when no recognized vulnerability results are present. |

Incomplete results take precedence over a finding threshold. Findings that were
successfully read remain in the output when possible, even when exit `2` applies.
An `UNKNOWN` or unrecognized severity makes the import incomplete even without
`--fail-on`; it is not silently treated as a low-severity or clean result.
Output files cannot overwrite the input report; unsafe linked output paths are
rejected. Use separate files for JSON and SARIF, with existing parent directories.
JSON output names must end in `.json`; SARIF output names must end in `.sarif`
or `.json`. Package manifests/lockfiles and Git metadata cannot be output targets.
If an output cannot be written safely, available JSON results fall back to stdout.

## Accepted reports and output

The importer supports Trivy JSON with `SchemaVersion: 2` and
`ArtifactType: "container_image"`. It reads OS-package and language-package
vulnerability results. Filesystem/repository scans, SBOM documents, and Trivy
secret, misconfiguration, and license findings are not this command's scope.
An empty or absent top-level `Results` array can be imported without a severity
check, but is not proof of a successful vulnerability scan. A severity check
requires at least one recognized vulnerability result.

Imported findings use `container_vulnerabilities`, separate from repository SCA's
`dependency_vulnerabilities`. Package versions, vulnerability IDs, supplied
severity/fix information, and image/result context stay associated with the
findings. SARIF contains the same imported findings; image package paths are
not presented as source-code locations in the checked-out repository.

The import receipt distinguishes two different facts:

- `import_complete` says whether Skylos handled the supported report without
  input or coverage gaps.
- `scan_complete` remains `null` for both commands: a report and a successful
  Trivy process cannot prove that every package was checked, that the database
  was fresh, or that every finding was returned.

An empty recognized vulnerability result can therefore import successfully
without making `scan_complete` true. Do not use `import_complete` as a release
attestation or as proof that an image has no vulnerabilities.

## Produce the report in CI

The following shell step works in a GitHub Actions `run` block or a GitLab CI
`script` block. Install reviewed, pinned versions of Trivy and Skylos separately.
Supply these values through your trusted CI/build configuration:

- `IMAGE_REF`: the full repository reference and immutable digest to deploy.
- `IMAGE_PLATFORM`: the deployment platform, such as `linux/amd64`.
- `IMAGE_SCAN_CONFIG`: an absolute path to an operator-controlled Trivy config.
- `IMAGE_SCAN_IGNOREFILE`: an absolute path to an operator-controlled empty
  ignore file when no exceptions are intended.

For this separate Trivy/import path, use Trivy's Docker Hub spelling for
`IMAGE_REF` in trusted CI configuration: for example, `alpine@sha256:...`
rather than `docker.io/library/alpine@sha256:...`. The direct `skylos image
scan` command handles that spelling difference automatically. Do not derive
the expected image from the untrusted report.

Run in a fresh, trusted output directory. Review the Trivy configuration and
inherited `TRIVY_*` environment variables: they must not introduce unwanted
exclusions, ignored statuses, Rego policies, VEX filtering, or a stale database
policy. Do not load those settings from an untrusted pull-request checkout.

```bash
set -eu
: "${IMAGE_REF:?Set the trusted repository@sha256:digest}"
: "${IMAGE_PLATFORM:?Set the deployment platform}"
: "${IMAGE_SCAN_CONFIG:?Set the trusted Trivy config path}"
: "${IMAGE_SCAN_IGNOREFILE:?Set the trusted empty ignore file path}"

trivy image \
  --config "$IMAGE_SCAN_CONFIG" \
  --ignorefile "$IMAGE_SCAN_IGNOREFILE" \
  --image-src remote \
  --platform "$IMAGE_PLATFORM" \
  --scanners vuln \
  --pkg-types os,library \
  --severity UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL \
  --ignore-unfixed=false \
  --exit-code 0 \
  --format json \
  --output trivy.json \
  "$IMAGE_REF"

skylos ingest trivy --input trivy.json \
  --expect-image "$IMAGE_REF" \
  --expect-platform "$IMAGE_PLATFORM" \
  --fail-on high \
  --output image-results.json \
  --sarif image.sarif
```

The Trivy step accesses the registry and its vulnerability databases; the Skylos
step is offline. Neither step needs to run the scanned container. Trivy's
`--exit-code 0` keeps reported findings available for Skylos to evaluate; genuine
Trivy errors must still stop the job. Do not add `|| true` to either command.
These options follow the official
[Trivy image CLI reference](https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/)
and [container-image guide](https://trivy.dev/docs/latest/target/container_image/).

Configure artifact retention to run even when the severity check fails. Review
access permissions before retaining reports. This example does not install
tools, change CI permissions, upload SARIF, or use the composite Action's
image-only mode. GitLab jobs can retain the files as ordinary artifacts; this
command does not create a GitLab Container Scanning report.

## Trust and privacy limits

The report producer and its configuration are part of your security boundary.
A report can be edited, copied from another job, stale, or filtered before Skylos
receives it. Digest and platform checks reduce accidental mismatches, but cannot
prove authenticity or reconstruct missing findings.

Trivy can omit findings using severity filters, ignore files/statuses, Rego
policies, file/directory exclusions, and VEX. Its optional `--show-suppressed`
exports experimental modified findings, not a guarantee that every filtered
finding is present. Review those controls at the producer rather than treating
successful ingestion as validation of the scan configuration. See
[Trivy filtering](https://trivy.dev/docs/latest/configuration/filtering/).

Raw Trivy JSON can contain image configuration, including environment variables.
Keep it private by default. Skylos copies only allowed metadata fields rather
than exporting the raw image configuration, but normalized package names and
image identities can still be confidential. Review artifacts before sharing.
Reports over 20 MiB are rejected as incomplete (exit `2`).

The direct command and GitHub Action image mode do not install Trivy, configure
registry credentials, upload to Skylos Cloud, or create a GitLab Container
Scanning report. Installed-package SBOMs, SBOM import, license policy, runtime
container testing, and vulnerability reachability analysis are also outside
this feature.
Repository dependency scanning and offline SBOM export remain separate; see
[dependency scanning](./dependency-scanning.md).
