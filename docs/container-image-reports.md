# Container-image vulnerability reports

Import a Trivy container-image report into Skylos JSON and SARIF, then apply a
severity threshold to the reported vulnerabilities:

```bash
skylos ingest trivy --input trivy.json --output image-results.json --sarif image.sarif
```

This command reads an existing report. It does not install or run Trivy, pull
an image, start a container, contact a vulnerability service, or upload data.
Trivy remains responsible for scanning the image; Skylos checks and normalizes
the supplied results. Without `--output`, normalized JSON goes to stdout.

## Check a specific image

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

`--expect-platform` checks the report's image OS and architecture, for example
`linux/amd64`. Check each deployment platform separately; one platform's report
does not establish coverage of a multi-platform release. Identity checks compare
reported metadata with the requested values; they do not authenticate the report
or independently fetch the image.

`--fail-on` accepts `low`, `medium`, `high`, or `critical`. It includes the
selected severity and higher severities. A severity check requires
`--expect-image`; a report for an unspecified image cannot pass that check.

| Exit | Meaning |
| --- | --- |
| `0` | The supported report was imported; if requested, its identity and severity checks passed. This does not certify the image as safe or the original scan as complete. |
| `1` | At least one reported vulnerability met the requested severity threshold. |
| `2` | The requested import or check could not be completed, such as malformed/unsupported input, an identity mismatch, missing required identity, an unclassifiable severity, or a read/write failure. A severity check also fails with `2` when no recognized vulnerability results are present. |

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
- `scan_complete` remains `null`: importing JSON cannot prove that Trivy scanned
  everything, used a fresh database, or returned every finding.

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
tools, change CI permissions, upload SARIF, or add an image input to Skylos's
composite GitHub Action. GitLab jobs can retain the files as ordinary artifacts;
this command does not create a GitLab Container Scanning report.

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

This first version does not add automatic scanner execution, registry
credentials, Cloud ingestion, an installed-package SBOM, SBOM import, license
policy, runtime container testing, or vulnerability reachability analysis.
Repository dependency scanning and offline SBOM export remain separate; see
[dependency scanning](./dependency-scanning.md).
