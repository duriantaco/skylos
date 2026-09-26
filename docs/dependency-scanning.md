# Dependency scanning

`skylos . --sca --format json` inventories dependencies and queries OSV for
known vulnerabilities in exact package versions. `-a` also enables SCA.
Lockfiles are parsed as data: Skylos does not install dependencies, run package
scripts, synchronize environments, or execute workspace code for SCA.

For packages reported inside a built container image, use the separate
[`skylos ingest trivy` workflow](./container-image-reports.md). It imports an
existing Trivy vulnerability report without running a scanner or container;
repository SCA does not inspect the built image.

## Supported inventories

| Input | Coverage |
| --- | --- |
| `uv.lock` format 1 | Recorded public PyPI packages, including transitive packages and all locked environments |
| `Pipfile.lock` spec 6 | Recorded public PyPI packages across default, development, and custom categories, including transitives |
| `package-lock.json`, `npm-shrinkwrap.json` versions 1, 2, 3 | Recorded npm packages, including nested installations and multiple versions; v2/v3 use the authoritative `packages` table |
| `pnpm-lock.yaml` versions 6.0 and 9.0 | Recorded npm packages, including transitives, workspace importers, aliases, and separate peer-dependency snapshots |
| `poetry.lock` formats 1.0, 1.1, 2.0, 2.1 | Recorded public PyPI packages, including transitives, multiple versions, groups, extras, and environment markers |
| `yarn.lock` Classic v1; Berry formats 4, 6, 8 | Recorded npm packages, including transitives, aliases, optional/peer declarations and recorded workspaces |
| `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod` | Supported direct entries with exact versions; manifest ranges are not resolved |

The scanner discovers these files recursively, excluding dependency/build
directories. It combines lockfiles with direct manifest pins: an old or empty
lockfile must not silently hide a different manifest version. Identical
ecosystem/name/version queries are deduplicated, while every source occurrence
is retained. When both a manifest and a lockfile record the same version, the
finding prefers the lockfile location.

This is a **recorded inventory**, not a claim about what is installed in
production. Development groups, extras, optional dependencies, Python/platform
markers, workspace origins, and dependency edges remain available in finding
metadata. Markers are not evaluated against the scanner's host. npm v1 cannot
reliably distinguish direct dependencies from hoisted transitives; uncertain
classification remains `unknown`.

Local workspace packages are not queried as public packages. Explicit private
registries, Git dependencies, and external archives remain unresolved, rather
than being guessed to have public-registry identities. Known local/non-registry
identities also prevent matching direct manifest pins in the lockfile's project
and recorded workspace directories from being reinterpreted as public packages.
Unrelated nested projects retain their own manifest inventory.

npm permits omitted or registry-relative `resolved` values; those retain
`registry_unspecified` provenance. Even `registry.npmjs.org` is npm shorthand
for the configured registry, not proof of package provenance. This scanner does
not inspect `.npmrc`, verify artifact integrity, or establish supply-chain trust.

### Pipenv lockfiles

Skylos reads `Pipfile.lock` spec 6 as JSON without running Pipenv, installing
packages, or contacting package indexes. It inventories recorded exact versions
from `default` (production), `develop` (development), and custom categories.
Categories and package environment markers remain in finding and SBOM context;
markers are not evaluated against the scanning machine. The lock does not
identify which packages are direct rather than transitive or record their
dependency edges, so Skylos does not invent those classifications or SBOM graph
links.

Only packages associated with a supported public PyPI source are sent to OSV.
Private indexes and Git or archive sources remain explicit inventory gaps;
local path packages are counted separately and never queried as public
packages. Source URLs and credentials are not included in findings or the SBOM.
Skylos does not validate artifact hashes or verify that `Pipfile.lock` is fresh
relative to `Pipfile`. `skylos sbom` exports the supported package inventory
entirely offline.

### npm shrinkwrap

`npm-shrinkwrap.json` uses the same supported schemas as `package-lock.json`.
When both names exist in a directory, Skylos selects shrinkwrap and does not
read or inventory the neighboring package-lock, following
[npm's precedence rule](https://docs.npmjs.com/cli/v11/configuring-npm/npm-shrinkwrap-json/).
This selection happens before parsing and inventory limits. An unreadable,
symlinked, malformed, or unsupported shrinkwrap makes the scan incomplete;
it never causes fallback to a potentially different package-lock inventory.
Directories named `npm-shrinkwrap.json` are also invalid selected inputs.

The receipt records `ignored_lockfile_count` and up to 25 `ignored_lockfiles`
path examples, identifying the selected shrinkwrap and
`npm_shrinkwrap_precedence` reason.
SBOM receipts use relative paths for both filenames. Precedence is local to
each directory: other nested projects, other package managers, and direct
manifest pins remain independently inventoried. Findings and SBOM occurrences
retain the shrinkwrap filename and package location.

Only explicit `lockfileVersion` values 1, 2, and 3 are supported. Legacy files
without that field and future schema versions fail explicitly. Skylos does not
run npm to migrate locks, install packages, or infer missing metadata.

### pnpm lockfiles

Version 6.0 records package metadata and dependency edges together. Version 9.0
splits them into `packages` and `snapshots`; Skylos joins those tables and keeps
each full snapshot key as `package_path`. Multiple peer-dependency contexts
therefore retain separate occurrences, while OSV queries for the same package
and version are still deduplicated. Importer paths identify workspace consumers.
Development and optional usage, plus recorded OS/CPU/libc/engine constraints,
remain metadata rather than host-specific filters. Usage is also recorded per
workspace, so a baseline cannot hide a move from development to production in
one workspace just because another workspace already uses that package.

Integrity-only pnpm resolutions use `registry_unspecified`, not verified public
provenance. Local links are not queried. Git, private-registry, and archive
sources are reported as gaps rather than guessed from their name/version.
Missing package/snapshot records and unresolved dependency edges also make the
scan incomplete without discarding findings for other valid package entries.
Source references that may contain URL credentials are redacted; sensitive peer
contexts use stable hashes so they still remain distinct in baselines.

Only schema versions 6.0 and 9.0 are supported in this implementation. YAML
aliases, custom tags, duplicate keys, and excessive nesting are rejected.
For version 9.0, Skylos recognizes pnpm's leading environment document followed
by the project document. The two documents are validated independently before
their package graphs are combined; `packageManagerDependencies` and
`configDependencies` are inventoried as direct environment dependencies.
Ambiguous streams, conflicting records, cross-document references that would
repair an incomplete graph, and extra documents are rejected.
`ignoredOptionalDependencies` remains unsupported inventory. A valid nonempty
`bundledDependencies` or `bundleDependencies` field keeps the containing
package queryable but records `bundled_dependencies_not_enumerated` as a
coverage limitation because the lockfile does not identify the bundled
versions. No package installation, workspace script execution, lockfile
rewriting, or artifact download is performed.

### Poetry lockfiles

Poetry's default PyPI entries omit their source. Explicit custom indexes must
identify a supported public PyPI endpoint; private indexes, Git, and archive
sources stay explicit gaps. Directory dependencies are counted as local and
are never queried as public packages.

Skylos retains legacy categories, dependency groups, optional flags, extras,
Python requirements, and group-specific markers. The lock alone does not say
which packages are direct dependencies of the project, so that classification
remains unknown. Dependency constraints are preserved, not resolved. Only
unambiguous recorded targets receive graph links; uncertain ranges and omitted
project-root back-references remain unknown graph edges without discarding
the exact package inventory.

### Yarn lockfiles

Classic's `# yarn lockfile v1` format and Berry's `__metadata.version` values
4, 6, and 8 are supported. These are **lockfile schema versions**, not Yarn
CLI versions. Other schemas, including version 10, fail explicitly.

Skylos preserves multiple versions, npm aliases, workspace roots, optional
metadata, peer declarations, and recorded environment conditions. Yarn locks
do not separate development from production usage, and Berry does not record
all virtual peer installations. Skylos does not invent those classifications
or installed peer-provider relationships.

Patched, Git, archive, private-registry, and unsupported local-source records
remain gaps. Manifest `resolutions` overrides can prevent matching a recorded
dependency descriptor to a lock entry; these are explicit incomplete-graph
issues even when all package versions are present. No Yarn commands, package
scripts, or dependency installation are run.

## Export an SBOM offline

Create a software bill of materials (a list of recorded dependencies):

```bash
skylos sbom . --output sbom.cdx.json
```

The default output is CycloneDX 1.6 JSON. Omit `--output` or use `--output -`
to write JSON to stdout. `--format cyclonedx-json` is also accepted, and
`--format spdx-json` writes SPDX 2.3 JSON instead. This is a
separate offline inventory command: it does not contact OSV, run a vulnerability
scan, execute project code, or require Cloud changes. Declared licenses are read
from lockfiles and installed package metadata; `--license-lookup` is the only
option that makes network requests. See
[License compliance](./license-compliance.md).

The artifact includes every supported exact public package identity, not just
vulnerable packages. It preserves multiple versions, deduplicated package URLs,
relative source locations, and recorded context in
`skylos:dependency:occurrence` properties. Only known recorded dependency edges
are exported to the CycloneDX graph; missing graph nodes mean unknown, not
dependency-free. Incomplete inventories omit the graph entirely.

`metadata.properties` contains `skylos:inventory:receipt`, a JSON-encoded record
of counts and gaps. No source snippets, absolute checkout paths, or transport
URLs are included. CycloneDX output is deterministic for identical inputs,
installed package metadata, and Skylos versions; there is no generated timestamp
or random serial number. SPDX requires a `created` timestamp, which honours
`SOURCE_DATE_EPOCH`.

- Exit **0** means the available inventory was exported. With a matching lock
  in the same project/workspace and ecosystem, manifest ranges remain recorded
  limitations; lock freshness and range satisfaction are not verified.
- Incomplete input coverage (malformed locks, unsupported locks, unknown
  schemas, limits, unresolved sources, manifest ranges without a corresponding
  recorded lock inventory such as an unpinned `requirements.txt` with no
  lockfile, or no supported inputs) prints an `SBOM incomplete` warning on
  stderr and records the gaps in the receipt, but still exits **0**. Add
  `--strict` to exit **2** on an incomplete inventory, for example in a release
  pipeline that must not publish a partial SBOM.
- Exit **2** always means a usage, read or write error (bad path, refused
  output file).
- Existing input manifests and lockfiles cannot be selected as output files.
  Output parents must exist; unsafe linked output paths are rejected.

This is a **pre-build, partial inventory**, not an installed-environment
attestation. Local workspace packages are counted but not exported as
public third-party components. Private/unresolved sources, unsupported package
managers, artifact hashes, and production environment selection are
not filled in. Licenses are declared licenses only, and unknown values stay
`NOASSERTION` (no CycloneDX `licenses` entry). CycloneDX `compositions`
therefore remains `incomplete`, even when the supported inventory export
succeeds. SBOM import is not supported. License policy (`SKY-SCA-LIC001`) is
described in [License compliance](./license-compliance.md).

## Results and failures

### npm publisher review

`skylos . --sca --scan-publisher-changes --format json` adds an opt-in review
of direct npm dependencies recorded in `package-lock.json`. It queries the
public npm registry for publisher history and reports a newly observed
publisher after a long release gap as `SKY-SCA-NPM-PUB001` in the separate
`publisher_change_findings` field. This is a `WARN` review signal: verify the
publisher and release provenance. It is not proof of compromise, is not an OSV
vulnerability, and does not count toward `dependency_vulnerabilities` or the
quality gate. Selecting this rule with `--select SKY-SCA-NPM-PUB001` also
enables the publisher check.

The review requires a pinned direct npm dependency in a supported package
lockfile. Registry history can lack publisher data for older releases, so a
"first observed" publisher may not be the first publisher ever. A trusted
publisher identity or an established publisher with another widely used npm
package is exempt. A failed publisher reputation search keeps a review
finding and records a warning; a failed registry history lookup records a
warning without inventing a finding. Lockfiles remain data; Skylos never runs
npm package scripts for this check. JSON records check coverage and warnings in
`analysis_summary.publisher_change_scan`; terminal reports show incomplete
checks in rich and pretty formats. In concise output, use JSON to inspect
coverage when the finding list is empty.

### Known vulnerabilities

Findings use the existing `SKY-SCA-*` rule IDs and
`dependency_vulnerabilities` result field. Metadata includes package identity,
lockfile location, dependency context, and `dependency_occurrences`. The same
metadata is preserved in SARIF properties within the exporter's bounded
depth, item, text, and node budgets. CLI JSON and SARIF both include dependency
findings, including retained findings from an incomplete detail lookup.

OSV's batch endpoint returns advisory IDs. Skylos fetches each distinct full
advisory once per scan, with no project-owned or persistent cache. Findings now
include available summaries, CVE aliases, references, severity information,
affected ranges, and package-specific reported fixes. `advisory_status` records
whether a full matching advisory was available; `advisory_error` explains a
failed lookup or package mismatch without exposing transport credentials.

Severity uses published numeric CVSS scores or recognized severity labels.
CVSS vectors are preserved as `severity_vectors`, but are not converted into
numeric scores. If only a vector—or no severity—is supplied, the severity stays
`UNKNOWN` rather than being guessed. `fixed_versions` retains reported release
fixes; a single `fixed_version` upgrade hint is emitted only when supported
stable-version ranges establish an unambiguous newer fix. Multiple branches
and unsupported version syntax retain their evidence without a guessed upgrade.

`analysis_summary.sca_coverage` reports parsing/query completion, package and
occurrence counts, local packages, unresolved entries, unsupported lockfiles,
and inventory limits. Up to 25 lockfile issues and lockfile limitations are
included as examples; `unresolved_lockfile_dependency_count` and
`lockfile_limitation_count` are not truncated. For lockfiles,
`inventory_scope` is `all_recorded_lockfile_environments`.

The nested `query.advisory_details` receipt records distinct IDs, requests,
successful/failed/skipped lookups, accepted bytes, and limits. Failure to fetch
details does not erase a batch-confirmed finding: the finding stays visible,
the scan becomes incomplete, and CLI exit code 2 applies. An advisory that was
retrieved successfully may still legitimately omit optional severity/fix data.

- Malformed/unreadable locks, unsupported schema versions, unresolved external
  lock entries, inventory limits, or failed OSV requests produce incomplete
  operational results. CLI exit code **2** signals this failure, even with
  `--force` or an advisory gate. JSON is emitted before exit; upload is skipped.
- A completed inventory with findings can fail a configured vulnerability gate
  with exit code **1**. Reporting without a gate does not make findings an
  operational error.
- Manifest ranges remain explicit unresolved versions. No supported inputs and
  limited category coverage are not, by themselves, operational failures.
- Lockfile coverage limitations such as unenumerated bundled dependencies do
  not turn a completed OSV query into an operational failure. They remain
  explicit in `limitations` and `lockfile_limitations`; stricter completeness
  consumers such as SBOM graph export do not claim full dependency coverage.

`category_complete` remains `false`: these inputs do not cover all package
managers or establish a complete installed environment. Lockfile freshness and
production reachability are not verified.

Inventories are bounded by per-file/total bytes, file/directory counts, and
package counts; graph traversal has additional bounds. Local records also count
toward package limits. A project-owned OSV cache is neither read nor written.
OSV queries send package names, ecosystems, and exact versions—not source code
or registry credentials. Advisory availability and detail depend on OSV.
Full-advisory retrieval is limited to 512 distinct IDs, four concurrent
requests, 1 MiB per advisory, and 32 MiB total accepted response data. A
45-second collection deadline stops new detail work; HTTP connect/read timeouts
and deadline checks bound normal requests, but are not a guaranteed process-wide
wall-clock timeout for a slowly streaming server. Redirects are not followed.
Batch matches also have size/count bounds. If OSV returns another page of
matches, the current client retains the known matches and reports incomplete
coverage rather than silently treating the first page as the complete result.

## CI

For a CLI job:

```bash
skylos . --sca --gate --format json
```

### Report only new dependency issues

Capture the current findings explicitly, then compare later scans with them:

```bash
skylos baseline . --sca
skylos . --sca --baseline --gate --format json --sarif results.sarif
```

The ordinary `skylos baseline .` command still does not enable SCA or make OSV
requests. `--sca` adds dependency findings to the baseline after a completed
scan. An incomplete scan, failed lookup, or absence of supported dependency
inputs returns exit 2 without replacing an existing baseline.

Matching uses the exact advisory ID, ecosystem, package name/version, severity,
manifest path relative to the scan directory, workspace roots, and recorded
usage/environment context. npm installation paths and pnpm snapshot keys also
distinguish separate copies; uv's array indexes do not. Line changes, checkout
location changes, and uv package-table reordering do not make the same issue new.
A new advisory, version, consumer, usage context, or severity remains visible. Advisory aliases
are retained in findings, but are not used to merge distinct baseline IDs.

Only matching findings with complete advisory details can be excluded. If the
current SCA scan is incomplete, no dependency findings are excluded. Unsupported
or ambiguous identity data also remains visible. This is a recorded-finding
baseline, not a claim that accepted packages are safe or reachable in production.

JSON keeps matching findings in `baseline_dependency_vulnerabilities`; new
findings remain in `dependency_vulnerabilities` and SARIF. The
`analysis_summary.dependency_baseline` receipt gives the status and both counts.
The original `sca_coverage` receipt is preserved. Older baselines without the
versioned dependency section still work for their existing finding categories,
but cannot exclude dependency findings. Baseline files are bounded to 2 MB,
and dependency sections to 20,000 fingerprints; unsafe file links are rejected.

In CI, explicitly select a **trusted base revision** containing the reviewed
baseline, not the pull request's editable baseline:

```bash
skylos . --sca --baseline-ref "$TRUSTED_BASE_SHA" --gate --format json
```

Set `TRUSTED_BASE_SHA` from trusted CI metadata, such as the pull request target
branch's base commit SHA, and make that commit available in the local Git clone.
`--baseline-ref` implies `--baseline` and reads the dependency baseline from an
immutable Git object. It is not accepted through project-controlled `addopts`.
Without an explicit ref in CI, or if the selected baseline cannot be read,
Skylos retains all dependency findings and records the reason; it never falls
back to the checkout's dependency baseline. This restriction applies to the
new dependency baseline support, not the older non-dependency baseline format.

Uploads, strict scans, synced Cloud policy, and agent pre-commit checks retain
full dependency findings. A local baseline does not override those policies.
The CLI commands above support this workflow; this change does not add a
`baseline-ref` input to the composite GitHub Action or change generated workflows.

In an existing Skylos GitHub Action step, enable SCA explicitly:

```yaml
with:
  path: .
  mode: gate
  analysis: dead-code security sca
```

`dependency` and `dependencies` are aliases for `sca`. Both the scan and optional
upload paths recognize these exact, space-separated tokens. The Action default
remains `dead-code security`; this change does not enable uploads or change
permissions. Use an Action revision containing this support.

`skylos cicd init` already generates a workflow with SCA enabled. No Ansible,
container-image scanning, or C++ engine is introduced by this lockfile change.

## Format references

The formats are described in [npm's package-lock documentation](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/)
and [uv's project layout documentation](https://docs.astral.sh/uv/concepts/projects/layout/).
uv's detailed serialization is defined by its
[lockfile wire format](https://github.com/astral-sh/uv/blob/main/crates/uv-resolver/src/lock/mod.rs).
pnpm publishes specifications for [lockfile 6.0](https://github.com/pnpm/spec/blob/master/lockfile/6.0.md)
and [lockfile 9.0](https://github.com/pnpm/spec/blob/master/lockfile/9.0.md).
Poetry serialization is defined in its
[locker implementation](https://github.com/python-poetry/poetry/blob/2.1.4/src/poetry/packages/locker.py).
Yarn documents [Classic lockfiles](https://classic.yarnpkg.com/lang/en/docs/yarn-lock/)
and implements Berry serialization in its
[project writer](https://github.com/yarnpkg/berry/blob/%40yarnpkg/cli/4.9.2/packages/yarnpkg-core/sources/Project.ts).
SBOM output follows the [CycloneDX 1.6 schema](https://cyclonedx.org/schema/bom-1.6.schema.json).
Advisory retrieval follows the official
[OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/) and
[full-advisory endpoint](https://google.github.io/osv.dev/get-v1-vulns/).
