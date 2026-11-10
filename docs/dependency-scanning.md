# Dependency scanning

`skylos . --sca --format json` inventories dependencies and queries OSV for
known vulnerabilities in exact package versions. `-a` also enables SCA.
Lockfiles are parsed as data: Skylos does not install dependencies, run package
scripts, synchronize environments, or execute workspace code for SCA.

## Optional EPSS and CISA KEV context

```bash
skylos . --sca-threat-intel --format json
skylos . --sca --sca-threat-intel --format rich
```

`--sca-threat-intel` implies `--sca` and explicitly enables additional provider
lookups. `-a` and `--sca` alone do not enable them. Every supported ecosystem's
advisories are enriched after CVE aliases are resolved. Only canonical CVE IDs
are sent to FIRST's EPSS API; CISA's public KEV catalog is downloaded separately.
Repository source, package names, and credentials are not sent to these providers.

This requires the additive `ca9.api.threat_context` capability in ca9 0.9.0.
Publish that ca9 release before rolling out the integration. Older installations
keep their CVE findings, attach explicit unknown context and show an availability
warning; upgrading is optional for scans without this flag. Skylos does not enable
ca9's legacy threat-intelligence confidence boost.

Finding metadata adds `risk_context` with `schema_version: 1` and up to 16 sorted,
deduplicated CVEs. Each has `cve_id`, `epss` (`status`, `score`, `percentile`,
`score_date`, `retrieved_at`) and `kev` (`status`, `in_catalog`, `date_added`,
`due_date`, `catalog_date`, `retrieved_at`). Status is `current`, `stale`, or
`unknown`; unavailable values are `null`, and a real zero EPSS score stays zero.
`false` KEV membership requires a validated current catalog, never a failed request.

Both the provider date and individual retrieval time must be within 7 days for
current context. Cache entries refresh after 24 hours; failed refreshes keep dated
scores and positive KEV entries as stale. Missing or stale negative membership is
unknown. ca9 uses verified HTTPS, no redirects, bounded responses and an atomic
cache outside scanned source. The whole CLI enrichment has a 15-second network
budget; further CVEs use cache-only lookup and retain explicit unknown statuses
when no data is available. At most 16 lookup batches can use the network.

Rich and pretty package rows show EPSS and KEV context with stale/unknown labels;
individual details, JSON, SARIF and Cloud uploads preserve the dated records.
`analysis_summary.sca_threat_intel` reports provider status counts separately
from `sca_coverage`. Context never changes advisory IDs, severity, confidence,
listing, reachability, default package ordering, or local and Cloud gate decisions.

Cloud's CVE monitoring also uses an explicit source classification in uploaded
dependency inventory rows. `source: "public_registry"` requires an exact npm/PyPI
version and recorded supported public registry evidence. Private registries and
configured internal package names are classified `private_registry`; conflicting,
merged or unspecified registries remain unknown. Git/path declarations and
unresolved versions never acquire a public identity. Missing `source` in older
uploads means unknown. Monitoring can report that coverage gap until a new scan
supplies the evidence; a plain name and version do not establish public origin.
This records manifest/lockfile evidence and does not attest installed artifacts.

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
| `bun.lock` (Bun's text lockfile) `lockfileVersion` 0–3 | Recorded npm packages, including transitives and nested copies (`parent/child` keys); workspace, `file:` and `link:` entries are the project's own code and are not queried; Git, tarball and other-registry entries are not checked |
| `Cargo.lock` versions 1–4 | Recorded crates.io packages (git and sparse index), including transitives and multiple versions; see [Cargo](#cargo) |
| `composer.lock` | Recorded Packagist packages from `packages` and `packages-dev` (development-only); see [Composer](#composer) |
| `Gemfile.lock` | Recorded RubyGems specs from rubygems.org `GEM` sources, one identity per version across platforms; see [Bundler](#bundler) |
| `pubspec.lock` | Recorded Pub packages hosted on pub.dev, including transitives; `direct dev` packages are development-only; see [pub](#pub) |
| `gradle.lockfile` | Recorded Maven modules per Gradle configuration; modules locked only in test configurations are development-only; see [Gradle](#gradle) |
| `packages.lock.json` versions 1, 2 | Recorded NuGet packages for every target framework, including transitives; `Project` entries are the build's own projects; see [NuGet lockfile](#nuget-lockfile) |
| `requirements.txt`, `pyproject.toml`, `package.json`, `go.mod` | Supported direct entries with exact versions; manifest ranges are not resolved. `requirements.txt` includes its `-r` files inside the project (constraint `-c` files install nothing and are not scanned) |
| `pom.xml` | Direct dependencies whose version Maven would resolve from this POM, its `<properties>`, `<dependencyManagement>` and parent POMs inside the scan root; see [Maven](#maven) |
| `Cargo.toml`, `composer.json`, `pubspec.yaml` | Exact pins only: Cargo `=x.y.z`, a bare Composer version, a bare pub version. Ranges are counted as unresolved; Git, path, SDK and private-registry declarations are left to the lockfile |
| `setup.cfg`, `setup.py` | Exact `install_requires` pins, like `[project].dependencies`. `setup.cfg` is read as INI (including `file:` requirement lists inside the project); `setup.py` is parsed, never run, and only literal lists (or module-level names bound to them) are read. A file without static `install_requires` is not a dependency manifest |

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

Local workspace packages are not queried as public packages. In pnpm
lockfiles, the project's own local code (`link:` and `file:` directories, local
`file:` tarballs, peers satisfied by a workspace project, and pnpm `runtime:`
entries such as `node@runtime:26.11.1`) is listed as **not checked** instead of
making the scan incomplete: it has no public registry identity to look up.
For every lockfile format except `gradle.lockfile` and `packages.lock.json`,
validated Git, URL, path and private-registry sources are also listed as
**not checked**; see [uv source coverage](#uv-source-coverage), which applies to
all of them. A pull request that introduces such a source is reported as
`SKY-SCA-SRC004`. Contradictory records still stop the scan: a tarball on the
public registry that does not match its package, an alternate package `id`, or
an unrecorded Yarn `virtual:` peer. Known local/non-registry
identities also prevent matching direct manifest pins in the lockfile's project
and recorded workspace directories from being reinterpreted as public packages.
Unrelated nested projects retain their own manifest inventory.

npm permits omitted or registry-relative `resolved` values; those retain
`registry_unspecified` provenance. Even `registry.npmjs.org` is npm shorthand
for the configured registry, not proof of package provenance. This scanner does
not inspect `.npmrc`, verify artifact integrity, or establish supply-chain trust.

### uv source coverage

If at least 5 packages are not checked this way and they outnumber the packages
Skylos could check, the scan is incomplete and exits 2, with
`most_packages_not_checked: true` in the receipt. A private mirror of public
packages does this: passing would say little about the project's dependencies.
Findings for the packages it could check are still reported.

Skylos validates `uv.lock` source records before classifying them. Recognized
Git, URL, path and private-index sources have no supported public package
identity: they are **not checked**, never fetched or queried as public PyPI
packages. Matching manifest pins cannot override those recorded sources.
Supported public packages in the same project still get queried.

When the supported inventory and advisory queries succeed, the receipt uses
`status: "complete_with_non_registry_sources"`. A normal scan exits `0` if no
configured gate fails; known public-package vulnerabilities still appear and
can fail the gate. Rich, pretty, LLM, concise and GitHub output explain the
not-checked count. JSON keeps source types, reasons and locations in
`analysis_summary.sca_coverage.lockfile_not_checked`, without source URLs or
credentials. Examples are capped at 25; the
`non_registry_lockfile_dependency_count` count is not truncated.

This is successful processing with **limited coverage**. `complete` and
`category_complete` remain `false`: the dependency assessment cannot claim a
clean result, SCA baseline creation refuses it, and uploads cannot use it to
resolve earlier dependency findings by absence.

Malformed or contradictory source metadata, unreadable lockfiles, invalid
public-package versions, resource limits and advisory-service failures still
make the scan incomplete and exit `2`. Any vulnerabilities already found
remain in the report.

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
Private indexes and Git or archive sources are listed as not checked;
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
provenance. References are resolved the way pnpm writes them:

| Lockfile form | Result |
| --- | --- |
| `1.0.0(react@18.2.0)`, `1.0.0(patch_hash=…)` peer and patch contexts | Same package and version, separate occurrence |
| `npm:real@1.0.0`, `real@1.0.0` aliases; `catalog:` specifiers | The real package and version |
| `alias@https://registry.npmjs.org/real/-/real-1.0.0.tgz` | Queried as `real@1.0.0` when the canonical public tarball path and recorded `version` agree |
| v6 `file:dir` keys, v9 `name@file:dir` keys, `file:` tarballs, `directory` resolutions | Not checked (`local_package`) |
| `link:` to a directory that is not a workspace project, or outside the lock root | Not checked (`local_link`) |
| `link:packages/x` from a package snapshot (a peer resolved to a workspace project) | Workspace edge, not a gap |
| A bare version for a name that an importer links to a workspace project (`zod: 4.6.6` with no `zod@4.6.6` record) | Not checked (`workspace_package`) |
| `node`/`deno`/`bun@runtime:<version>` | Not checked (`runtime`) |
| Git, private-registry, and external archive sources | Not checked (`non_registry_source`) |
| A public-registry tarball that does not match its package, or an alternate `id` | Unresolved; the scan is incomplete |

OS/CPU/libc constraints may be a single string (`libc: glibc`) or a list.
Missing package/snapshot records for names that are not workspace projects, and
other unresolved dependency edges, still make the scan incomplete without
discarding findings for other valid package entries.
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
sources are listed as not checked. Directory dependencies are counted as local and
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

Patched, Git, archive and private-registry records are listed as not checked,
and local-source records as local packages. Unrecorded `virtual:` peers stay
unresolved. Manifest `resolutions` overrides can prevent matching a recorded
dependency descriptor to a lock entry; these are explicit incomplete-graph
issues even when all package versions are present. No Yarn commands, package
scripts, or dependency installation are run.

### Maven

`pom.xml` is read as XML, never run. A dependency's version may be a literal,
a `${property}` from the POM's `<properties>` (or `project.version`,
`project.groupId`), or come from a `<dependencyManagement>` entry with the
same groupId, artifactId, type (default `jar`) and classifier, as Maven matches
them. Properties
and managed versions are inherited from parent POMs found through
`<relativePath>` (default `../pom.xml`) inside the scan root, when the parent's
coordinates match. Skylos never downloads a parent POM or an imported BOM
(`<scope>import</scope>`), so a version that only they define, a version range
such as `[1.0,2.0)`, `LATEST`/`RELEASE`, and dependencies inside `<profiles>`
are counted as unresolved and not queried. `test` scope is development-only.
Plugin dependencies are build tooling and are not counted. A dependency on a
module of the same reactor is not a public package and is not counted: its
groupId, artifactId and version must match a POM that `<modules>` entries
inside the scan root reach from the declaring POM, a local parent, or a
`pom.xml` in an enclosing directory. Using `${project.version}` or the
project's own groupId does not make a dependency internal. A `pom.xml` with a
DTD (`<!DOCTYPE`/`<!ENTITY`) fails closed.

### Gradle

Gradle build scripts are code, so Skylos reads the single-file
`gradle.lockfile` written by
[dependency locking](https://docs.gradle.org/current/userguide/dependency_locking.html)
(`dependencyLocking { lockAllConfigurations() }` and
`gradle dependencies --write-locks`). Each `group:artifact:version=configurations`
line is an exact Maven module. A module locked only in test configurations
(`test*`, `androidTest*`, `*UnitTest*`, `*AndroidTest*`) is development-only;
every other configuration, including tool configurations such as `checkstyle`,
counts as runtime. The lockfile does not record repositories, so modules are
queried by their Maven coordinates. Legacy per-configuration lockfiles under
`gradle/dependency-locks/` are not read.

### Cargo

`Cargo.lock` versions 1 to 4 are read. Only packages from the crates.io index
(`registry+https://github.com/rust-lang/crates.io-index` or
`sparse+https://index.crates.io/`) are queried. Packages without a `source`
are workspace members or path dependencies (local, not checked); `git+` sources
and other registries are not checked. Cargo.lock does not record dev or build
scope. A member crate's `Cargo.toml` ranges count as covered by the workspace
root's `Cargo.lock` when the root's `[workspace] members` (minus `exclude`)
names it.

RustSec also publishes informational notices (`unmaintained`, `notice`,
`unsound`). They are reported with `metadata.advisory_informational`.
`unmaintained` and `notice` advisories are not vulnerabilities (cargo-audit
warns on them), so they get `low_risk_context.reason = "informational-advisory"`
and are left out of the default listing like development-only dependencies;
JSON, `--all-advice` and gates still count them. `unsound` advisories stay
listed.

### Composer

`composer.lock` `packages` are runtime packages and `packages-dev` are
development-only. A package is queried only when Composer recorded
packagist.org as its repository (`notification-url`). Path repositories are
local; VCS, private-repository and branch versions (`dev-main`, `1.x-dev`) are
not checked, because OSV would match a branch name against every advisory
range. A leading `v` is dropped (`v4.4.0` is `4.4.0`), and a short exact pin in
`composer.json` (`"1.2"`) is the same identity as the locked `1.2.0`. Platform
requirements (`php`, `ext-*`, `lib-*`) are not packages.

### Bundler

`Gemfile.lock` specs under a `GEM` source whose remotes are all rubygems.org are
queried. `PATH` sources are local; `GIT`, plugin sources and other `GEM`
remotes, including mirrors, are not checked. Bundler writes platform builds as
`nokogiri (1.13.3-x86_64-linux)`; the platform is not part of the version, so
every platform build of a version is one identity with each location kept.
The lockfile does not record Gemfile groups, so development scope is unknown.
The `Gemfile` itself is Ruby code and is not evaluated.

### pub

`pubspec.lock` `hosted` packages from `https://pub.dev` (or the former
`https://pub.dartlang.org`) are queried. `path` packages are local, `sdk`
packages ship with Dart or Flutter, and `git` packages and other hosted servers,
including mirrors such as `pub.flutter-io.cn`, are not checked. `direct dev`
packages are development-only. A workspace member's `pubspec.yaml`
(`resolution: workspace`) counts as covered by the nearest `pubspec.lock` above
it. In `pubspec.yaml`, a `dependency_overrides` entry replaces the package's
`dependencies`/`dev_dependencies` declaration, as pub resolves it: an exact
hosted override is queried at that version, a range override is unresolved,
and a `path`, `git` or `sdk` override is not queried.

### NuGet lockfile

`packages.lock.json` versions 1 and 2 (`RestorePackagesWithLockFile`) record
the resolved version of every package for each target framework, including
transitive and central-transitive ones. `Project` entries are the build's own
projects and are not checked. The lockfile does not record the feed, so
packages are queried by their NuGet identity, as `dotnet list package
--vulnerable` does. `.csproj` minimum versions next to a lockfile no longer
leave NuGet coverage incomplete, because the lockfile holds the resolved
versions.

### Files Skylos does not read

Every dependency file Skylos finds but does not read is named in
`analysis_summary.sca_coverage.unsupported_inputs` (file, ecosystem, reason; up
to 25 examples) and counted in `unsupported_lockfile_count` and
`unsupported_manifest_count`. The terminal says which ones, for example:

```
SCA coverage limited: 41 dependencies queried. Dependency files not read: ios/Podfile.lock (CocoaPods: not supported yet)
```

| File | Ecosystem | Reason |
| --- | --- | --- |
| `Gemfile` | RubyGems | Ruby code, not evaluated; `Gemfile.lock` is read |
| `build.gradle`, `build.gradle.kts` | Gradle | build scripts are not evaluated; enable dependency locking to write `gradle.lockfile` |
| `Package.resolved`, `Podfile.lock`, `mix.lock` | SwiftPM, CocoaPods, Hex | not supported yet |
| `bun.lockb` | npm | binary lockfile; run `bun install --save-text-lockfile` to write `bun.lock` |
| `Pipfile` | PyPI | not read; `Pipfile.lock` is |
| `go.sum` | Go | checksums, not the build list |

When unread files are present and everything Skylos reads was read and
queried, `sca_coverage.status` is `complete_with_unsupported_inputs`,
`complete` is `false` and `supported_inputs_complete` is `true`. That is a
coverage limit, not an operational failure: it does not make a scan exit 2,
and `skylos baseline --sca` still records the advisories it found. A gate
with `coverage.required = ["dependencies"]` fails on it, naming the unread
files. A repository with only unread files keeps the status
`no_supported_manifests`, and the message names the files.

Some files are listed under `skipped_inputs` instead, because another file
already holds their versions: `go.sum` next to a `go.mod` that declares Go
1.17 or later (that go.mod lists every module in the build), `Pipfile` next to
`Pipfile.lock`, `Gemfile` next to `Gemfile.lock`, `build.gradle(.kts)` next to
`gradle.lockfile`, and `bun.lockb` next to `bun.lock`. Before Go 1.17, go.mod
omits indirect modules, so its `go.sum` is an unread file. Copies under a
`vendor/` folder (Composer, Bundler and `cargo vendor` install third-party
copies there) are not the project's declarations: they are neither read nor
listed.

A dependency file Skylos reads but cannot parse (invalid syntax, an unknown
format version, a DTD in `pom.xml`, or a file over 10 MB) makes the scan
`incomplete`. It is counted in `parse_error_count` and named in
`sca_coverage.parse_errors` (file and reason, up to 25), and nothing from it
is queried.

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
lockfile. Skylos checks at most 25 eligible packages in deterministic path/name
order and reports partial coverage when the limit is reached.
`npm-shrinkwrap.json` is not supported; when present, it takes precedence over
`package-lock.json` and the check reports the skipped project. Registry history
can lack publisher data for older releases, so a
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

Terminal output (the default table and `--format pretty`) shows one row per
installed package: the worst severity, the version to upgrade to, and the
number of advisories with up to three IDs. "Upgrade to" takes, for each
advisory, its lowest reported fix above the installed version (so `next`
14.0.0 with fixes in 15.5.24 and 16.3.3 needs 15.5.24), then the highest of
those; advisories with no fix above the installed version are counted next to
it. Check the ranges in JSON before pinning. JSON, SARIF and
`--format concise` keep one finding per advisory.

Findings use the existing `SKY-SCA-*` rule IDs and
`dependency_vulnerabilities` result field. Metadata includes package identity,
lockfile location, dependency context, and `dependency_occurrences`. The same
metadata is preserved in SARIF properties within the exporter's bounded
depth, item, text, and node budgets. CLI JSON and SARIF both include dependency
findings, including retained findings from an incomplete detail lookup.

OSV's batch endpoint returns advisory IDs. Skylos fetches each distinct full
advisory once per scan, with no project-owned cache. Findings now
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
and inventory limits. Up to 25 lockfile issues, lockfile limitations and
not-checked local lockfile entries (`lockfile_not_checked`) are included as
examples; `unresolved_lockfile_dependency_count`,
`not_checked_lockfile_dependency_count` and `lockfile_limitation_count` are not
truncated. Not-checked entries add the `local_lockfile_packages_not_checked`
limitation. `unresolved_dependency_count` counts manifest ranges (for example
`package.json` `^1.2.0`, `workspace:*`, `npm:` aliases);
`lockfile_covered_unresolved_dependency_count` is the part of it in
directories that a parsed lockfile records as a project, where the lockfile
pins the installed versions (its freshness is not verified). For lockfiles,
`inventory_scope` is `all_recorded_lockfile_environments`.

Inventory limits: OSV is queried once per unique dependency (package, version
and ecosystem), and a scan may hold at most 5,000 of them; the same package
repeated across many lockfiles of a monorepo counts once. Separately, the
dependency files may list at most 50,000 entries in total (ten times the unique
limit, to bound parsing work). Above either limit nothing is queried, the scan
is incomplete and `limit_reasons` names `dependency_limit_exceeded` or
`dependency_entry_limit_exceeded`. The other limits are 10,000 directories,
1,000 dependency files, 10 MB per file and 50 MB in total.

The nested `query.advisory_details` receipt records distinct IDs, requests,
successful/failed/skipped lookups, accepted bytes, and limits. Failure to fetch
details does not erase a batch-confirmed finding: the finding stays visible,
the scan becomes incomplete, and CLI exit code 2 applies. An advisory that was
retrieved successfully may still legitimately omit optional severity/fix data.

- Malformed/unreadable locks, unsupported schema versions, contradictory lock
  entries, inventory limits, or failed OSV requests with no usable
  [saved answers](#when-osv-cannot-be-reached) produce incomplete operational
  results. CLI exit code **2** signals this failure, even with
  `--force` or an advisory gate. JSON is emitted before exit; upload is skipped.
  The run ends with a reason that names the cause and its count (unresolved
  lock entries with file and line, unreadable files, failed OSV.dev batches);
  to gate without dependency results, run without `--sca`. See
  [Gate verdict](./cli-output.md#gate-verdict).
- A completed inventory with findings can fail a configured vulnerability gate
  with exit code **1**. Reporting without a gate does not make findings an
  operational error.
- Manifest ranges remain explicit unresolved versions. No supported inputs and
  limited category coverage are not, by themselves, operational failures.
- Not-checked local lockfile entries (local directories, local tarballs,
  workspace packages, runtimes) are not an operational failure either. They
  are listed in `lockfile_not_checked`; dependency findings uploaded from such
  a scan are not treated as full coverage for resolving earlier findings.
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

### Malicious packages

An OSV record is treated as malware when its ID or an alias starts with
`MAL-` (the OpenSSF malicious-packages database), when it carries a
`malicious-packages-origins` import record, or when it lists CWE-506
(Embedded Malicious Code), as GitHub advisories for hijacked releases do
(`xrpl` 4.2.1, `debug` 4.4.2). The finding keeps its `SKY-SCA-<id>` rule ID,
is `CRITICAL`, sets `metadata.malicious: true` with `malicious_evidence`
(the original label stays in `advisory_severity`), and says to remove the
package, reinstall from a clean lockfile and rotate every credential an
install could read. The terminal package table shows "remove (malicious
package)" instead of an upgrade.

Malware is never demoted: the dev-only listing demotion does not apply
(installs on developer machines run its install scripts), reachability is not
attached, and the default gate (`max_dependency_vulnerabilities = 0`, critical
issues) fails.

When the OSV query is incomplete (for example offline), Skylos checks the
installed ca9 malware feed (`ca9 feed update`) instead of reporting nothing:
matches are `CRITICAL` with `metadata.malware_source: "ca9_feed"`, and
`sca_coverage.supply_chain.malware_sources` lists `ca9_feed`. Without a feed
the receipt notes `ca9_malware_feed_unavailable`. The scan stays incomplete
(exit code 2) either way, because advisories other than malware were not
checked.

### Supply-chain checks

`--sca` (and `-a`) also passes the inventory it read to the ca9 engine
(`ca9.api`, API version 1). Each ca9 result must agree with the record Skylos
read before it is reported:

| ID | Severity | Reported when |
|:---|:---|:---|
| `SKY-SCA-SRC001` | CRITICAL direct, HIGH transitive | A package matching `internal_packages` resolves from a public or merged index (`--extra-index-url`, a lockfile entry from `registry.npmjs.org` or `pypi.org`): dependency confusion. Never without configured internal patterns or registry evidence |
| `SKY-SCA-SRC003` | MEDIUM | A Git dependency not pinned to a full 40-character commit, or a URL dependency without a hash (`requirements.txt`, `pyproject.toml`, `package.json` without a lockfile, or a lockfile Git/URL entry). Local paths are not reported |
| `SKY-SCA-SRC004` | HIGH | In a pull request, a lockfile points a package at a private, Git or URL source this repository did not use for it, or at a new host. Advisory databases do not cover it, so it blocks until reviewed. Packages matching `internal_packages` on the target branch are exempt; the pull request cannot add its own exemption |
| `SKY-SCA-INT001` | MEDIUM | A registry entry in `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `uv.lock` or `poetry.lock` without an integrity hash (an empty value counts as missing). Never for `requirements.txt`, and not for npm `inBundle` entries, which ship inside their parent's verified tarball |
| `SKY-SCA-AGE001` | HIGH | The locked version is younger than `min_release_age_hours`. Scans check this only when the policy sets it |

Configure them in `pyproject.toml`; a synced Skylos Cloud policy can only
tighten these values:

```toml
[tool.skylos.supply_chain]
internal_packages = ["acme-*", "@acme/*"]
private_registries = ["https://pypi.acme.dev/simple"]
min_release_age_hours = 24
```

`--index-url` alone is an exclusive index and is not confusion. Source URLs in
findings drop user info and query values other than Git refs; archive URLs keep
only their host and file name. The built-in `--gate` reports `SKY-SCA-SRC003`
without counting it toward `max_dependency_vulnerabilities`, so a tag-pinned Git
dependency does not fail an existing gate; a synced Skylos Cloud gate counts it. When ca9 is
missing, older than API version 1 or fails, the scan continues with OSV
findings only and `sca_coverage.supply_chain.notes` says
`ca9_supply_chain_api_unavailable` or `ca9_supply_chain_api_failed`. These
findings sit in `dependency_vulnerabilities`; all but `SKY-SCA-SRC003` count
toward the dependency gate like advisories.

### Pull request checks: upgrades and weakened hardening

With `--diff BASE` or `--diff-base BASE`, `--sca` also compares the merge base
of `BASE` and `HEAD` with the files Git tracks in your working tree (untracked
files never count). Both sides are copied into temporary folders for ca9; the
checkout itself is never handed to it, installed or run.

| ID | Severity | Reported when |
|:---|:---|:---|
| `SKY-SCA-HRD001` | HIGH | The change weakens install hardening (`ca9.api.hardening_regressions`): a cooldown removed or lowered (npm `min-release-age`, pnpm `minimumReleaseAge`, Yarn `npmMinimalAgeGate`, Bun `minimumReleaseAge` in seconds, uv `exclude-newer`, pip `--uploaded-prior-to`, Dependabot `cooldown`, Renovate `minimumReleaseAge`; compared in minutes, and a removal that falls back to an equal or longer default such as pnpm 11's one day is not reported), a package newly allowed to skip the cooldown, `ignore-scripts` turned off, packages added to pnpm `allowBuilds`, npm `allowScripts` or Bun `trustedDependencies`, `strictDepBuilds` turned off, or an action pinned to a SHA moved to a tag or branch |
| `SKY-SCA-UPG001` | CRITICAL | With `--review-upgrades`: ca9 puts a delta of a lockfile change (npm or PyPI) in its `block` list: an upgrade adds install-time or start-up code (a `.pth` file or `sitecustomize` with code, a new install or prepare hook, decode-and-exec, a new Git or URL dependency, agent/editor hook files shipped in the package, two archive entries that install to the same path or differ only by case, a new executable named like a system command such as `node`, `git`, `pip`, `sh` or `curl`, bytecode without source that runs at import or interpreter start, an artifact that does not match the lockfile's integrity) |
| `SKY-SCA-UPG002` | MEDIUM | With `--review-upgrades`: only ca9's `warn` list has deltas: import-time network or exec calls, a much larger obfuscated file, a native binary, a new publisher, install-time code that changed beyond version strings and other literals, or anything ca9 flags in a newly added package (no base version), `block` list included, because there is no earlier version to compare against. A review signal, not proof |
| `SKY-SCA-API001` | MEDIUM | With `--review-upgrades`: a line of yours uses a name, module, method or keyword argument that exists in the old version of a Python package and not in the new one. Advice: listed, never counted by any gate |

`--review-upgrades` implies `--sca`. It downloads both versions of each
upgraded package through ca9's hash-verified fetcher (trusted indexes only,
size-capped) and reads them as data. A package the base did not lock is sent
with no old version and reviewed as newly added; everything ca9 flags in it is
UPG002, because nothing shows the behaviour is new. Otherwise findings follow
ca9's lists, never the delta kind: `block` is UPG001, `warn` is UPG002. Workflows
written by `skylos cicd init` turn it on for pull requests when dependency
checks are selected; plain CLI runs need the flag. The finding sits on the
lockfile line of the new version; `metadata.block_deltas` / `warn_deltas`
name the file inside the package, the line and a redacted snippet;
`metadata.basis` is `upgrade` or `new_package`. Packages matching
`internal_packages`, and entries the lockfile resolves from one of the
`private_registries`, are never looked up on a public registry: ca9 skips them
(`internal_package`, `private_registry`), and the verdict shows `Upgrade
review limited: N of M dependency upgrades reviewed (internal_package: K)`.
Every other change that was not reviewed (a timeout, an unreachable registry,
an artifact over the size cap, more than 100 changes, a pair with no result, a
result or receipt with `complete: false`, or `incomplete_results` in the
receipt) is an analysis error, so a diff gate stops as incomplete (exit 2)
instead of passing those packages unread; what an incomplete result did find is
still reported. Each pair carries the lockfile's `integrity` hash and, where
the lockfile records it, the download URL (`resolved` from npm and Yarn
classic lockfiles, pnpm's `resolution.tarball`), so ca9 skips private entries
and reports a lockfile that points a version at a different artifact
(`lockfile_artifact_mismatch`, UPG001). The PyPI lockfiles (`uv.lock`,
`poetry.lock`, `Pipfile.lock`) list entries from a non-public index as not
checked, so those are never paired or looked up. The policy values come from
`[tool.skylos.supply_chain]` (the base commit's under `SKYLOS_POLICY_BASE`); a
ca9 whose `review_upgrades` takes no `options` is still used when none is set,
and is an analysis error when `internal_packages` or registries are set (it
would look them up publicly).

#### Which of your lines an upgrade breaks (`SKY-SCA-API001`)

Python has no compile step, so CI misses a removed API unless a test runs that
line. For each Python package whose locked version changed (`uv.lock`,
`poetry.lock`, `Pipfile.lock`, and `==` pins in `requirements*.txt` and
`requirements/*.txt`), `--review-upgrades` compares the public API of both
releases and names your lines that use something the new one no longer has.
There is no model, no account, no install and no import of the package.

- **Both versions** are fetched and unpacked by `ca9.artifacts` (digest-verified,
  size-capped: 50 MB per archive, 20,000 files, the same kind of file on both
  sides) and read with `ast` (`.py`, and `.pyi` for compiled modules). Nothing
  from the archive runs.
- **The surface** is each module's bound names, classes, methods and parameters.
  `__all__`, re-exports and star imports inside the package are followed, so a
  symbol that moved but still imports from the same path is not reported.
  Underscore-private names are not public and are not compared.
- **Your code** is every tracked `.py` file except `node_modules`, `.venv`,
  `venv`, `vendor`, `build`, `dist` and similar. Import aliases, `from x import
  y`, attribute access, keyword arguments, `with X() as y` and `x = Class()` are
  followed. A parameter or local that shadows the name is not the package, and
  neither is a top-level module of your own with the same name. An import in
  `try`/`except ImportError`, or an attribute behind `hasattr`, has already
  handled the removal and is counted but not reported.
- **A removed keyword** is reported when the old signature names it and the new
  one rejects it. Where the new signature only has `**kwargs`, the forwarding is
  followed through the package; if it cannot be followed the line is "could not
  check". A keyword that goes through `**kwargs` on both versions without being
  followed is treated as unchanged (the visible signature is the same) and
  counted in `keywords_not_followed`.

The pull request comment gets one section, with one of two fixed sentences:
`No API-level impact found in N call sites (behaviour changes not checked)` or
`Review these N call sites`. The first appears only when every changed package
was compared and nothing was left unread. It is never a statement that an
upgrade is fine: only names and keyword arguments are compared, not behaviour.

Anything that could not be read says `Could not check` with the reason and
removes the clean sentence: a failed download, no comparable wheel or sdist, an
archive over its limits, a compiled module with no `.pyi`, a module `__getattr__`
that may provide the name, a computed `__all__`, a module that writes through
`globals()` or `sys.modules`, a star import that cannot be followed, a file of
yours that mentions the package and does not parse, an internal package, npm
packages (only Python is compared so far), `pdm.lock` and `pylock.toml`. A
package no file imports is listed as `not used, 0 call sites`.

Limits: at most 25 packages and 180 seconds per scan. The rule does not see
behaviour changes, changed return types or defaults, positional arguments,
newly required parameters, methods called through `self.x` or a function's
return value, string-based references (Django settings, Celery task names), or
what your other dependencies call. It reads the whole repository, so a monorepo
with two services on different versions can name lines in the other service.

On a Dependabot pull request the generated workflow needs no
`pull_request_target`: the comment comes from the `summary` job on the plain
`pull_request` event, using `GITHUB_TOKEN`. GitHub gives Dependabot-triggered
runs a read-only token and no Actions secrets, but the job's explicit
`permissions: pull-requests: write` raises the token, as GitHub's Dependabot
troubleshooting page documents. Pull requests from real forks keep a read-only
token, so they get no comment; the scan and its findings still run.

`SKY-SCA-API001` never fails a gate, built-in or synced from Skylos Cloud, and
is not uploaded to Skylos Cloud. Could-not-check rows are never an analysis
error, so they do not stop a diff gate as incomplete. Turn the check off with
`ignore = ["SKY-SCA-API001"]`. The receipt is
`analysis_summary.supply_chain_diff.checks.upgrade_api`.

Lockfiles are read up to 64 MB per side (other compared files up to 2 MB). A
lockfile that changed but could not be read (over 64 MB, not UTF-8, a link) or
that its parser rejects (invalid, or over 100,000 packages) is an analysis
error naming the file, never a review with nothing to compare; an unchanged
large lockfile (same Git object on both sides) is not. Changed dependency files
the review does not read yet (pins in `requirements*.txt` and
`requirements/*.txt`, hashed or not, `pdm.lock`, `pylock.toml`) are listed in
`analysis_summary.supply_chain_diff.checks.upgrades.limitations` and in the
verdict (`Upgrade review did not read changed dependency files: …`); they do
not fail the gate on their own.

A diff that changes a lockfile (or a requirements file) under `--sca` while ca9
is not installed, older than API version 1, or lacks `evaluate_packages` is an
analysis error ("… Upgrade ca9 (pip install -U ca9) and rerun."), as is one that
changes agent configs or workflows under `--danger` without `agent_config` /
`audit_workflows`. Changed hardening settings alone with no ca9 installed are
a receipt note. Hardening exceptions always come from the merge base; `ignore`
and `[tool.skylos.supply_chain]` come from the base only under `--gate` (see
[where settings come from](./agent-config-and-publish-rules.md#where-settings-come-from)).

Exceptions for a package (pnpm 11's cooldown otherwise breaks bot pull
requests on fresh transitive dependencies) are read from the base commit only,
so a pull request cannot add its own:

```toml
[tool.skylos.supply_chain.hardening_exceptions]
esbuild = "downloads its platform binary in postinstall"
```

An exception needs a non-empty reason and applies to regressions that name
that package (`allow_builds_added`, `cooldown_exclusion_added`, ...).
`analysis_summary.supply_chain_diff.checks.hardening.exceptions_applied`
lists the ones used.

In the built-in gate `SKY-SCA-UPG001` and `SKY-SCA-HRD001` fail a diff or
baseline scan on their own, whatever `max_dependency_vulnerabilities` allows;
`SKY-SCA-UPG002` is listed and not counted. When ca9 lacks
`hardening_settings`/`hardening_regressions` or `review_upgrades`, fails, or
reports `check_failed`, and there was something to compare, the scan records
an analysis error with no file (`supply_chain_check_unavailable`), so a
diff-scoped gate stops as incomplete (exit 2) instead of passing without the
check. Agent hooks, MCP servers and publish jobs are security checks; see
[Agent configuration and publish-job rules](./agent-config-and-publish-rules.md).

### Supply-chain posture and package inventory

Every `--sca` scan adds these blocks to `analysis_summary`, and uploads carry
them next to `sca_coverage`:

- `dependency_inventory` (`skylos.dependency_inventory.v1`): up to 10,000
  packages (`ecosystem`, `name`, `version`, `direct`, `dev`, `file`), sorted
  and de-duplicated, with `total` and `truncated`. Skylos Cloud matches new
  malware advisories against it after the scan.
- `supply_chain_posture` (`skylos.supply_chain_posture.v1`): six checks, each
  `pass`, `fail`, `not_applicable` or `unknown` with a `detail` and `paths`.
  `pass` needs evidence in the repository; `unknown` means the files cannot
  tell. In a Git checkout only committed manifests and config files count
  (a nested checkout or a local `.npmrc` does not configure CI), and only
  workflows directly in `.github/workflows` are read, as GitHub runs only
  those.
- `ci_inventory` (`ca9.ci_inventory.v1`, when ca9 provides it): per CI job
  (GitHub Actions and GitLab CI) the triggers, runner, environment, token
  write scopes and `id-token`, secret names, installs, actions, tools,
  downloads (hosts only), publish steps and, from ca9 releases that report
  it, `indirect` (`{command, line}`: a build runner, container tool,
  test-environment manager or repository script such as `make`, `docker` or
  `tox` that may install packages out of sight). Skylos Cloud uses it to tell
  which jobs could have installed a malicious version and what they could
  reach.
- `agent_hooks` (`ca9.agent_hooks.v1`, when ca9 provides it): committed agent
  and editor hooks, MCP servers and base-URL overrides, with redacted commands
  and `skylos_hook: true` for hooks `skylos agent install-hooks` wrote. Configs
  reached through links inside the repository are listed under the link path;
  a link that leaves the repository or points nowhere makes the block
  `partial`.

Both are built from the repository top (the Git root), also when only a
subfolder was scanned: workflows and agent configs live there, and a subfolder
scan would otherwise upload a complete, empty CI list. File paths are
repository-relative; `analysis_summary.supply_chain_checks` marks such blocks
`scope: repository`. Both are bounded (200 workflows, 500 jobs, 100 items per
CI list as in ca9, 50 per agent-hook list, 200 hooks and servers,
200-character strings); a CI job whose own lists were cut carries
`truncated: true`, and a cut workflow or job list sets the block's
`truncated`, so a cut list is never read as complete. They keep names instead of
values (secret names that are identifiers, `scheme://host` instead of URLs,
token-like text replaced by `[redacted]`) and list only files Git tracks or
does not ignore.
`analysis_summary.supply_chain_checks` says when ca9 could not build one; it
stays local and is not uploaded.

| Check | Passes when |
|:---|:---|
| `lockfile_committed` | Every npm and Python manifest has a lockfile (or fully pinned requirements) and Git tracks it. Outside a Git checkout: `unknown` |
| `frozen_install_ci` | Every recognised CI install uses the lockfile as is: `npm ci`, `--frozen-lockfile`/`--immutable`, pnpm in CI, `uv sync --locked`/`--frozen`, `pip --require-hashes` or hashed requirements, `poetry install`, `pipenv sync`/`--deploy` |
| `install_scripts_disabled` | npm projects block dependency install scripts: `ignore-scripts=true` in `.npmrc`, `--ignore-scripts` on every CI install, npm 12+ or pnpm 10+ (from `packageManager`; packages in npm `allowScripts` or pnpm `allowBuilds` are counted in the detail, and pnpm 11 `strictDepBuilds: false` still blocks unapproved builds), Yarn `enableScripts: false`, or Bun. pnpm `dangerouslyAllowAllBuilds: true` fails it even with `ignore-scripts=true` in `.npmrc`, which pnpm 11 no longer reads |
| `release_age_cooldown` | A minimum release age is set: `.npmrc` `min-release-age`, pnpm `minimumReleaseAge` (or pnpm 11+, one day by default), `.yarnrc.yml` `npmMinimalAgeGate` (or Yarn 4.15+, one day by default), `bunfig.toml` `minimumReleaseAge` (seconds; under 3600 fails as a likely unit mistake), uv `exclude-newer`, pip `--uploaded-prior-to` (CI command, requirements file, `pip.conf` or `PIP_UPLOADED_PRIOR_TO`), or Skylos `min_release_age_hours`. An explicit 0 fails. Dependabot's cooldown is named in the detail but does not pass the check: it delays only Dependabot's own pull requests |
| `actions_pinned` | No `SKY-D292` finding: every third-party action and reusable workflow is pinned to a commit SHA (GitHub-owned actions at release tags are noted) |
| `no_pr_target_checkout` | No `SKY-D290` finding for a `pull_request_target` or comment-triggered job that runs pull request code with privileges |

When ca9 provides `hardening_settings`, the committed values it reads are used
first and Skylos's own readers fill the gaps; a value from a file Git does not
track is ignored. The rich report prints one line when checks fail; JSON has
the details.

### When OSV cannot be reached

A failed batch request is retried twice, within a 20-second budget for the scan.
If OSV still does not answer, Skylos uses the last good answer for that exact
package version, up to 7 days old, from `osv-answers.json` in the user cache
(`$XDG_CACHE_HOME/skylos`, or `~/.cache/skylos`). Every successful scan updates
that file. Live answers always win.

A scan that used saved answers reports `status: "complete_with_saved_answers"`
and `complete: false`, with `query.saved_answers` giving the package count and
the age of the oldest answer. Known vulnerabilities still fail the gate. Advisories
published since then are missing, so the scan prints a warning, a baseline refuses
it, an upload cannot use it to resolve earlier findings, and
`coverage.required = ["dependencies"]` fails on it.

A package with no saved answer, or an answer older than 7 days, leaves the scan
incomplete with exit code **2**. So does a store inside the scanned repository,
which is never read or written: a repository cannot supply its own answers. The
GitHub workflow `skylos cicd init` writes keeps this file between runs with
`actions/cache`. Other CI systems need their own cache of that path, otherwise a
fresh runner has nothing saved.

### Reachability

For PyPI advisories, findings carry `metadata.reachability_tier`, what the code
shows about use of the package:

| Tier | Shown as | Meaning |
| --- | --- | --- |
| `used` | `called at app.py:4` | A listed vulnerable API is called (`reachability_call_sites`), or coverage shows the code ran |
| `imported` | `imported` | The package is imported, directly or through a dependency you import; no vulnerable call was found |
| `unknown` | `unknown` | Nothing proves either way: a transitive package, a command-line tool or plugin, a guessed import name, or an incomplete dependency graph |
| `not_imported` | `no import found` | A declared direct dependency, with a complete dependency graph, no import and no sign of indirect use |
| `unreachable` | `not reached` | The version is outside the affected range, or the code was proved not to run |

Terminal output sorts packages by severity and, within a severity, what the code
uses first. `no import found` and `not reached` sort last. Nothing is hidden and
the gate counts every advisory: "no import found" is not proof of safety. Other
ecosystems show `not analyzed`.

`reachability_verdict` keeps ca9's own verdict. It can change with GitHub
availability, because ca9 reads fix commits; the tier does not, because a call to
a listed API counts as use either way.

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

Under `SKYLOS_POLICY_BASE` (pull-request CI, and every `--gate` run with a
diff base), malware findings (`SKY-SCA-MAL*` and other advisories marked
malicious) stay excluded only when the base commit's `.skylos/baseline.json`
holds them too, wherever the dependency baseline was read from; see
[agent-config rules](./agent-config-and-publish-rules.md#gate).

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
