# License Compliance and SPDX SBOM

Skylos records the declared license of each dependency it already inventories
for SCA. It writes those licenses into CycloneDX and SPDX 2.3 SBOMs, and it can
flag dependencies whose license breaks a policy you set.

Collection works offline by default. Skylos never guesses a license. If it
cannot prove a license from local metadata, it writes `NOASSERTION`.

## Export an SBOM with licenses

```bash
skylos sbom . -o sbom.cdx.json                          # CycloneDX 1.6 (default)
skylos sbom . --format spdx-json -o sbom.spdx.json      # SPDX 2.3 JSON
skylos sbom . --format spdx-json --license-lookup       # opt-in network lookup
```

Exit codes are the same as the CycloneDX export: `0` means the supported
inventory was exported, and `2` means inputs were incomplete or a read or write
failed. A package with an unknown license does not make the export incomplete.

## Where license data comes from

| Ecosystem | Offline source (default) | With `--license-lookup` |
|:---|:---|:---|
| npm (`package-lock.json`, `npm-shrinkwrap.json` v2/v3) | The lockfile's `packages[...].license`, then the installed `node_modules/<pkg>/package.json` when its name and version match exactly | deps.dev |
| npm (pnpm, Yarn, `package.json` pins) | The installed `node_modules/<pkg>/package.json` when its name and version match exactly. Symlinked installs (the pnpm store) are not followed | deps.dev |
| PyPI (`requirements.txt`, `pyproject.toml`, uv, Poetry, Pipfile locks) | Installed distribution metadata from the project's `.venv`/`venv`, or from the Python environment running Skylos. It is used only when the normalized name **and** version match the locked version. Order of preference: `License-Expression`, then `License`, then an unambiguous `License ::` classifier | deps.dev |
| Go (`go.mod`) | None. `go.mod` and `go.sum` do not declare licenses, so the value is `NOASSERTION` | deps.dev |

Skylos does not support Cargo, Maven, or other ecosystems in the dependency
inventory yet, so they have no license data either.

`--license-lookup` is the only option that makes a network request. It only
queries packages that are still `NOASSERTION` after the offline pass. Each
request has a 5-second timeout. The whole lookup has a 60-second deadline and a
limit of 1,000 packages. Failed lookups leave the value as `NOASSERTION`. Scans
(`skylos . -a`) never run license lookups.

### Normalization

Declared values become SPDX identifiers or expressions only when the mapping is
exact:

- SPDX identifiers and expressions are validated and put in canonical case, for
  example `mit or apache-2.0` becomes `MIT OR Apache-2.0`.
- Deprecated SPDX IDs map to their exact replacements, for example `GPL-3.0`
  becomes `GPL-3.0-only` and `GPL-2.0+` becomes `GPL-2.0-or-later`.
- A small table covers unambiguous variants, such as `MIT License` → `MIT`,
  `Apache 2.0` → `Apache-2.0`, and `New BSD` → `BSD-3-Clause`.
- Legacy npm `{"type": ...}` objects are read, and `licenses` arrays become an
  `OR` expression, as npm documents.

Values that could mean more than one license become `NOASSERTION`. Examples
are `BSD`, `GPLv3` (it could be `-only` or `-or-later`), `Apache Software
License` (no version given), `UNLICENSED`, and `SEE LICENSE IN ...`. The raw
declared string is kept in the policy finding metadata for review.

## CycloneDX output

- `components[].licenses` holds `[{"license": {"id": "MIT"}}]` for a single
  SPDX ID and `[{"expression": "MIT OR Apache-2.0"}]` for anything else.
- If the license is unknown, the component has no `licenses` entry.
- `components[].properties` includes `skylos:license:source`, for example
  `package-lock.json` or `python-metadata:License-Expression`.
- `metadata.properties` → `skylos:licenses` is a JSON receipt with the
  collection mode, declared and `NOASSERTION` counts, counts per source, and
  lookup statistics.

## SPDX 2.3 output

Sample, trimmed:

```json
{
  "spdxVersion": "SPDX-2.3",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "app-sbom",
  "documentNamespace": "https://spdx.skylos.dev/spdxdocs/app-422edcfd…",
  "creationInfo": {"created": "2026-09-25T04:32:21Z", "creators": ["Tool: skylos-4.39.1"]},
  "packages": [
    {"SPDXID": "SPDXRef-RootPackage", "name": "app", "downloadLocation": "NOASSERTION",
     "filesAnalyzed": false, "licenseConcluded": "NOASSERTION",
     "licenseDeclared": "NOASSERTION", "copyrightText": "NOASSERTION",
     "primaryPackagePurpose": "SOURCE"},
    {"SPDXID": "SPDXRef-Package-npm-parent-1.0.0-db4b09d612", "name": "parent",
     "versionInfo": "1.0.0", "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
     "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT",
     "copyrightText": "NOASSERTION", "primaryPackagePurpose": "LIBRARY",
     "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                       "referenceLocator": "pkg:npm/parent@1.0.0"}]}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
     "relatedSpdxElement": "SPDXRef-RootPackage"},
    {"spdxElementId": "SPDXRef-RootPackage", "relationshipType": "DEPENDS_ON",
     "relatedSpdxElement": "SPDXRef-Package-npm-parent-1.0.0-db4b09d612"}
  ]
}
```

- `licenseDeclared` holds the normalized declared license, or `NOASSERTION`.
  `licenseConcluded`, `downloadLocation`, and `copyrightText` are always
  `NOASSERTION`, because Skylos does not inspect package contents.
- Relationships: `DOCUMENT DESCRIBES` the root package. The root `DEPENDS_ON`
  each direct dependency, meaning a manifest pin or a lockfile direct entry.
  Package-to-package `DEPENDS_ON` edges are written only when the lockfile
  graph is complete. Any other package is linked from the root as `OTHER`,
  with a comment that its path was not recorded.
- A `LicenseRef-*` declaration adds a `hasExtractedLicensingInfos` entry.
- `created` follows `SOURCE_DATE_EPOCH` when it is set, so builds can be
  reproducible. `documentNamespace` is derived from the package set and the
  Skylos version.
- Inventory completeness and the license receipt are recorded in
  `creationInfo.comment`.

## License policy (SKY-SCA-LIC001)

Set the policy in `pyproject.toml`:

```toml
[tool.skylos]
license_deny = ["GPL-*", "AGPL-3.0-only"]  # SPDX IDs or globs
license_allow = []                          # optional allow-list; empty = allow anything not denied
license_exceptions = ["some-pkg", "other-pkg@1.2.3"]  # waived packages
license_severity = "HIGH"                   # LOW | MEDIUM | HIGH | CRITICAL (default HIGH)
```

The policy runs as part of dependency analysis (`skylos . -a`, `--sca`, or
`--select SKY-SCA-LIC001`). It is offline. Findings go in the
`dependency_vulnerabilities` result bucket with rule ID `SKY-SCA-LIC001` and
category `DEPENDENCY`. Their metadata includes `license`, `license_source`,
`license_declared`, `denied_licenses`, and `disallowed_licenses`.

How the policy is evaluated:

- A package is a violation only when **no** choice under its expression
  avoids the policy. `MIT OR GPL-3.0-only` passes a `GPL-*` deny list, and
  `MIT AND GPL-3.0-only` fails it.
- The deny list wins over the allow list. When `license_allow` is set, a
  license that is not on it is a violation.
- Entries in the config are normalized the same way as package metadata, so
  `GPL-3.0` in the config matches `GPL-3.0-only`. Globs (`GPL-*`) match
  without case sensitivity and match the whole ID, so `GPL-*` does not match
  `LGPL-*`. List `-only` and `-or-later` variants separately, or use a glob.
- `NOASSERTION` never produces a finding. An unknown license is reported in
  the SBOM, not turned into a violation.
- License findings are not captured in dependency baselines. To waive one, use
  `license_exceptions` or a suppression.

### Suppressing findings

- Project-wide: `ignore = ["SKY-SCA-LIC001"]` in `[tool.skylos]`.
- One package: add it to `license_exceptions` as `name` or `name@version`.
- Inline: in manifests that allow `#` comments, such as `requirements.txt`,
  add `# skylos: ignore[SKY-SCA-LIC001]` on the dependency's line. JSON
  lockfiles cannot hold comments, so use `license_exceptions` for them.

When `.skylos/config.yaml` (cloud-synced policy) sets any `license_*` key, the
synced values take precedence. Repository `pyproject.toml` cannot relax
`license_deny`, `license_allow`, `license_exceptions`, or `license_severity`,
and cannot add `SKY-SCA-LIC001` to `ignore`.
