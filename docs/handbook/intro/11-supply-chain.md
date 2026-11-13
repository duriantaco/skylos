# Supply-chain protection

A supply-chain attack reaches you through something you install or run:
a malicious package version, a dependency that suddenly runs code at
install time, an agent hook in a pull request, or a release job that can be
tricked into publishing. Skylos checks these in four places.

| Where | What it checks | How to turn it on |
|:--|:--|:--|
| The agent install hook | Packages a coding agent tries to install | `skylos agent install-hooks` or `skylos setup` |
| Dependency scans | Locked versions: known vulnerabilities, malware, integrity, sources, release age | `--sca` (or `-a`) |
| Upgrade review | What a version upgrade adds | `--review-upgrades` with `--diff` |
| Configuration scans | Agent, editor and MCP settings, and publish jobs | `--danger` (or `-a`) |

The rule IDs start with `SKY-SCA` for dependencies, and are SKY-D364 to
SKY-D377 for agent settings and publish jobs.

## The install hook

When a coding agent with Skylos hooks (Claude Code, Codex or Cursor) runs an
install command (`pip`, `uv`, `poetry`, `pdm`, `pipenv`, `pipx`, `npm`,
`pnpm`, `yarn`, `bun`, `deno` or `go`), Skylos checks the packages before
the command runs:

- **Packages that do not exist**, look-alike names of popular packages and
  versions that were never published are blocked (the same checks as
  SKY-D222 and SKY-D225).
- **Known malware** is blocked: a fresh OSV lookup, where an advisory counts
  as malware when its ID starts with `MAL-`, it comes from the
  malicious-packages project, or it lists CWE-506. When OSV does not answer,
  the local `ca9` feed is used if you downloaded it with `ca9 feed update`;
  otherwise the install counts as unchecked.
- **The 48-hour hold.** A version published less than 48 hours ago is
  blocked, and the message names the newest version that is old enough.
  Set `min_release_age_hours` under `[tool.skylos.supply_chain]` to change
  the wait, or `0` to turn it off.
- **npm provenance.** A version that lost the build provenance its earlier
  releases had is blocked.

The malware, release-age and provenance checks cover npm and PyPI
packages. The release-age and provenance checks run for packages named on
the command line; lockfile installs (`npm ci`, `uv sync`,
`pip install -r …`) get the malware check. Go and JSR packages get only the
existence and look-alike checks.

Installs from Git, a URL or an untrusted registry, and installs Skylos could
not check, ask the person first (Codex has no "ask", so they are blocked).
The whole check has a budget of about 20 seconds. Packages from registries
declared as trusted (and `GOPRIVATE` modules), and those listed in
`hooks_allow_packages`, are not looked up.

## Dependency scans

`--sca` reads lockfiles and manifests and asks OSV.dev about every locked
version.

| Rule | Severity | Finds |
|:--|:--|:--|
| `SKY-SCA-<advisory>` | from the advisory | a known vulnerability, named after the OSV, GHSA or CVE ID |
| `SKY-SCA-<MAL-…>`, `SKY-SCA-MAL000` | CRITICAL | known malware, from OSV or, when OSV cannot be reached, the local `ca9` feed if one was downloaded |
| SKY-SCA-INT001 | MEDIUM | a lockfile entry without an integrity hash |
| SKY-SCA-SRC001 | CRITICAL (HIGH when transitive) | possible dependency confusion; needs `internal_packages` |
| SKY-SCA-SRC003 | MEDIUM | a Git dependency not pinned to a commit, or a URL without a hash |
| SKY-SCA-AGE001 | HIGH | a locked version younger than `min_release_age_hours`; scans check it only when you set the value |
| SKY-SCA-LIC001 | HIGH (configurable) | a licence on your deny list, or missing from your allow list |
| SKY-SCA-HRD001 | HIGH | a change that weakens install hardening (diff scans only) |
| SKY-SCA-SRC004 | HIGH | a pull request points a package at a private, Git or URL source this repository did not use for it, or at a new host (diff scans only) |

Malware is always CRITICAL. Dependency findings count toward
`max_dependency_vulnerabilities`, which is 0 by default; the built-in gate
lists SKY-SCA-SRC003 and SKY-SCA-UPG002 without counting them (a gate
policy pulled from Skylos Cloud counts them).

### Private and Git packages

Advisory databases don't cover packages from a private registry, Git or a URL,
so Skylos lists them as **not checked** and still checks every public package.
The status is `complete_with_non_registry_sources` with `complete: false`: the
scan never claims those packages are clean. A pull request that introduces such
a source is reported as SKY-SCA-SRC004, and packages in `internal_packages` on
the target branch are exempt.

The scan still stops with exit 2 when it could check no public package at all,
or when at least 5 packages are not checked and they outnumber the packages it
could check, which is what a private mirror of public packages looks like. It
also stops on contradictory records: a tarball on the public registry that
doesn't match its package, a pnpm alternate `id`, or an unrecorded Yarn
`virtual:` peer.

### Public npm packages behind a private mirror

npm, pnpm, Yarn Classic and Bun lockfiles often record public packages
through a company mirror. To check those packages, list the mirror:

```toml
[tool.skylos.supply_chain]
npm_registry_mirrors = ["https://packages.example.com/npm/"]
internal_packages = ["@company/*"]
```

For each locked package behind that mirror, Skylos asks the public npm
registry for the same name and version and compares the lockfile's
`sha256`, `sha384` or `sha512` integrity value. Only an exact match makes it a
public package that OSV is asked about. The mirror itself is never contacted,
and names that match `internal_packages` are never sent. A package with no
integrity value, or a different one, stays "not checked".

### When OSV can't be reached

A failed request is retried within a 20-second budget. After that, Skylos reuses
the last good answer for that exact package version, up to 7 days old, from
`osv-answers.json` in the user cache. Live answers always win, and a file inside
the scanned repository is never read. The status is
`complete_with_saved_answers` with `complete: false`, so baselines and required
coverage refuse the scan, while known vulnerabilities still fail the gate. A
package with no saved answer leaves the scan incomplete (exit 2).

### How each package is used

PyPI advisories carry `metadata.reachability_tier`, shown in a **Use** column:
`called at app.py:4`, `imported`, `unknown`, `no import found` or `not reached`.
For npm advisories, Skylos looks for JavaScript and TypeScript source that
imports a direct dependency (static imports, re-exports, literal dynamic
imports and bare `require()` calls) and shows `JS/TS import at src/app.ts:3`.
It matches the import to the vulnerable copy in a v2 or v3
`package-lock.json` or `npm-shrinkwrap.json`; anything else stays `unknown`.
Packages sort by severity and, within a severity, by use. Nothing is hidden and
the gate counts every advisory: a package can run without an import, as a
command-line tool does.

### Exploit context (EPSS and KEV)

`--sca-threat-intel` turns on `--sca` and adds two public signals to each CVE:
its EPSS score (FIRST's estimate of how likely it is to be exploited soon) and
whether it is in CISA's Known Exploited Vulnerabilities catalog. Only CVE IDs
are sent to FIRST; the CISA catalog is downloaded whole. Each value is dated
and marked `current`, `stale` or `unknown`. The context never changes a
finding's severity, its order or the gate. It needs `ca9` 0.9.0 or later;
older versions keep the CVE findings and say the context is unavailable.

## Upgrade review

On a pull request, `--review-upgrades` (with `--diff` or `--diff-base`)
downloads the old and new version of each upgraded npm or PyPI package from
the trusted registries and compares them. It never installs, imports or runs
them.

- **SKY-SCA-UPG001** (CRITICAL) when `ca9` finds a change on its block
  list, such as a new `.pth` or `sitecustomize` file, a new install hook,
  decode-and-execute code, a new Git or URL dependency, shipped agent or
  editor hooks, files that shadow system commands, import-time code that
  cannot be inspected, or an artifact that does not match the lockfile. It
  fails a diff gate on its own.
- **SKY-SCA-UPG002** (MEDIUM, listed only) for changes worth a look:
  new network or execute calls at import, more obfuscation, a new native
  binary, a publisher change, changed install scripts.

A package new to the project is compared with its previous release; an
install hook there is reported as UPG002. A changed package that could not
be reviewed makes the scan incomplete (exit 2). Changes in requirements
files, `pdm.lock` and `pylock.toml` are listed as not reviewed.

The same flag also runs **SKY-SCA-API001** (MEDIUM, advice only) for Python: it
reads both releases without installing them and names your lines that use
something removed. This check also reads `requirements*.txt` `==` pins. Anything
it cannot read says "could not check", and it never says an upgrade is safe.

## Agent, editor and MCP settings

Committed settings can make a developer's tools run commands. With
`--danger`, the `ca9` library reads `.claude/settings.json`,
`.claude/settings.local.json`, `.gemini/settings.json`, `.cursor/hooks.json`,
`.codex/hooks.json`, `.vscode/tasks.json`, workspace files, and MCP
configurations (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and
others).

| Rule | Severity | Finds |
|:--|:--|:--|
| SKY-D365 | HIGH (CRITICAL when it downloads, decodes or disguises the code it runs) | an agent hook command |
| SKY-D366 | HIGH (CRITICAL as D365) | an editor task that runs when the folder opens |
| SKY-D367 | MEDIUM | an MCP server launched without an exact version |
| SKY-D368 | HIGH | an MCP server launched from a hidden home-directory or temporary folder |
| SKY-D369 | MEDIUM | an MCP package name imitating a vendor |
| SKY-D370 | HIGH | the agent's API base URL overridden |
| SKY-D377 | MEDIUM | duplicated keys that hide what runs |

A full scan lists these without counting them (a CRITICAL one still fails),
so repositories that already commit hooks keep their gate. A diff scan fails
on a new hook, folder-open task, hidden-path server or base-URL override.

## Publish jobs

With `--danger`, CI jobs that publish packages are checked for an unpinned
tool in a job holding publish credentials (SKY-D371), an unverified download
reaching the publish step (D372), an OIDC publish job without an environment
(D373), a publish started by a manual dispatch or a push to any branch
(D374), secrets passed to a reusable workflow in another repository (D376),
and, in diff scans, a publish job the change added or edited (D375).
Publishing with a stored token where the registry offers trusted publishing
is SKY-D364.
