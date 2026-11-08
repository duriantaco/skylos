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

The rule IDs start with `SKY-SCA` for dependencies, and are SKY-D365 to
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
  the malware feed installed with the `ca9` library is used.
- **The 48-hour hold.** A version published less than 48 hours ago is
  blocked, and the message names the newest version that is old enough.
  Set `min_release_age_hours` under `[tool.skylos.supply_chain]` to change
  the wait, or `0` to turn it off.
- **npm provenance.** A version that lost the build provenance its earlier
  releases had is blocked.

Installs from Git, a URL or an untrusted registry, and installs Skylos could
not check, ask the person first (Codex has no "ask", so they are blocked).
The whole check has a budget of about 20 seconds. Packages from private
registries, and those listed in `hooks_allow_packages`, are not looked up.

## Dependency scans

`--sca` reads lockfiles and manifests and asks OSV.dev about every locked
version.

| Rule | Severity | Finds |
|:--|:--|:--|
| `SKY-SCA-<advisory>` | from the advisory | a known vulnerability, named after the OSV, GHSA or CVE ID |
| `SKY-SCA-<MAL-…>`, `SKY-SCA-MAL000` | CRITICAL | known malware, from OSV or, when OSV cannot be reached, the installed `ca9` feed |
| SKY-SCA-INT001 | MEDIUM | a lockfile entry without an integrity hash |
| SKY-SCA-SRC001 | CRITICAL (HIGH when transitive) | possible dependency confusion; needs `internal_packages` |
| SKY-SCA-SRC003 | MEDIUM | a Git dependency not pinned to a commit, or a URL without a hash |
| SKY-SCA-AGE001 | HIGH | a locked version younger than `min_release_age_hours`; scans check it only when you set the value |
| SKY-SCA-LIC001 | HIGH | a licence your policy denies |
| SKY-SCA-HRD001 | HIGH | a change that weakens install hardening (diff scans only) |

Malware is always CRITICAL. Dependency findings count toward
`max_dependency_vulnerabilities`, which is 0 by default; SKY-SCA-SRC003 and
SKY-SCA-UPG002 are listed but not counted.

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

A changed package that could not be reviewed makes the scan incomplete
(exit 2).

## Agent, editor and MCP settings

Committed settings can make a developer's tools run commands. With
`--danger`, the `ca9` library reads `.claude/settings.json`,
`.claude/settings.local.json`, `.gemini/settings.json`, `.cursor/hooks.json`,
`.codex/hooks.json`, `.vscode/tasks.json`, workspace files, and MCP
configurations (`.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json` and
others).

| Rule | Severity | Finds |
|:--|:--|:--|
| SKY-D365 | HIGH (CRITICAL for remote or hidden code) | an agent hook command |
| SKY-D366 | HIGH (CRITICAL as D365) | an editor task that runs when the folder opens |
| SKY-D367 | MEDIUM | an MCP server launched without an exact version |
| SKY-D368 | HIGH | an MCP server launched from a hidden home-directory path |
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
