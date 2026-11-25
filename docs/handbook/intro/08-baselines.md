# Baselines

A baseline records the findings a project already has, so that later scans
show only new ones. It is the usual way to adopt Skylos on an existing
codebase without fixing everything first.

```bash
skylos baseline .          # save today's findings
skylos . -a --baseline     # report only findings not in the baseline
```

`skylos baseline .` writes `.skylos/baseline.json` in the scanned folder.
By default it runs the security, secret, quality and AI-code checks. Add `--sca`
to include dependencies. If the scan is incomplete, even because of one file
that cannot be parsed, it exits 2 and keeps the old baseline.

Use `skylos lint` to check import cycles and configured layers. To
track new architecture findings in CI, save a baseline for these checks.

```bash
skylos baseline . --architecture
skylos lint --baseline
```

The first command replaces the same `.skylos/baseline.json` file with
architecture findings.

## How a finding is matched

| Finding | Matches the baseline when |
|:--|:--|
| Most code findings | Rule ID, absolute file path and line are all the same. |
| Unused functions, classes, imports and variables | The kind and the bare name are the same, in any file. |
| Agent-configuration and publish-job rules (SKY-D365 to SKY-D377, except D375) | Rule, relative file path, event or job name, and the command are the same. |
| Architecture cycles (SKY-CIRC, SKY-Q807) | The directed dependency edges are the same. |
| Layer violations (SKY-Q805) | The source and destination modules and their configured layers are the same. |
| Dependency advisories | Advisory, ecosystem, package, version, manifest, severity and how the package is used are the same. |

Architecture baselines work across line shifts and checkout locations. Create
a fresh baseline to capture architecture cycles and replace older file-and-line
entries for SKY-Q805.

Some findings are never hidden by a baseline: unused parameters, custom-rule
findings are not recorded, and a removed security
control (SKY-L021) or a change to AI-reviewer settings or scanner markers
(SKY-A122, SKY-A125) always shows. Of the dependency findings, only
advisories can be baselined; supply-chain findings such as SKY-SCA-INT001,
SRC001 and AGE001 always show.

## In CI

Most code findings are recorded with absolute paths and line numbers. For these
findings, use a baseline from the same checkout path. On pull requests, a diff
scan (see "Full scans and diff scans") is usually the simpler way to see only
new findings.

For dependency findings, `--baseline-ref REF` reads the baseline from a Git
commit instead of the checkout, so a pull request cannot add its own
entries. In CI, dependency filtering needs that explicit reference.
`--upload`, `--strict` and a gate policy pulled from Skylos Cloud turn
dependency filtering off.

## Baseline or suppression?

Use a baseline for findings you have not reviewed yet. Use a suppression
comment (next chapter) for a finding you reviewed and decided to keep, with
the reason next to it.
