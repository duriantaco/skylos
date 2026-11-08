# Baselines

A baseline records the findings a project already has, so that later scans
show only new ones. It is the usual way to adopt Skylos on an existing
codebase without fixing everything first.

```bash
skylos baseline .          # save today's findings
skylos . -a --baseline     # report only findings not in the baseline
```

`skylos baseline .` writes `.skylos/baseline.json` in the scanned folder.
It always runs the security, secret, quality and AI-code checks; add `--sca`
to include dependencies. If the scan is incomplete, even because of one file
that cannot be parsed, it exits 2 and keeps the old baseline.

## How a finding is matched

| Finding | Matches the baseline when |
|:--|:--|
| Most code findings | Rule ID, absolute file path and line are all the same. |
| Unused functions, classes, imports and variables | The kind and the bare name are the same, in any file. |
| Agent-configuration and publish-job rules (SKY-D365 to SKY-D377, except D375) | Rule, relative file path, event or job name, and the command are the same. |
| Dependency advisories | Advisory, ecosystem, package, version, manifest, severity and how the package is used are the same. |

> Code findings are matched by absolute path and line. Adding or removing
> lines above a baselined finding moves it, and it shows up as new. A
> baseline made in one checkout folder matches no code findings in a
> checkout at another path, such as a CI runner.

Some findings are never hidden by a baseline: unused parameters, custom-rule
findings and circular imports are not recorded, and a removed security
control (SKY-L021) or a change to AI-reviewer settings or scanner markers
(SKY-A122, SKY-A125) always shows. Of the dependency findings, only
advisories can be baselined; supply-chain findings such as SKY-SCA-INT001,
SRC001 and AGE001 always show.

## In CI

Because of the absolute paths, a baseline only helps for code findings when
it is made in the same folder it is used in. On pull requests, a diff scan
(chapter 6) is usually the simpler way to see only new findings.

For dependency findings, `--baseline-ref REF` reads the baseline from a Git
commit instead of the checkout, so a pull request cannot add its own
entries. In CI, dependency filtering needs that explicit reference.
`--upload`, `--strict` and a gate policy pulled from Skylos Cloud turn
dependency filtering off.

## Baseline or suppression?

Use a baseline for findings you have not reviewed yet. Use a suppression
comment (next chapter) for a finding you reviewed and decided to keep, with
the reason next to it.
