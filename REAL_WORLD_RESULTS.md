# Real-World Skylos Results

Skylos-assisted dead-code cleanup PRs have been accepted in mature open-source
repositories. These are maintainer-merged cleanup PRs, not endorsements or
adoption claims by the listed projects.

## Merged Cleanup PRs

| Project | PR | Status | Final GitHub Diff | What It Shows |
|:---|:---|:---|:---|:---|
| Black | [psf/black#5041](https://github.com/psf/black/pull/5041) | Merged | 3 files, 0 additions, 24 deletions | unused internal parsing/node helpers |
| Black | [psf/black#5052](https://github.com/psf/black/pull/5052) | Merged | 3 files, 0 additions, 36 deletions | unused token helpers, parser debug methods, and stale attribute |
| Flagsmith | [Flagsmith/flagsmith#6953](https://github.com/Flagsmith/flagsmith/pull/6953) | Merged | 10 files, 0 additions, 56 deletions | unused exceptions, serializers, response classes, and helper code |
| pypdf | [py-pdf/pypdf#3685](https://github.com/py-pdf/pypdf/pull/3685) | Merged | 1 file, 0 additions, 4 deletions | unused reverse encoding dictionaries |
| mitmproxy | [mitmproxy/mitmproxy#8136](https://github.com/mitmproxy/mitmproxy/pull/8136) | Merged | 8 files, 2 additions, 44 deletions | unused console helpers, bit utilities, and stale imports |
| NetworkX | [networkx/networkx#8572](https://github.com/networkx/networkx/pull/8572) | Merged | 5 files, 1 addition, 31 deletions | unused private function and imports |
| Optuna | [optuna/optuna#6547](https://github.com/optuna/optuna/pull/6547) | Merged | 5 files, 2 additions, 37 deletions | unused helper functions, method, constant, and unpacked variables |
| beets | [beetbox/beets#6473](https://github.com/beetbox/beets/pull/6473) | Merged | 4 files, 0 additions, 38 deletions | unused plugin helpers and dead database type |
| react-error-boundary | [bvaughn/react-error-boundary#243](https://github.com/bvaughn/react-error-boundary/pull/243) | Merged | 7 files, 0 additions, 102 deletions | unused docs and Vite integration helpers |

Total final GitHub diff across the merged PRs above:

| PRs | Files Changed | Additions | Deletions | Net Change |
|---:|---:|---:|---:|---:|
| 9 | 46 | 5 | 372 | -367 |

## Why This Matters

Static analysis tools are easy to demo on toy repositories and hard to trust on
real ones. These PRs show that Skylos can find dead-code candidates in mature
projects and produce cleanup work that survives maintainer review.

This proof has a narrow scope:

- It supports Skylos as a practical dead-code discovery tool.
- It does not prove every finding is correct.
- It does not prove Skylos is better than every specialized analyzer.
- It does not mean the listed projects use Skylos.

For reproducible benchmark details and current caveats, see
[BENCHMARK.md](./BENCHMARK.md).
