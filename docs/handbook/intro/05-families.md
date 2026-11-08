# Rule families and ID prefixes

Every rule has an ID such as SKY-D211. The letters after `SKY-` say what
kind of rule it is. IDs are kept stable so that suppressions, baselines and
CI policies keep working across releases; the changelog announces the rare
change. Unused-code findings show their ID (SKY-U001 and so on) in the
terminal and in markers, but JSON leaves it out and SARIF names them
`SKYLOS-DEADCODE-UNUSED_*`.

This handbook groups the {{page_count}} rules into families by what they
protect. Go engine IDs that are reported under a shared rule are counted
with that rule.

{{family_table}}

## Prefixes to know

| Prefix | Meaning |
|:--|:--|
| `SKY-D` | Security ("danger"). Also used by CI/CD, agent-configuration and deployment rules. |
| `SKY-S` | Secrets. |
| `SKY-SCA` | Dependencies: vulnerabilities, supply-chain checks, upgrade review. |
| `SKY-A` | AI-code defects. |
| `SKY-L` | Logic bugs and resilience. |
| `SKY-Q`, `SKY-C`, `SKY-P`, `SKY-T`, `SKY-F`, `SKY-R` | Quality, structure, performance, typing, framework practice and repository policy. |
| `SKY-U`, `SKY-UC`, `SKY-E` | Unused code, unreachable code, and empty or unused files. |
| `SKY-G` | Go. Not CI: the Go engine's own rules. |
| `SKY-DEP`, `SKY-GPU` | Kubernetes deployment exposure and GPU release compatibility. |
| `SKY-SC` | Security-contract regressions. |
| `SKY-CIRC` | Circular imports between modules. |

## One ID across languages

When several languages have the same problem, Skylos reports it under one
ID. SQL injection is SKY-D211 in Python, TypeScript, Java, Kotlin, Go, C# and
PHP (a Next.js server action has its own rule, SKY-D281). The Go engine
emits its own `SKY-G` IDs, and Skylos renames the ones with a shared rule
before reporting, not always to the same number: SKY-G211 becomes SKY-D211,
SKY-G209 becomes SKY-D250. Only Go-only rules keep a `SKY-G` ID.

## Prefix is not category

The catalog also gives each rule a category, and the two do not always
agree. Some AI-code rules kept older IDs so that existing suppressions keep
working: SKY-L012 (phantom symbol reference) and SKY-D222 (a dependency
that does not exist) are AI-code defects. The family of a rule page follows what
the rule is about, not only its prefix.

{{category_table}}

## IDs you may see that are not in this book

- Dependency vulnerabilities are reported as `SKY-SCA-` plus the advisory
  ID from OSV, for example a GHSA identifier.
- `SKY-SCA-MAL000` marks a malware-feed match without an advisory ID, and
  `SKY-SCA-NPM-PUB001` an npm publisher change after a long pause.
- Generic IDs such as `SKY-D000` and `SKY-Q000` stand in for findings that
  arrive without a rule ID of their own, and `SKY-ANALYSIS-INCOMPLETE`
  marks a file Skylos could not analyse.
- Custom rule packs in `.skylos/rules/*.yml` (or `.yaml`) use the IDs their
  authors choose, ideally with a project prefix such as `ORG-SEC001`.
