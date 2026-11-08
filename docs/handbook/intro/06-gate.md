# The quality gate and exit codes

A plain scan reports findings and exits 0: findings alone do not fail it.
To block a merge or a deploy, run Skylos as a gate.

```bash
skylos . -a --gate
```

The gate counts the findings of the checks that ran against the limits under
`[tool.skylos.gate]` in `pyproject.toml`. (A gate policy pulled from Skylos
Cloud with `skylos sync pull` replaces those limits.) A check that did not
run is not judged: a dead-code-only scan says
`security not scanned (add -a)`. The run ends with one verdict line:

| Verdict | Exit code | Meaning |
|:--|:--|:--|
| `Quality Gate: PASSED` | 0 | Every limit holds. Passing means within your policy, not zero findings. |
| `Quality Gate: FAILED` | 1 | A limit failed. Each failing limit and its findings are listed. `--force` exits 0 instead. |
| `Quality Gate: INCOMPLETE — could not decide` | 2 | Required analysis did not finish, so Skylos will not claim a pass. `--force` does not change this. |

In an interactive terminal, a failed gate run without `--strict` asks
whether to continue anyway.

## Default limits

| Setting | Default | Counts |
|:--|:--|:--|
| `max_critical` | 0 | CRITICAL security findings |
| `max_high` | 5 | HIGH security findings |
| `max_security` | 10 | security findings |
| `max_secrets` | 0 | secrets |
| `max_quality` | 10 | quality findings |
| `max_ai_defects` | same as `max_quality` | AI-code findings |
| `max_reliability` | 0 | reliability findings |
| `max_dependency_vulnerabilities` | 0 | dependency findings, except SKY-SCA-SRC003 and UPG002 |
| `max_dead_code` | no limit | unused code |

## What always fails

Some findings fail the gate whatever the limits say:

- any CRITICAL security finding;
- any secret;
- any AI-code finding at a severity in `block_ai_defect_severities`
  (`["CRITICAL"]` by default; `[]` turns this off);
- a security control that the change removed (SKY-L021);
- in diff and baseline scans, a supply-chain change to review: a new agent
  hook, folder-open task, hidden-path MCP server or agent base-URL override
  (SKY-D365, D366, D368, D370), and a blocked dependency upgrade or weakened
  install hardening (SKY-SCA-UPG001, SKY-SCA-HRD001).

Setting `fail_on_critical = false`, or `max_critical` or `max_secrets` above
0, only prints a warning: the gate still fails.

## Stricter and looser runs

- `--strict` fails on any listed finding, with or without `--gate`.
  `strict = true` under `[tool.skylos.gate]` does the same for `--gate`
  runs. Advice the report does not list does not count.
- `--format concise` exits 1 when it lists findings, even without `--gate`.
- `--force` turns a FAILED gate into exit 0. It never overrides INCOMPLETE.

## Exit codes

| Code | When |
|:--|:--|
| 0 | The scan finished. With `--gate`, the gate passed. |
| 1 | `--gate` failed, `--strict` found something, `--format concise` listed findings, or `--type-check` found type errors. |
| 2 | A usage error (a missing path, a mistyped command) or incomplete analysis. |

## Incomplete analysis

A file that cannot be analysed (see "How Skylos reads code"), or a language engine that is
missing, is a coverage warning: the scan and the gate are decided on the
code that was analysed, and the report ends with `Coverage: INCOMPLETE —
some code was not analysed`. It becomes exit 2 when:

- you pass `--strict`, or a `--gate` run has `require_complete = true` under
  `[tool.skylos.gate.coverage]`;
- more than half of the source files could not be analysed;
- a `--diff` or `--diff-base` scan could not analyse a changed file;
- a whole requested check failed, such as an interrupted `--sca` lookup or
  GitHub Actions YAML that cannot be read;
- a requested `--type-check` could not finish (the checker is missing, timed
  out, or printed output Skylos could not read).
