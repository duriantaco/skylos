# Silencing a finding

When you have read a finding and decided the code is right, silence it where
the next reader will see why. Skylos offers three levels.

## On one line

Put the marker on the reported line itself, with a reason after it.

```python
cur.execute(sql)  # skylos: ignore[SKY-D211] sql comes from REPORT_QUERIES
```

```typescript
el.innerHTML = trustedHtml; // skylos: ignore[SKY-D226] sanitized by renderMarkdown()
```

| Marker | Effect |
|:--|:--|
| `skylos: ignore[SKY-D211]` | Hides only the listed rules. Several IDs are separated by commas. Text after the bracket, separated by a space, is a free-form reason. |
| `skylos: ignore` | Hides every rule on that line. |
| `skylos: ignore-start` … `skylos: ignore-end` | Hides everything between the two lines (source files only). |
| `# noqa: skylos`, `# pragma: no skylos` | In Python, the same as `skylos: ignore`. |

In source files a marker on the line above does not count. In Python, a
marker on a decorator line also covers the decorated definition, and one on
a multi-line import covers the whole import.

Use `#` in Python, Shell, Ruby and YAML, `#` or `//` in PHP, and `//` (or a
one-line `/* … */`) in TypeScript, JavaScript, Go, Java, Kotlin, C#, Rust,
Swift, Dart and C++. In TypeScript, JavaScript, Go, Java, Kotlin, C#, Dart,
Rust, C/C++, PHP and Shell the marker must be in a real comment that starts
with it; the same text inside a string does not count. Dead-code findings
take their rule ID too: SKY-U001 for functions, SKY-U002 for imports,
SKY-U003 for variables, SKY-U004 for classes and SKY-U006 for parameters.

### Other tools' markers

- In Python, a bare `# noqa` still hides dead-code, quality, AI-code and LOW
  or MEDIUM findings, but **not** a HIGH or CRITICAL `SKY-D` or `SKY-S`
  finding. That finding stays reported, marked `bare_noqa_ignored`.
  `// noqa` is not read in TypeScript and JavaScript.
- `# noqa: F401` and `# noqa: F841` hide only the matching unused import or
  variable. Other `noqa` codes never hide a Skylos security, secret or
  quality finding.
- `#nosec`, `//nolint`, `NOSONAR`, `@SuppressWarnings` and
  `# pragma: no cover` do not hide Skylos findings.

### In CI files and other configuration

In GitHub Actions and GitLab CI files, Dockerfiles and similar
configuration, Skylos looks for the text `skylos: ignore[RULE]` on the
reported line or on the line directly above it. Write exactly one rule per
marker, with the ID in upper case. The bare `skylos: ignore`, a list of
several rules and `ignore-start` / `ignore-end` are not read there.

```yaml
      # skylos: ignore[SKY-D292] internal action, pinned by our release process
      - uses: our-org/deploy-action@v3
```

Some rules read no inline marker at all: agent and editor settings and
publish-job rules (SKY-D365 to SKY-D377), Terraform and Kubernetes rules
(SKY-D400 to SKY-D411), security-contract regressions (SKY-SC001), the
prompt-injection text rules SKY-D260 and SKY-D266, empty files (SKY-E002),
duplicated code (SKY-C401), circular imports (SKY-CIRC), the module design
rules SKY-Q802 to SKY-Q805, and the AI-code rules that compare a change with
its base (SKY-A102, SKY-A103, SKY-A104, SKY-A122 and SKY-A125). Use a
baseline or the project setting below for those. Each rule page says which methods work, and the
build checks those claims against the real scanner.

## For the whole project

```toml
[tool.skylos]
ignore = ["SKY-L028", "SKY-C303"]
```

This turns the listed rules off everywhere. Their findings are dropped, not
counted as suppressed. Write the IDs in upper case. Secrets are the
exception: `ignore = ["SKY-S101"]` does not affect the secrets scan, and a
committed secret stays reported. The dependency checks SKY-SCA-SRC001,
SKY-SCA-SRC003, SKY-SCA-INT001 and SKY-SCA-AGE001 are not affected either:
neither this list, an inline marker nor a baseline hides them. Circular
imports (SKY-CIRC) ignore the list and baselines too; set
`check_circular = false` under `[tool.skylos]` to turn them off. A gate policy
pulled from Skylos Cloud can set this list instead of `pyproject.toml`.

For dead code, a whitelist keeps matching names alive instead of turning
the rule off. Patterns use shell-style wildcards:

```toml
[tool.skylos.whitelist]
names = ["handle_*"]
documented = { "plugin_*" = "loaded by entry points in setup.cfg" }
```

## For findings you have not reviewed

Use a baseline (previous chapter). It hides existing findings without
claiming they are fine.

## Counting

Most findings silenced by a marker are not lost: the report counts them,
and the JSON `issue_summary` has `suppressed` and
`suppressed_by_ignore_comments`, so a reviewer can see how much is being
silenced. Two kinds are dropped without being counted: findings in
configuration files, and secrets silenced with `skylos: ignore[SKY-S101]`.
