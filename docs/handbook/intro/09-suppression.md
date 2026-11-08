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
Swift, Dart and C++. Outside Python the marker must be in a real comment that starts
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

Agent and editor settings, publish-job rules (SKY-D365 to SKY-D377) and
Terraform rules read no inline marker at all. Use a baseline or the project
setting below for those.

## For the whole project

```toml
[tool.skylos]
ignore = ["SKY-L028", "SKY-C303"]
```

This turns the listed rules off everywhere. Their findings are dropped, not
counted as suppressed. Write the IDs in upper case. Secrets are the
exception: `ignore = ["SKY-S101"]` does not affect the secrets scan, and a
committed secret stays reported. A gate policy pulled from Skylos Cloud can
set this list instead of `pyproject.toml`.

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
