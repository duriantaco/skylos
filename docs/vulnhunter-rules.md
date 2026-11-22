# VulnHunter static rules in Skylos

The standard Skylos security scan checks Rails controllers for request data used as raw SQL
(`SKY-D211`) or as the destination of an outbound request (`SKY-D216`). Ruby analysis
follows local assignments within the controller method. For SQL, it recognizes the
Active Record base class and models whose ancestry is visible in the same file.

Python security scans check for an lxml parse using a parser explicitly configured with
`resolve_entities=True` (`SKY-D236`) and for ordinary equality comparisons of keyed
digests from the standard `hmac` module (`SKY-D253`).

## Supplemental rule pack

With the Semgrep CLI on PATH, run the pack from an installed Skylos checkout or wheel.

```sh
skylos rules vulnhunter ./project
skylos rules vulnhunter ./project --format sarif > findings.sarif
```

The command uses bundled local rules and disables Semgrep metrics and its version check.
It returns 0 for a completed scan with no findings, 1 for a completed scan with
findings, and an error code for an unsuccessful or incomplete scan. A run can
emit partial results and still return an error. It supports text, JSON and SARIF.
The pack runs separately from the standard Skylos PR gate. Some rule families
overlap with that gate.

The pack includes 38 VulnHunter OpenGrep rules. It covers Python, JavaScript/TypeScript,
Go, Java, Ruby, PHP, C#, C/C++, Rust and generic templates. Rule IDs retain their
`VHOG` prefix. The C/C++ command rule (`VHOG153`) follows environment reads or
indexed arguments from a recognized `main` signature. Ordinary function parameters
alone do not establish user control. The 11 traversal-related rules are excluded.

Four additional Python review rules retain their original `VH` IDs:

| ID | What the reported code shows |
| --- | --- |
| VH127 | A Flask request supplies a whole filter to a recognized MongoDB query. |
| VH131 | A function returns the answer field from an oracle round. Check where its caller validates freshness. |
| VH137 | An Ariadne ASGI or WSGI service explicitly enables GraphQL introspection. |
| VH138 | An Ariadne ASGI or WSGI service is constructed without an explicit validation rules argument. Query limits may live elsewhere. |

The extras are static review leads. Scan precision depends on the scanner version,
language support, and code shape. They require no model provider.

`VHOG102` reports a bare `pass` in a matched exception handler. A `None` return
can be a rejection signal, so the rule does not infer whether a caller accepts
it. `VHOG157` checks nonempty credential defaults at recognized OS environment
reads.
