# Skylos Rule Dictionary

Rule IDs are unified across languages — same vulnerability, same ID.

## Security / Danger (SKY-D)

| ID | Severity | Name | Languages | CWE | OWASP |
|----|----------|------|-----------|-----|-------|
| D201 | HIGH | eval() usage | Python, TS | CWE-95 | A03:2021 |
| D202 | HIGH | Dynamic code execution (exec, new Function, setTimeout string) | Python, TS | CWE-95 | A03:2021 |
| D203 | CRITICAL | os.system() | Python | — | A03:2021 |
| D204 | CRITICAL | pickle.load | Python | — | A08:2021 |
| D205 | CRITICAL | pickle.loads | Python | — | A08:2021 |
| D206 | HIGH | yaml.load without SafeLoader | Python | — | — |
| D207 | MEDIUM | Weak hash (MD5) | Python, TS, Go | CWE-328 | — |
| D208 | MEDIUM | Weak hash (SHA1) | Python, TS, Go | CWE-328 | — |
| D209 | HIGH | subprocess shell=True | Python | — | A03:2021 |
| D210 | HIGH | TLS verification disabled | Python, Go | — | A02:2021 |
| D211 | CRITICAL | SQL injection | Python, TS, Go | CWE-89 | A03:2021 |
| D212 | CRITICAL | Command injection | Python, TS, Go | CWE-78 | A03:2021 |
| D214 | HIGH | Broken access control | Python | — | A01:2021 |
| D215 | HIGH | Path traversal | Python, Go | CWE-22 | A01:2021 |
| D216 | CRITICAL | SSRF | Python, TS, Go | CWE-918 | A10:2021 |
| D217 | CRITICAL | SQL injection (ORM — sqlalchemy.text, pandas.read_sql, Django .raw) | Python | CWE-89 | A03:2021 |
| D222 | MEDIUM | Dependency hallucination | Python | — | — |
| D223 | MEDIUM | Undeclared third-party dependency | Python | — | — |
| D226 | CRITICAL | XSS (mark_safe, innerHTML, outerHTML, document.write, dangerouslySetInnerHTML) | Python, TS | CWE-79 | A03:2021 |
| D227 | HIGH | XSS: unsafe template rendering | Python | CWE-79 | A03:2021 |
| D228 | HIGH | XSS: unescaped HTML output | Python | CWE-79 | A03:2021 |
| D230 | HIGH | Open redirect | Python, TS, Go | CWE-601 | A01:2021 |
| D231 | HIGH | CORS misconfiguration | Python | — | A05:2021 |
| D232 | CRITICAL | JWT vulnerability (algorithms=none, verify=False) | Python | — | A02:2021 |
| D233 | CRITICAL | Unsafe deserialization (marshal, shelve, jsonpickle, dill) | Python | — | A08:2021 |
| D234 | HIGH | Mass assignment (Django Meta.fields='\_\_all\_\_') | Python | — | A01:2021 |
| D245 | HIGH | Dynamic require() with variable argument | TS | CWE-94 | A03:2021 |
| D246 | HIGH | JWT decode without verification | TS | CWE-347 | A02:2021 |
| D247 | MEDIUM | CORS wildcard origin | TS | CWE-942 | A05:2021 |
| D248 | MEDIUM | Hardcoded internal URL (localhost/127.0.0.1) | TS | CWE-798 | — |
| D250 | MEDIUM | Insecure randomness (Math.random) | TS | CWE-330 | — |
| D251 | HIGH | Sensitive data in logs | TS | CWE-532 | — |
| D252 | MEDIUM | Insecure cookie (missing httpOnly/secure) | TS | CWE-614 | — |
| D253 | MEDIUM | Timing-unsafe comparison | TS | CWE-208 | — |
| D270 | MEDIUM | Sensitive data in localStorage/sessionStorage | TS | CWE-922 | — |
| D271 | MEDIUM | Error info disclosure in HTTP response | TS | CWE-209 | — |
| D510 | HIGH | Prototype pollution (\_\_proto\_\_) | TS | CWE-1321 | — |

### MCP Server Security

| ID | Severity | Name | Languages | OWASP |
|----|----------|------|-----------|-------|
| D240 | CRITICAL | MCP tool description poisoning | Python | A03:2021 |
| D241 | HIGH | MCP unauthenticated transport | Python | A07:2021 |
| D242 | HIGH | MCP permissive URI / path traversal | Python | — |
| D243 | CRITICAL | MCP server bound to 0.0.0.0 | Python | — |
| D244 | CRITICAL | MCP hardcoded secrets in tool params | Python | — |

## Secrets (SKY-S)

| ID | Severity | Name | Languages | CWE |
|----|----------|------|-----------|-----|
| S101 | CRITICAL | Hardcoded secret / API key (prefix match + Shannon entropy) | All | CWE-798 |

## Go-Specific (SKY-G)

These have no cross-language equivalent and keep their own IDs.
Go rules that DO have equivalents (G211, G212, etc.) are remapped to their unified D-series IDs automatically.

| ID | Severity | Name | Details |
|----|----------|------|---------|
| G203 | HIGH | Defer in loop | Resource leak risk |
| G206 | HIGH | Unsafe package usage | unsafe stdlib package |
| G209 | MEDIUM | Weak RNG | math/rand instead of crypto/rand |
| G221 | MEDIUM | Insecure cookie | Missing HttpOnly/Secure flags |
| G260 | HIGH | Unclosed resource | os.Open/sql.Open without defer .Close() |
| G280 | HIGH | Weak TLS version | TLS 1.0/1.1 configured |

## Logic (SKY-L)

| ID | Severity | Name | Languages | CWE |
|----|----------|------|-----------|-----|
| L001 | HIGH | Mutable default argument | Python | CWE-665 |
| L002 | MEDIUM | Bare except block | Python | — |
| L003 | LOW | Dangerous comparison (== True/False/None) | Python | — |
| L004 | MEDIUM | Anti-pattern try block (too broad) | Python | — |
| L005 | LOW | Unused exception variable | Python | — |
| L006 | MEDIUM | Inconsistent return (some paths implicit None) | Python | — |

## Quality (SKY-Q, SKY-C, SKY-P)

### Complexity & Structure

| ID | Severity | Name | Languages | Threshold |
|----|----------|------|-----------|-----------|
| Q301 | WARN–CRITICAL | Cyclomatic complexity | All | >10 |
| Q302 | MEDIUM | Deep nesting | All | >3 levels |
| C303 | MEDIUM | Too many arguments | All | >5 required / >10 total |
| C304 | MEDIUM | Function too long | All | >50 lines |
| Q305 | MEDIUM | Duplicate condition in if-else-if chain | TS | — |
| Q401 | HIGH | Async blocking call (time.sleep, requests in async) | Python | — |
| Q402 | MEDIUM | Await in loop (prefer Promise.all) | TS | — |
| Q501 | MEDIUM | God class | Python | >20 methods or >15 attrs |
| Q701 | MEDIUM | High coupling (CBO) | Python | — |
| Q702 | MEDIUM | Low cohesion (LCOM) | Python | — |

### Performance

| ID | Severity | Name | Languages |
|----|----------|------|-----------|
| P401 | LOW | Memory risk: file.read() / readlines() | Python |
| P402 | LOW | Memory risk: pandas.read_csv without chunksize | Python |
| P403 | LOW | Nested loop O(N^2) | All |

### Architecture

| ID | Severity | Name | Languages |
|----|----------|------|-----------|
| Q801 | MEDIUM | High architectural instability | Python |
| Q802 | MEDIUM | Distance from main sequence | Python |
| Q803 | MEDIUM | Zone of Pain / Zone of Uselessness | Python |
| Q804 | MEDIUM | Dependency Inversion Principle violation | Python |
| CIRC | — | Circular dependency | Python |

## Dead Code (SKY-U, SKY-UC)

| ID | Severity | Name | Languages |
|----|----------|------|-----------|
| U001 | INFO | Unused import | Python |
| U002 | INFO | Unused variable | Python |
| U003 | INFO | Unused function | Python |
| U004 | INFO | Unused class | Python |
| UC001 | MEDIUM | Unreachable code (after return/raise/break) | Python |
| UC002 | MEDIUM | Unreachable code (after return/throw/break/continue) | TS |

## Other

| ID | Severity | Name | Languages |
|----|----------|------|-----------|
| E002 | — | Empty/docstring-only file | Python |
| C401 | — | Module reachability | Python |
| SCA-* | varies | Software Composition Analysis (CVE scanning) | Python |

## Go Rule Remap Table

When the Go binary outputs these IDs, they are translated to unified IDs before reporting:

| Go Binary Output | Unified ID | Vulnerability |
|------------------|------------|---------------|
| SKY-G207 | SKY-D207 | Weak MD5 |
| SKY-G208 | SKY-D208 | Weak SHA1 |
| SKY-G210 | SKY-D210 | TLS disabled |
| SKY-G211 | SKY-D211 | SQL injection |
| SKY-G212 | SKY-D212 | Command injection |
| SKY-G215 | SKY-D215 | Path traversal |
| SKY-G216 | SKY-D216 | SSRF |
| SKY-G220 | SKY-D230 | Open redirect |
