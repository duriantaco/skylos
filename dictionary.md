# Skylos Rule Dictionary and Product Glossary

This file is the repo-local glossary for public Skylos terminology and emitted
rule IDs. Keep it aligned with `README.md`, translated READMEs in
`docs/i18n/`, `docs/*.md`, CLI help text, and rule implementations.

Rule IDs use a stable public prefix:

| Prefix | Meaning |
|:---|:---|
| `SKY-D` | Security and danger findings |
| `SKY-S` | Secrets findings |
| `SKY-SCA` | Software composition / dependency vulnerability findings |
| `SKY-SC` | Security contract regression findings |
| `SKY-A` | AI-defect verification findings |
| `SKY-L` | Logic, AI-code mistake, and resilience findings |
| `SKY-Q` | Quality, complexity, coupling, and architecture findings |
| `SKY-C` | Structure and clone findings |
| `SKY-P` | Performance findings |
| `SKY-U`, `SKY-DC`, `SKY-UC` | Dead-code, LLM dead-code report, and unreachable-code findings |
| `SKY-T` | Typing practice findings |
| `SKY-F` | Framework practice findings |
| `SKY-R` | Repository policy findings |
| `SKY-E` | Analyzer inventory / export findings |
| `SKY-G` | Raw Go engine findings before remapping |
| `SKY-CIRC` | Circular dependency finding |

## Product Glossary

| Term | Meaning |
|:---|:---|
| Skylos | Local-first static analysis and PR gate for dead code, security, secrets, quality, dependency, and AI-code issues. |
| Local-first | Core static analysis runs on the developer machine or CI runner without requiring cloud upload or LLM calls. |
| Core scan | `skylos .`; dead-code focused scan. |
| Full audit | `skylos . -a`; enables security, secrets, dependency, quality, and AI-defect checks in addition to dead code. |
| Dead code | Unused functions, classes, imports, variables, parameters, files, unnecessary exports, and unreachable code. |
| Security / danger | Potentially exploitable code paths such as injection, SSRF, path traversal, weak crypto, unsafe deserialization, and CI/CD supply-chain risk. |
| Secrets | Hardcoded credentials, tokens, API keys, and client-side exposure of server-only values. |
| Quality | Maintainability, complexity, architecture, resilience, typing, framework practice, and repo policy issues. |
| AI defects | Evidence-backed AI-code failure modes such as hallucinated APIs, impossible dependencies, phantom references, and weakened tests. Run with `--ai-defects`; full audits include it. Output uses the `ai_defects` bucket; individual findings use category `ai_defect`. |
| AI code mistakes | Hallucinated security calls, phantom decorators, unfinished stubs, disabled controls, placeholder data, stale mocks, and missing timeouts. |
| Security quick | `skylos agent security-quick .`; one-shot LLM security audit, equivalent to `skylos agent scan . --security`. |
| Security deep | `skylos agent security-deep .`; three-stage security workflow for threat-model context, static threat tracing, discovery/validation, and remediation handoff, equivalent to `skylos agent audit . --deep`. |
| Threat trace | Static source-to-sink evidence showing how user-controlled input reaches a sensitive sink, recorded on security-deep findings and run artifacts. |
| LLM app defense | `skylos defend .`; checks LLM integrations for guardrails such as tool safety, output validation, rate limits, and prompt-injection exposure. |
| Prompt templates | Maintainer-provided files under `[tool.skylos.templates]` that extend built-in LLM prompts without replacing safety and JSON-output contracts. |
| Vibe dictionary | Project-specific keyword extensions under `[tool.skylos.vibe]` for phantom security names, credential names, sensitive files, and timeout-required calls. |
| Quality gate | A threshold-based pass/fail decision used locally or in CI. |
| Diff-aware scan | `--diff <base>` limits reporting to changed work so old debt does not drown out the current PR. |
| Baseline | A saved set of accepted existing findings so only new or changed findings fail a gate. |
| Suppression | An inline or config-level exception for an intentional finding, usually using `skylos: ignore[SKY-...]`. |
| Smart tracing | `--trace`; runtime-assisted dead-code verification used to reduce false positives in dynamic Python code. |
| Technical debt | `skylos debt .`; ranks maintainability hotspots and debt trends. |
| TUI | `--tui`; screen-only selectable terminal interface with category list, finding list, and detail pane. |
| Pretty output | `--format pretty`; compact file-grouped terminal output with severity rails, snippets, and copyable `file:line` locations. |
| Concise output | `--format concise`; plain `file:line` output for editors, scripts, and agents. |
| Structured output | `--format json`, `--format llm`, or `--format github` for machines, LLM consumers, and GitHub annotations. |
| Upload / Cloud workflow | Optional upload of scan results to Skylos Cloud; not required for local analysis. |
| MCP server | Integration surface for AI agents and coding assistants. |
| SCA | Software composition analysis for dependency vulnerability findings. |
| Symlink safety | Checks for file operations that follow repository-controlled symbolic links across the intended scan or output boundary. |

## CLI Output Modes

| Mode | Command | Intended Use |
|:---|:---|:---|
| Rich/default | `skylos .` | Existing full terminal report. |
| Pretty | `skylos . --format pretty` | Human terminal triage with grouped findings and copyable locations. |
| Concise | `skylos . --format concise` | Editors, test scripts, and agents that need plain `file:line` findings. |
| JSON | `skylos . --format json` or `skylos . --json` | Structured machine output. |
| LLM | `skylos . --format llm` or `skylos . --llm` | LLM-oriented structured report with code context. |
| GitHub | `skylos . --format github` or `skylos . --github` | GitHub annotation output. |
| TUI | `skylos . --tui` | Screen-only selectable keyboard-driven terminal triage. |

See [docs/cli-output.md](./docs/cli-output.md).

## Security / Danger (SKY-D)

Rule IDs are unified across languages where the same vulnerability exists.

| ID | Severity | Name | Languages / Scope | CWE / OWASP |
|:---|:---|:---|:---|:---|
| D200 | varies | Dangerous function call family | Python | wrapper for D201-D210, D233, D235, D250 |
| D201 | HIGH-CRITICAL | Dynamic code execution: `eval` | Python, TS/JS, Java, audit | CWE-95 / A03 |
| D202 | HIGH-CRITICAL | Dynamic code execution: `exec`, `new Function`, string timers | Python, TS/JS | CWE-95 / A03 |
| D203 | CRITICAL | OS command execution: `os.system` / process sinks | Python, Java | CWE-78 / A03 |
| D204 | CRITICAL | Unsafe deserialization: `pickle.load` and language equivalents | Python, Java, PHP, audit | A08 |
| D205 | CRITICAL | Unsafe deserialization: `pickle.loads` | Python | A08 |
| D206 | HIGH | `yaml.load` without SafeLoader | Python | A08 |
| D207 | MEDIUM | Weak hash: MD5 | Python, TS/JS, Go, Java | CWE-328 |
| D208 | MEDIUM | Weak hash: SHA1 | Python, TS/JS, Go, Java | CWE-328 |
| D209 | HIGH | `subprocess` with `shell=True` | Python | CWE-78 / A03 |
| D210 | HIGH | TLS verification disabled | Python, Go | A02 |
| D211 | CRITICAL | SQL injection | Python, TS/JS, Go, Java, PHP, audit | CWE-89 / A03 |
| D212 | CRITICAL | Command injection | Python, TS/JS, Go, Java, Rust, Dart, Shell, audit | CWE-78 / A03 |
| D214 | HIGH | Broken access control | Python | A01 |
| D215 | HIGH | Path traversal and archive extraction traversal | Python, TS/JS, Go, Java, PHP, Rust, Dart, Shell | CWE-22 / A01 |
| D216 | CRITICAL | Server-side request forgery | Python, TS/JS, Go, Java, Dart, Shell, audit | CWE-918 / A10 |
| D217 | CRITICAL | Raw SQL / ORM SQL injection | Python | CWE-89 / A03 |
| D220 | CRITICAL | SQL injection in added code / diff validation | MCP code-change validator | CWE-89 / A03 |
| D223 | MEDIUM | Undeclared third-party dependency | Python | supply-chain |
| D226 | CRITICAL | XSS: unsafe DOM or HTML rendering | Python, TS/JS, Java, audit | CWE-79 / A03 |
| D227 | HIGH | XSS: unsafe template rendering | Python | CWE-79 / A03 |
| D228 | HIGH | XSS: unescaped HTML output | Python | CWE-79 / A03 |
| D230 | HIGH | Open redirect | Python, TS/JS, Go, Java, audit | CWE-601 / A01 |
| D231 | HIGH | CORS misconfiguration | Python | A05 |
| D232 | CRITICAL | JWT verification disabled or unsafe algorithm | Python | A02 |
| D233 | HIGH-CRITICAL | Unsafe deserialization: marshal, shelve, jsonpickle, dill | Python | A08 |
| D234 | HIGH | Mass assignment | Python | A01 |
| D235 | HIGH | Remote command execution via `exec_command` | Python | CWE-78 |
| D240 | CRITICAL | MCP tool description poisoning | Python, Java | A03 |
| D241 | HIGH | MCP unauthenticated transport | Python, Java | A07 |
| D242 | HIGH | MCP permissive URI / path traversal | Python | A01 |
| D243 | CRITICAL | MCP server bound to `0.0.0.0` | Python | exposure |
| D244 | CRITICAL | MCP hardcoded secrets in tool params | Python | CWE-798 |
| D245 | HIGH | Dynamic `require()` with variable argument | TS/JS | CWE-94 / A03 |
| D246 | HIGH | JWT decode without verification | TS/JS | CWE-347 / A02 |
| D247 | MEDIUM | CORS wildcard origin | TS/JS | CWE-942 / A05 |
| D248 | MEDIUM | Hardcoded internal URL | TS/JS | CWE-798 |
| D250 | MEDIUM | Insecure randomness for security-sensitive values | Python, TS/JS, Go, Java | CWE-330 |
| D251 | HIGH | Sensitive data in logs | TS/JS | CWE-532 |
| D252 | MEDIUM | Insecure cookie flags | TS/JS, Go, Java | CWE-614 |
| D253 | MEDIUM | Timing-unsafe comparison | TS/JS, Java | CWE-208 |
| D260 | HIGH-CRITICAL | Prompt injection scanner | Text, config, prompt, and source files | AI supply-chain |
| D261 | HIGH | Untrusted input to LLM prompt | Python | OWASP LLM01 |
| D262 | CRITICAL | Unsafe LLM output handling | Python | OWASP LLM05 |
| D263 | HIGH | Sensitive data sent to LLM | Python | OWASP LLM02 |
| D264 | HIGH | Excessive agent tool privilege | Python | OWASP LLM06 |
| D265 | HIGH-CRITICAL | Unsafe ML model deserialization | Python | OWASP LLM04 |
| D266 | CRITICAL | AI config instruction injection | Agent config and instruction files | OWASP LLM01 |
| D267 | MEDIUM | Unbounded LLM consumption | Python | OWASP LLM10 |
| D270 | MEDIUM | Sensitive data in `localStorage` / `sessionStorage` | TS/JS | CWE-922 |
| D271 | MEDIUM | Error information disclosure in HTTP responses | TS/JS | CWE-209 |
| D280 | HIGH | Next.js mutating API route missing auth checks | TS/JS | A01 |
| D281 | HIGH | SQL injection in server actions via template literals | TS/JS | CWE-89 |
| D282 | HIGH | Webhook handler missing signature verification | Python, TS/JS | CWE-347 |
| D510 | HIGH | Prototype pollution via `__proto__` | TS/JS | CWE-1321 |

### AI Supply Chain Security

| ID | Severity | Name | File Types | Details |
|:---|:---|:---|:---|:---|
| D260 | HIGH-CRITICAL | Prompt injection scanner | `.py`, `.md`, `.rst`, `.txt`, `.yaml`, `.yml`, `.json`, `.toml`, `.env` | Multi-file scanner with text canonicalization |

Finding types:

- `literal_payload`: direct instruction override, role hijacking, suppression, or exfiltration phrase.
- `hidden_char`: zero-width or invisible Unicode.
- `obfuscated_payload`: encoded string that decodes to injection content.
- `mixed_script`: Cyrillic or Greek homoglyphs mixed with Latin text.
- `risky_placement`: injection in a high-risk README, prompt field, YAML, or JSON field.

### AI Application Security

| ID | Severity | Name | Languages | Details |
|:---|:---|:---|:---|:---|
| D261 | HIGH | Untrusted input to LLM prompt | Python | Request-controlled data reaches an LLM prompt or message without a clear instruction/data boundary |
| D262 | CRITICAL | Unsafe LLM output handling | Python | Model output flows into code execution, shell, SQL, or network sinks without validation |
| D263 | HIGH | Sensitive data sent to LLM | Python | Secrets, credential fields, or sensitive environment values flow into LLM or embedding API input |
| D264 | HIGH | Excessive agent tool privilege | Python | Agent frameworks are granted shell, code execution, unrestricted HTTP, or broad file-management tools |
| D265 | HIGH-CRITICAL | Unsafe ML model deserialization | Python | Pickle-backed model/checkpoint loading such as `torch.load`, `joblib.load`, or `numpy.load(..., allow_pickle=True)` |
| D266 | CRITICAL | AI config instruction injection | Agent config and instruction files | D260-style hidden, obfuscated, or instruction-override payloads in AI assistant rule/config files |
| D267 | MEDIUM | Unbounded LLM consumption | Python | LLM calls or agent executors lack token, timeout, iteration, or obvious loop bounds |

### MCP Server Security

| ID | Severity | Name | Languages |
|:---|:---|:---|:---|
| D240 | CRITICAL | MCP tool description poisoning | Python, Java |
| D241 | HIGH | MCP unauthenticated transport | Python, Java |
| D242 | HIGH | MCP permissive URI / path traversal | Python |
| D243 | CRITICAL | MCP server bound to `0.0.0.0` | Python |
| D244 | CRITICAL | MCP hardcoded secrets in tool params | Python |

### Filesystem And Archive Safety

| ID | Severity | Name | Languages / Scope |
|:---|:---|:---|:---|
| D324 | HIGH | Symlink-following file write | Python |
| D325 | MEDIUM | Symlink-following file read | Python |
| D326 | HIGH | Unsafe archive extraction | Python |

### Agent And Build Command Safety

| ID | Severity | Name | Languages / Scope |
|:---|:---|:---|:---|
| D327 | CRITICAL | Data exfiltration command | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D328 | HIGH | Remote script piped to shell | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D329 | HIGH | Broad destructive command | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D337 | HIGH | Package registry or index override | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D338 | CRITICAL | Sensitive host scope access | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D339 | HIGH | Persistent environment mutation | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D340 | HIGH | Unapproved package or artifact publish | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D341 | HIGH | Untrusted package-managed tool execution | Shell, Python, TS/JS, GitHub Actions, GitLab CI, Dockerfile |
| D342 | HIGH | Dockerfile remote ADD without checksum | Dockerfile |
| D343 | HIGH | Dockerfile literal secret build value | Dockerfile |
| D344 | HIGH | Trojan Source bidirectional Unicode | Python |
| D345 | HIGH | Mutable Hugging Face artifact revision | Python |
| D346 | HIGH | Flask debug mode enabled | Python |
| D347 | MEDIUM | Unsafe logging config listener | Python |
| D348 | HIGH | Insecure temporary filename | Python |

### Config And Deployment Security

| ID | Severity | Name | Provider |
|:---|:---|:---|:---|
| D290 | HIGH | Dangerous trigger (`pull_request_target`, `workflow_run`) | GitHub Actions |
| D291 | MEDIUM-HIGH | Missing or excessive permissions | GitHub Actions |
| D292 | MEDIUM | Unpinned action or reusable workflow | GitHub Actions |
| D293 | MEDIUM | Checkout persists credentials | GitHub Actions |
| D294 | HIGH | Template injection from untrusted context | GitHub Actions |
| D295 | HIGH | Self-hosted runner exposure | GitHub Actions |
| D296 | MEDIUM | Unpinned container image | GitHub Actions |
| D297 | HIGH | Secrets inheritance into reusable workflow | GitHub Actions |
| D298 | MEDIUM | Overprovisioned secrets | GitHub Actions |
| D299 | HIGH | Secret used outside protected environment | GitHub Actions |
| D300 | HIGH | Unsafe environment file write | GitHub Actions |
| D301 | HIGH | Hardcoded container credentials | GitHub Actions |
| D302 | HIGH | Broad GitHub App token permissions | GitHub Actions |
| D303 | MEDIUM | Unsound `contains()` condition | GitHub Actions |
| D304 | MEDIUM | Spoofable bot condition | GitHub Actions |
| D305 | MEDIUM | Unsound multiline condition | GitHub Actions |
| D306 | HIGH | Insecure commands enabled | GitHub Actions |
| D307 | MEDIUM | Anonymous action/workflow definition | GitHub Actions |
| D308 | HIGH | Cache poisoning risk | GitHub Actions |
| D309 | HIGH | Broad secret environment exposure | GitHub Actions |
| D310 | HIGH | OIDC token exposed to local build script | GitHub Actions |
| D311 | MEDIUM | Lax artifact upload | GitHub Actions |
| D312 | MEDIUM | JavaScript install scripts in CI | GitHub Actions |
| D313 | MEDIUM | Privileged job missing timeout | GitHub Actions |
| D314 | HIGH | Mutable container image | GitLab CI |
| D315 | HIGH | Unpinned external include | GitLab CI |
| D316 | HIGH | Literal secret variable | GitLab CI |
| D317 | HIGH | Untrusted eval | GitLab CI |
| D318 | HIGH | Docker-in-Docker TLS disabled | GitLab CI |
| D319 | HIGH | OIDC local-script exposure | GitLab CI |
| D320 | HIGH | Release cache poisoning risk | GitLab CI |
| D321 | MEDIUM | Privileged job missing timeout | GitLab CI |
| D322 | MEDIUM | Dynamic runner tag | GitLab CI |
| D323 | MEDIUM | Ambiguous secret token | GitLab CI |
| D330 | HIGH | Privileged edge container | Docker Compose |
| D331 | HIGH | Host device exposure | Docker Compose |
| D332 | MEDIUM | Host networking on edge service | Docker Compose |
| D333 | HIGH | Edge service runs as root | systemd |
| D334 | HIGH | Root service executes mutable path | systemd |
| D335 | MEDIUM | Edge service missing sandboxing | systemd |
| D336 | HIGH | Broad edge service privilege | systemd |

## Secrets (SKY-S)

| ID | Severity | Name | Languages / Scope | CWE |
|:---|:---|:---|:---|:---|
| S101 | CRITICAL | Hardcoded secret / API key | Python, TS/JS, Java, Go, config files | CWE-798 |
| S102 | HIGH | Server-only environment variable exposed to client component | TS/JS, Next.js | CWE-200 |

## Security Contracts (SKY-SC)

| ID | Severity | Name | Scope |
|:---|:---|:---|:---|
| SC001 | HIGH | Security contract regression | Diff-aware CI/CD review |

## Go-Specific Raw Rules (SKY-G)

The Go engine may emit `SKY-G` IDs. Cross-language equivalents are remapped to
`SKY-D` before normal reporting where possible.

| Go Output | Unified ID | Vulnerability |
|:---|:---|:---|
| SKY-G203 | SKY-G203 | Defer in loop / resource leak risk |
| SKY-G206 | SKY-G206 | Unsafe package usage |
| SKY-G207 | SKY-D207 | Weak MD5 |
| SKY-G208 | SKY-D208 | Weak SHA1 |
| SKY-G209 | SKY-D250 | Weak random source |
| SKY-G210 | SKY-D210 | TLS verification disabled |
| SKY-G211 | SKY-D211 | SQL injection |
| SKY-G212 | SKY-D212 | Command injection |
| SKY-G215 | SKY-D215 | Path traversal |
| SKY-G216 | SKY-D216 | SSRF |
| SKY-G220 | SKY-D230 | Open redirect |
| SKY-G221 | SKY-D252 | Insecure cookie flags |
| SKY-G260 | SKY-G260 | Unclosed resource |
| SKY-G280 | SKY-G280 | Weak TLS version |
| SKY-G305 | SKY-D215 | Archive extraction path traversal |

## AI Defects

AI-defect grouping is based on finding category, not only the rule-ID prefix.
The CLI flag is `--ai-defects`, JSON reports use the top-level `ai_defects`
bucket, and individual findings use category `ai_defect`. Some hallucination
rules keep historical `SKY-L` or `SKY-D` IDs for compatibility with existing
suppressions, baselines, CI policies, and docs links; new AI-defect-only rules
use the `SKY-A` prefix.

| ID | Severity | Name | Languages |
|:---|:---|:---|:---|
| A101 | MEDIUM | Test assertion weakening | Diff-aware tests |
| A102 | LOW | High-risk change without tests | Diff-aware PR signal |
| A103 | HIGH | CI permission expansion | GitHub Actions |
| A104 | MEDIUM | Public CLI surface drift | Diff-aware CLI |
| L012 | CRITICAL | Phantom function call / hallucinated security function | Python |
| L023 | CRITICAL | Phantom decorator | Python |
| D222 | CRITICAL | Dependency hallucination | Python |
| D224 | HIGH | API signature hallucination | Python |
| D225 | HIGH | Dependency version hallucination | Python, npm, Go |

## Logic and AI-Code Mistakes (SKY-L)

| ID | Severity | Name | Languages |
|:---|:---|:---|:---|
| L001 | HIGH | Mutable default argument | Python |
| L002 | MEDIUM | Bare `except` block | Python |
| L003 | LOW | Dangerous comparison (`== True`, `== False`, `== None`) | Python |
| L004 | MEDIUM | Anti-pattern try block / too broad scope | Python |
| L005 | LOW | Unused exception variable | Python |
| L006 | MEDIUM | Inconsistent return paths | Python |
| L007 | MEDIUM-HIGH | Empty error handler | Python |
| L008 | MEDIUM | Missing resource cleanup | Python |
| L009 | LOW-HIGH | Debug leftover | Python |
| L010 | MEDIUM | Security TODO/FIXME marker left in code | Python |
| L011 | MEDIUM-HIGH | Disabled security control | Python |
| L013 | HIGH | Insecure randomness for security values | Python |
| L014 | HIGH | Hardcoded credential in code | Python |
| L016 | MEDIUM | Undefined config / ghost feature flag | Python |
| L017 | MEDIUM | Error information disclosure | Python |
| L020 | HIGH | Overly broad file permissions | Python |
| L021 | HIGH | Security control regression | Diff-aware review |
| L024 | HIGH | Stale mock target | Python |
| L026 | MEDIUM | Unfinished generated function | Python |
| L027 | LOW-MEDIUM | Duplicate string literal | Python |
| L028 | MEDIUM | Too many return statements | Python |
| L029 | MEDIUM | Boolean positional parameter trap | Python |
| L030 | MEDIUM | Broad exception with trivial handler | Python |
| L031 | MEDIUM | Missing network timeout | Python |
| L032 | MEDIUM | Mock or placeholder production data | Python |
| L033 | MEDIUM | No-effect statement | Python |

## Quality, Structure, Architecture, and Performance

| ID | Severity | Name | Languages / Scope | Threshold / Notes |
|:---|:---|:---|:---|:---|
| Q301 | WARN-CRITICAL | Cyclomatic complexity | Python, TS/JS, Java, Go | default >10 |
| Q302 | MEDIUM | Deep nesting | Python, TS/JS, Java, Go | default >3 |
| Q305 | MEDIUM | Duplicate condition / duplicate branch body | Python, TS/JS | control-flow correctness |
| Q306 | MEDIUM | Cognitive complexity | Python | Sonar-style cognitive complexity |
| Q401 | HIGH | Async blocking call | Python | blocking calls inside async code |
| Q402 | MEDIUM | Await in loop | TS/JS | prefer batching |
| Q403 | HIGH | Inconsistent lock acquisition order | Python | potential deadlock from reversed nested lock order |
| Q404 | MEDIUM | Thread shared state mutation | Python | thread target mutates module state without an obvious lock |
| Q501 | MEDIUM | God class | Python | excessive methods or attributes |
| Q502 | MEDIUM-HIGH | God file | Python | excessive file size / definitions |
| Q701 | MEDIUM | High coupling | Python | CBO-style signal |
| Q702 | MEDIUM | Low cohesion | Python | LCOM-style signal |
| Q801 | MEDIUM | High architectural instability | Python |
| Q802 | MEDIUM | Distance from main sequence | Python |
| Q803 | MEDIUM | Zone of Pain / Zone of Uselessness | Python |
| Q804 | MEDIUM | Dependency Inversion Principle violation | Python |
| Q805 | MEDIUM | Architecture layer policy violation | Python |
| C303 | MEDIUM | Too many arguments | Python, TS/JS, Java, Go | default >5 required / >10 total |
| C304 | MEDIUM | Function too long | Python, TS/JS, Java, Go | default >50 lines |
| C401 | MEDIUM | Duplicated implementation fragments | Python |
| P401 | LOW | Memory risk: `file.read()` / `readlines()` | Python |
| P402 | LOW | Memory risk: `pandas.read_csv` without `chunksize` | Python |
| P403 | LOW | Nested loop O(N^2) | Python / generic |
| P404 | MEDIUM | Unbounded SQLAlchemy-style ORM `.all()` query | Python |
| T101 | MEDIUM | Missing public parameter type annotation | Python |
| T102 | MEDIUM | Missing public return type annotation | Python |
| F101 | MEDIUM | FastAPI response model / return typing practice | Python |
| F102 | HIGH | Framework endpoint missing object-level authorization guard | Python |
| R101 | MEDIUM | Repository missing Python type-check command | Repo policy |
| R102 | MEDIUM | Repository missing Python lint command | Repo policy |
| R103 | MEDIUM | Repository missing Skylos quality gate | Repo policy |
| R104 | MEDIUM | Repository missing pre-commit config | Repo policy |
| R105 | MEDIUM | Repository missing TypeScript type-check command | Repo policy |
| CIRC | varies | Circular dependency | Python |

## Dead Code and Reachability

| ID | Severity | Name | Scope |
|:---|:---|:---|:---|
| U001 | INFO | Unused function | Upload/API normalized dead-code category |
| U002 | INFO | Unused import | Upload/API normalized dead-code category |
| U003 | INFO | Unused variable | Upload/API normalized dead-code category |
| U004 | INFO | Unused class | Upload/API normalized dead-code category |
| U005 | MEDIUM | Declared dependency appears unused | Python dependencies |
| U006 | INFO | Unused parameter | Debt normalized dead-code category |
| DC001 | MEDIUM | Unused function | LLM report dead-code ID |
| DC002 | LOW | Unused import | LLM report dead-code ID |
| DC003 | MEDIUM | Unused class | LLM report dead-code ID |
| DC004 | LOW | Unused variable | LLM report dead-code ID |
| DC005 | LOW | Unused parameter | LLM report dead-code ID |
| DC006 | LOW | Empty or unused file | LLM report dead-code ID |
| UC001 | MEDIUM | Unreachable code after control-flow exit | Python |
| UC002 | MEDIUM | Unreachable code after return/throw/break/continue | TS/JS, Java |
| E002 | LOW | Empty or docstring-only file | Python |
| E003 | LOW | Unused TypeScript/JavaScript file | TS/JS |
| E004 | LOW | Unnecessary export | TS/JS |

Pretty output and the TUI use short display labels such as
`dead-code/function`, `dead-code/import`, `dead-code/class`,
`dead-code/variable`, `dead-code/parameter`, and `dead-code/file`. Those labels
are UI grouping text, not stable rule IDs; use the `SKY-*` IDs above for
suppression, integrations, and public references.

## Dependency Vulnerabilities

| ID | Severity | Name | Scope |
|:---|:---|:---|:---|
| SCA-* | varies | Software composition analysis vulnerability | Dependency manifests / installed packages |

## Aggregate, Alias, and Workflow IDs

These IDs appear in API normalization, audit workflows, LLM schemas, prompts, or
agent workflows. They are not always emitted as first-class static-analysis
findings.

| ID | Meaning |
|:---|:---|
| SKY-D000 | Generic security fallback ID for normalized external findings. |
| SKY-Q000 | Generic quality fallback ID for normalized external findings. |
| SKY-S000 | Generic secret fallback ID for normalized external findings. |
| SKY-SCA-000 | Generic dependency fallback ID for normalized external findings. |
| SKY-U000 | Generic dead-code fallback ID for agent workflows. |
| SKY-D101 | Legacy compliance alias for code injection. |
| SKY-D102 | Legacy compliance alias for code injection. |
| SKY-D103 | Legacy compliance alias for insecure deserialization. |
| SKY-AUDIT | Deep-audit candidate or artifact marker. |
| SKY-AUDIT-ENTRYPOINT | Deep-audit entrypoint candidate marker. |
| SKY-AUDIT-PATH | Deep-audit security-sensitive path candidate marker. |
| SKY-DEAD | LLM dead-code verifier marker. |
| SKY-DEAD-CHALLENGE | LLM dead-code challenge marker. |
| SKY-DEBT | Agent command-center debt marker. |
| SKY-FIX | Agent remediation / fix generation marker. |
| SKY-L000 | Generic logic fallback ID for LLM schemas. |
| SKY-C399 | Structure placeholder ID used in prompt examples. |
| SKY-Q499 | Quality placeholder ID used in prompt examples. |
| SKY-P499 | Performance placeholder ID used in prompt examples. |
| SKY-S199 | Secret placeholder ID used in prompt examples. |

Prompt text may also use range notation such as `SKY-D226-228`,
`SKY-L001-004`, or `SKY-P401-404` to describe groups of concrete rule IDs.

## Custom Rules

Custom rule packs may emit project-defined IDs from `.skylos/rules/*.yml`.
Prefer a stable project prefix, for example `ORG-SEC001`, to avoid colliding
with Skylos-owned `SKY-*` IDs.
