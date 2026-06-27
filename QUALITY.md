## Good Coding Practice Policy

Skylos treats a "good coding practice" as enforceable only when it meets at least one
of these tests:

1. It is backed by a language, security, quality, or framework standard.
2. It is enforced by a mainstream tool that the ecosystem already accepts.
3. It protects a concrete quality attribute: security, reliability, maintainability,
   performance efficiency, or API correctness.
4. It is an explicit repository policy, such as requiring type-checking, linting,
   pre-commit hooks, or a Skylos gate.

Rules that are only taste preferences should stay out of the default quality set. They
can still be project policy, but they should be configured separately and rolled out as
advisory checks first.

## Standards-Backed Practice Matrix

| Practice Area | Source / Stipulation | Skylos Coverage | CI / Tool Coverage |
|---------------|----------------------|-----------------|--------------------|
| Python style and lint hygiene | [PEP 8](https://peps.python.org/pep-0008/), [Ruff linter](https://docs.astral.sh/ruff/linter/) | `SKY-R102`, existing Python quality rules | Advisory `ruff check .` |
| Python type clarity | [PEP 484](https://peps.python.org/pep-0484/), [mypy](https://mypy.readthedocs.io/) | `SKY-T101`, `SKY-T102`, `SKY-R101` | Advisory `mypy skylos` |
| TypeScript type safety | [TypeScript strict mode](https://www.typescriptlang.org/tsconfig/strict.html) | `SKY-R105` | Advisory `npm run compile` / `npm run build` |
| Rust idioms and correctness | [Clippy](https://doc.rust-lang.org/stable/clippy/), [Rustfmt style edition](https://doc.rust-lang.org/edition-guide/rust-2024/rustfmt-style-edition.html) | Repo policy visibility through CI | Advisory `cargo fmt --check`, `cargo clippy` |
| API authorization practice | [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/), `CWE-862` | `SKY-F102`, security/danger rules | Diff-aware Skylos advisory scan |
| API response contracts | [FastAPI response models / return types](https://fastapi.tiangolo.com/tutorial/response-model/) | `SKY-F101` | Diff-aware Skylos advisory scan |
| Dependency-injected guards | [FastAPI dependencies and security](https://fastapi.tiangolo.com/tutorial/dependencies/) | `SKY-F102` | Diff-aware Skylos advisory scan |
| Maintainability and complexity | [ISO/IEC 5055:2021](https://www.iso.org/standard/80623.html), [ISO/IEC 25010:2011](https://www.iso.org/standard/35733.html), CWE complexity/coding-standard classes | `SKY-Q*`, `SKY-C*`, `SKY-L*` | Diff-aware Skylos advisory scan |
| Secure coding conventions | [CWE-710](https://cwe.mitre.org/data/definitions/710.html), OWASP API Security Top 10 | `SKY-L*`, `SKY-F102`, `SKY-R*` | Diff-aware Skylos advisory scan |
| Repository enforcement policy | Repo-local `pyproject.toml`, `.pre-commit-config.yaml`, CI workflow policy | `SKY-R101` through `SKY-R105` | Advisory quality workflow and Skylos advisory gate |

## Rule Catalog

| Rule | ID | What It Catches |
|------|-----|-----------------|
| **Complexity** | | |
| Cyclomatic complexity | SKY-Q301 | Too many branches/loops (default: >10) |
| Deep nesting | SKY-Q302 | Too many nested levels (default: >3) |
| Duplicate branch logic | SKY-Q305 | Duplicate conditions or duplicate branch bodies |
| Cognitive complexity | SKY-Q306 | Nested/control-flow complexity that is hard to reason about |
| **Structure** | | |
| Too many arguments | SKY-C303 | Functions with >5 args |
| Function too long | SKY-C304 | Functions >50 lines |
| Clone group | SKY-C401 | Duplicated implementation fragments |
| **Logic** | | |
| Mutable default | SKY-L001 | `def foo(x=[])` - causes state leaks |
| Bare except | SKY-L002 | `except:` swallows SystemExit |
| Dangerous comparison | SKY-L003 | `x == None` instead of `x is None` |
| Anti-pattern try block | SKY-L004 | Nested try, or try wrapping too much logic |
| Unused exception variable | SKY-L005 | `except ValueError as e:` where `e` is never used |
| Inconsistent return | SKY-L006 | Mixed value returns and bare/`None` returns |
| Empty error handler | SKY-L007 | Silent `except: pass` / swallowed context-manager errors |
| Missing resource cleanup | SKY-L008 | `open()` without a context manager or close path |
| Debug leftover | SKY-L009 | `print()` / `breakpoint()` in production code |
| Security TODO | SKY-L010 | Comments that defer auth/security fixes |
| Disabled security control | SKY-L011 | Calls/settings that disable TLS, CSRF, or validation |
| Insecure random | SKY-L013 | Security-sensitive use of weak random sources |
| Hardcoded credential | SKY-L014 | Credential-looking constants in source |
| Undefined config | SKY-L016 | Environment/config references with no declared default |
| Error disclosure | SKY-L017 | Exception details returned from handlers |
| Broad file permissions | SKY-L020 | World-writable or overly broad file modes |
| Stale mock | SKY-L024 | Tests mocking symbols that no longer exist |
| Unfinished generation | SKY-L026 | Placeholder/generated functions left incomplete |
| Duplicate string literal | SKY-L027 | Repeated long literals that should be named constants |
| Too many returns | SKY-L028 | Functions with excessive exit paths |
| Boolean trap | SKY-L029 | Public APIs with unclear boolean flags |
| Broad exception | SKY-L030 | Broad `Exception` handlers with trivial bodies |
| Missing network timeout | SKY-L031 | HTTP calls without explicit timeout |
| **Type Checking** | | |
| Untyped public parameters | SKY-T101 | Public functions in typed modules missing parameter annotations |
| Missing public return type | SKY-T102 | Public functions in typed modules missing return annotations |
| **Framework Practices** | | |
| FastAPI response contract | SKY-F101 | Route lacks `response_model`, `response_class`, or return annotation |
| Mutating route auth guard | SKY-F102 | POST/PUT/PATCH/DELETE route lacks obvious auth/dependency guard |
| **Performance** | | |
| Memory load | SKY-P401 | `.read()` / `.readlines()` loads entire file |
| Pandas no chunk | SKY-P402 | `read_csv()` without `chunksize` |
| Nested loop | SKY-P403 | O(N²) complexity |
| Await in loop | SKY-Q402 | Awaiting serially inside loops where batching may be intended |
| **Async / Class Design** | | |
| Blocking call in async code | SKY-Q401 | Synchronous I/O or blocking calls in async handlers |
| God class | SKY-Q501 | Classes with too many methods or attributes |
| God file | SKY-Q502 | Files with too many code lines or too many responsibilities |
| Coupling | SKY-Q701 | Classes coupled to too many other classes |
| Low cohesion | SKY-Q702 | Classes whose methods do not share state or responsibilities |
| **AI Defects** | | |
| Test assertion weakening | SKY-A101 | Specific or exception assertion replaced with a broad truthiness/null check, skip, or xfail |
| Phantom reference | SKY-L012 | Calls to undefined/hallucinated security helpers |
| Phantom decorator | SKY-L023 | Security decorators that are not defined or imported |
| Hallucinated dependency | SKY-D222 | Imported package does not exist in the package registry |
| API signature hallucination | SKY-D224 | Real package called with an invented API or keyword |
| Dependency version hallucination | SKY-D225 | Manifest pins a package version that does not exist |
| **Architecture** | | |
| High instability | SKY-Q801 | Module dependency instability is above policy |
| High main-sequence distance | SKY-Q802 | Module architecture is far from abstractness/instability balance |
| Architecture zone warning | SKY-Q803 | Module falls into Zone of Pain or Zone of Uselessness |
| Dependency inversion violation | SKY-Q804 | Concrete module depends on another concrete module where abstraction is expected |
| **Repository Policy** | | |
| Python type-check policy | SKY-R101 | No mypy or pyright policy is configured |
| Python lint policy | SKY-R102 | No Ruff policy is configured |
| Skylos gate policy | SKY-R103 | No `[tool.skylos.gate]` policy is configured |
| Pre-commit policy | SKY-R104 | No pre-commit config is present |
| TypeScript type-check policy | SKY-R105 | TS package lacks an npm script that runs `tsc` |
| Unused dependency | SKY-U005 | Declared dependency is not imported by reachable code |
| **Unreachable** | | |
| Unreachable Code | SKY-UC001 | `if False:` or `else` after always-true |
| Unreachable statement | SKY-UC002 | Statement after return/throw/break/continue |
| **Empty** | | |
| Empty File | SKY-E002 | Empty File |
