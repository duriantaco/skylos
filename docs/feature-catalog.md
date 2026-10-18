# Skylos CLI and Cloud Feature Catalog

For customer instructions, screenshots, worked tutorials, and task-based reference, start with the [Skylos customer guide](customer-guide.md).

Skylos combines local code analysis, checks for coding agent changes, and a Cloud workspace for repository results, review and policy. The CLI performs analysis on the developer's machine or CI runner. Cloud retains findings and evidence, coordinates review, evaluates merge policy, and integrates with repository hosts and team systems. Cloud also has hosted static scans and optional deep security scans.

This catalog describes CLI source whose package declares **4.50.1** in [pyproject.toml](../pyproject.toml), including the accompanying quality-rule changes. Cloud descriptions record the source review of **16 October 2026**, including additions whose deployment was not established. The Cloud application is located at `/Users/oha/skylos-cloud/skylos-cloud`. Feature availability can depend on language, plan, role, external service configuration, and deployment flags. Published live commercial terms differ from the local Cloud purchase implementation; the differences and verification results appear near the end.

## Product overview

| Surface | Main capabilities | Where work runs |
| --- | --- | --- |
| Local CLI | Dead code, security, secrets, dependency risks, quality, AI code defects, reports, baseline and diff review | Local machine or CI runner |
| Change and completion checks | `done`, `verify`, contracts, protected files, test integrity, reproducible receipts | Local machine or CI runner; some commands execute tests |
| Agent workflows | Model-assisted review, dead-code verification, security review, remediation, behavior tests, hooks, watch and MCP tools | Locally, with selected external models/services where configured |
| Developer integrations | GitHub Action, generated CI workflows, pre-commit, VS Code, Python API, Cloud authentication and sync | Editor, local tools and CI |
| Cloud workspace | Projects, scans, issue lifecycle, PR evidence, policy, agent oversight, governance and reporting | Next.js application and Supabase |
| Hosted scanning | Isolated GitHub static scans, public repository previews, optional VulnHunter security scans | Configured sandbox workers |
| Cloud integrations | GitHub, GitLab, Bitbucket, Azure DevOps, Jira, Slack/Discord, webhooks and read API | Cloud and connected services |
| Public site | Product guides, documentation entry points, research, public examples and read-only shared reports | Public web application |

Source references throughout identify the implementation behind each group of features. The complete built-in rule catalog, dashboard routes and API route inventory follow the workflow descriptions.

## Contents

- [CLI scanning](#cli-scanning)
- [CLI commands and workflows](#cli-commands-and-workflows)
- [Cloud features](#cloud-features)
- [Cloud plans and action costs](#cloud-plans-and-action-costs)
- [Cloud accounts and administration](#cloud-accounts-and-administration)
- [Cloud public API and signed verdicts](#cloud-public-api-and-signed-verdicts)
- [Live site differences and verification](#live-site-differences-and-verification)
- [Complete built-in rule catalog](#complete-built-in-rule-catalog)
- [Cloud dashboard screen reference](#cloud-dashboard-screen-reference)
- [Cloud API route reference](#cloud-api-route-reference)

## Source scope for quality and pull-request review

The [rule dictionary](../dictionary.md) records the detailed scope of the accompanying Python quality changes. Typing advice follows an incomplete signature or an applicable declared mypy policy; a typing import or typed sibling alone does not require annotations throughout a module. Size rules count code lines, and receiver-aware argument and cohesion measurements distinguish implementation from declarations and protocol behavior. Design advice has explicit test/example/build-support exclusions; these do not exempt security findings.

Security TODO markers come from actual comments and genuine docstrings. Error-disclosure messages distinguish exception text from stack traces and state when client exposure is an assumption. A quality-rule failure produces incomplete-analysis evidence while security and dead-code analysis remain available. Dependency declarations are read within the scanned project's manifest or Git boundary.

Python F102 distinguishes state-changing methods from query-like POST operations using supported body effects; endpoint names or a recognized dependency do not prove access control. L007 separates meaningful recovery and narrow fallbacks from silent errors, and permits only the supported deletion-cleanup exemption in finally blocks. Interrupt-swallowing handlers retain review. P403 includes supported filter/generator searches and stable reopened-file scans, while arbitrary per-item paths and unresolved source properties do not establish repeated work.

Python import checks can also recognize supported plain Pipfile/conda declarations and bounded straight-line install evidence from setup scripts or an unambiguous final Dockerfile stage. A nearer Python manifest sets the environment boundary. Conditional execution, changed install targets, ambiguous stages and lockfile-only transitive dependencies do not establish that an import is declared. These inputs are parsed, never executed.

Impact mode compares base and head dead-code findings and can name newly-unused code on untouched lines. PR summaries also cover introduced findings beyond the inline-comment cap or after failed inline posting. Legacy comments without symbol-specific keys may be repeated once as precise keyed comments. Snapshot omissions and incomplete-analysis behavior are documented in [PR impact](pr-impact.md). These source capabilities do not establish that every generated CI setup enables impact mode.

## CLI scanning

### Installation and basic operation

Skylos is a Python CLI requiring Python 3.10 or later. The main source scan accepts one or more files or directories. A default scan focuses on dead code. The main analyzer families can be enabled independently or together with `-a` / `--all`.

~~~bash
pip install skylos
pip install 'skylos[llm]'      # Optional model integrations
pip install 'skylos[lint]'     # Optional Ruff integration
pip install 'skylos[dart]'     # Optional Dart grammar; installation compiles C
pip install 'skylos[all]'

skylos .
skylos src tests --format json
skylos . -a --format json-ci
skylos . --danger --secrets
skylos . --quality --ai-defects
skylos . --sca
~~~

`-a` enables danger, secrets, quality, AI defect, and dependency vulnerability scanning in addition to dead code. It does not mean every subcommand or every catalogued rule runs: change verification, artifact inspection, container scanning, runtime tracing, model verification, and several AI change guardrails have their own triggers. Project configuration can also enable analyzer families. The normal source analysis path parses code without executing the target project's application code or tests. Dependency and registry truth checks can make network requests.

Evidence: [package metadata and extras](../pyproject.toml), [main source-scan parser](../skylos/cli_core/main_parser.py), [family switches](../skylos/cli_core/main_parser.py), [configuration defaults](../skylos/config.py).

### Language and file coverage

| Language or file type | Accepted source suffixes | Implemented scope and practical limits |
| --- | --- | --- |
| Python | `.py`, `.pyi`, `.pyw` | Broadest support: AST and cross-file dead code, framework and package entrypoints, security flows, quality and architecture, secrets, API and dependency truth checks, optional runtime evidence. |
| TypeScript and JavaScript | `.ts`, `.tsx`, `.mts`, `.cts`, `.js`, `.jsx`, `.mjs`, `.cjs` | Tree-sitter symbols, imports/exports, workspace resolution, framework entrypoints, unused files, language-specific security and async/type-safety quality rules, secrets, supported local/package API checks. |
| Go | `.go` | Symbol and security analysis through the separate `skylos-go` engine, with tree-sitter quality checks; secrets, Go module SCA and API checks. A working engine binary is required for the engine-backed checks. Exported symbols are conservatively treated as used. |
| Java | `.java` | Tree-sitter definitions and references, framework annotations and FXML references, security flow and property evidence, complexity/size/parameter/nesting checks and unreachable statements, supported API checks. Java source is absent from the current secret suffix allowlist. |
| PHP | `.php` | Tree-sitter symbols and references, Laravel conventions; focused request-source path traversal and unsafe `unserialize` checks; secrets. The Python quality rule suite is not ported here. |
| Rust | `.rs` | Tree-sitter symbols, references and import/use data; focused tainted command execution and filesystem path checks; secrets. No full Rust type checker or Python quality-rule parity. |
| Dart | `.dart` | Optional tree-sitter grammar, definitions/references/test roots; focused command execution, SSRF and filesystem path checks; secrets. Install the `dart` extra. |
| C# | `.cs` | Conservative lexical symbol and reference analysis, application reachability and private-member liveness; focused command execution, SQL injection, path traversal, SSRF and open redirect; unreachable-statement quality checks; secrets; exact supported NuGet project dependencies. |
| Kotlin | `.kt`, `.kts` | Conservative lexical symbol/reference/import collection, cross-JVM references and test annotation roots; secrets. The current scanner returns no Kotlin-specific danger or quality findings. |
| C++ | `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx` | Tree-sitter function/reference collection; only plainly file-local free functions in source files are eligible for unused reporting (`static` or anonymous-namespace functions, with conservative ambiguity guards). Class members, templates, header functions, macros, overload/linker semantics and public C++ APIs are outside that reporting promise. Current C++ adapter returns no C++ danger or quality findings, and the secret suffix allowlist excludes these files. `.c` and `.h` are not C++ scan inputs. |
| Shell | `.sh`, `.bash`, `.zsh`, `.ksh`, `.bats` | Focused static security and command-guard checks, including tainted command/path/URL use and dangerous command patterns. No shell symbol/dead-code or quality analysis; these suffixes are absent from the current secret allowlist. |
| Configuration and web assets | Supported YAML, JSON, TOML, INI/CFG/CONF/lock, `.env` variants and selected HTML/CSS/source-map assets | Secret checks and dedicated configuration/security checks where applicable. These are not general-purpose language analyzers. |

Vue single-file components (`.vue`) are currently skipped, including explicit Vue targets. Framework awareness for JavaScript does not imply a Vue component parser. Build files with C/CUDA suffixes may be read as GPU configuration evidence; that does not add general C or CUDA source analysis.

Evidence: [source dispatch](../skylos/analysis/file_processing.py), [C++ extensions and adapter](../skylos/visitors/languages/cpp/__init__.py), [Kotlin adapter](../skylos/visitors/languages/kotlin/__init__.py), [C# adapter](../skylos/visitors/languages/csharp/__init__.py), [shell adapter](../skylos/visitors/languages/shell/__init__.py), [Go adapter](../skylos/visitors/languages/go/go.py), [secret suffix allowlist](../skylos/rules/secrets.py), [Vue skip tests](../test/test_vue_scan.py).

### Dead code and framework awareness

The CLI reports unused functions/methods, imports, variables, classes and parameters. Additional checks identify unused supported dependencies, empty files, unused TypeScript/JavaScript files and unreachable statements. Findings carry a confidence score; `--confidence` / `-c` defaults to 60 and adjusts candidate reporting from 0 to 100.

Analysis combines symbol definitions and references, imported names, exports, call relationships, attribute and receiver evidence, implicit protocol methods, annotations, package metadata, and framework roots. The Python reachability pass can identify a group of mutually referencing functions with no reachable caller. Ambiguous dynamic uses remain uncertainty rather than a guarantee that removal is safe. A default grep verification pass searches for otherwise missed usage; `--no-grep-verify` disables it.

The evidence model records reasons such as static reference, reachable from root, module import execution, framework root, package entrypoint, test entrypoint, dynamic pattern, coverage hit, trace hit and grep rescue. It distinguishes alive, dead, likely dead, validated dead and uncertain decisions. Full JSON can include the evidence ledger and symbol definitions; compact JSON retains evidence attached to each reported finding.

Framework and ecosystem awareness includes the following implemented areas:

- Python web routes and lifecycle handlers: Flask, FastAPI, Starlette, Django and Django REST Framework, plus supported Sanic, aiohttp, Falcon, Bottle and Tornado conventions.
- FastAPI `Depends`, `Security`, `Annotated` and registered router/application metadata.
- Django URL registrations, class-based views, model/admin/serializer/form conventions, signals, template tags, filters and template references.
- pytest tests, fixtures, hooks and plugin registration; unittest/protocol lifecycle methods and supported external callback protocols.
- Pydantic and Pydantic Settings models, validators, serializers and computed fields; dataclasses, Marshmallow schemas/hooks, SQLAlchemy models and listeners.
- Click/Typer commands and callbacks, Celery tasks/signals, pluggy hook implementations, and package scripts/plugin entrypoints declared in project metadata.
- JS/TS React/JSX references, Next.js route/file exports and conventions, tool configuration entrypoints, package export maps, workspace/package imports, TypeScript path resolution, browser/HTML references and supported MDX imports.
- Java annotations and JavaFX FXML controller/event references; Laravel convention roots for PHP; test and exported API conventions in the other supported collectors.

Users can add explicit dead-code entrypoints using `[tool.skylos.dead_code]`. Selectors include symbol type/name/full name, decorator, base class, parent class, module and path, with a reason. The implementation requires a specific symbol/decorator/base/parent selector; a broad path alone is not enough.

~~~bash
skylos . --confidence 80 --format json
skylos . --no-grep-verify --format json
~~~

Evidence: [rule catalog](../skylos/rules/catalog.py), [confidence flag](../skylos/cli_core/main_parser.py), [Python reachability](../skylos/deadcode/reachability.py), [evidence states and reasons](../skylos/deadcode/evidence.py), [framework patterns](../skylos/visitors/framework_aware.py), [configured entrypoints](../skylos/deadcode/config_entrypoints.py), [TypeScript framework support](../skylos/visitors/languages/typescript/framework.py), [Django template liveness](../skylos/deadcode/django_template_liveness.py), [Java FXML references](../skylos/deadcode/java_fxml_refs.py).

#### Optional runtime evidence

`--trace` runs tests with call tracing to capture dynamic dispatch. `--cache`, `--refresh-cache` and `--no-cache` control successful trace-run reuse. `--coverage` can consume existing coverage evidence without running tests; `--allow-coverage-execution` explicitly permits test execution. `--pytest-fixtures` runs runtime fixture tracking and can report unused fixtures. These switches execute or can explicitly permit execution of repository code and are separate from ordinary static scans.

Evidence: [runtime flags](../skylos/cli_core/main_parser.py), [tracer](../skylos/core/tracer.py), [pytest fixture plugin](../skylos/plugins/pytest_unused_fixtures.py).

### Security analysis

`--danger` enables security checks. Coverage combines direct dangerous-call checks, language-specific source-to-sink propagation, local flow and binding/alias resolution, framework route analysis, and repository configuration inspection. Supported checks can attach CWE, trace/evidence, symbol and remediation context. Precision and flow depth vary by rule and language; this is not an assertion that every family is implemented for every language.

| Security area | Implemented checks and representative IDs |
| --- | --- |
| Code execution and deserialization | `eval`/`exec`, OS/subprocess shell execution, unsafe pickle and YAML, unsafe deserialization and model loading (`SKY-D201`–`D206`, `D209`, `D233`, `D265`). |
| Injection and web input | SQL/raw SQL injection (`D211`, `D217`), command injection (`D212`), path traversal (`D215`), SSRF (`D216`), unsafe trusted HTML and templates/XSS (`D226`–`D228`), server-side template injection (`D349`), prototype pollution (`D510`). |
| Authentication and authorization | Open redirects (`D230`), unsafe CORS (`D231`, `D247`), unsafe JWT usage (`D232`, `D246`), mass assignment (`D234`), HTTP session trust-boundary issues (`D254`), Next.js mutating API route authentication (`D280`), server-action SQL injection (`D281`), webhook signature handling (`D282`). |
| Cryptography, transport and data | Weak MD5/SHA1/randomness, disabled TLS verification, insecure cookies, timing-unsafe comparison, sensitive logs/storage, internal URL exposure and HTTP error disclosure (`D207`, `D208`, `D210`, `D248`, `D250`–`D253`, `D270`, `D271`). |
| Files and archives | Symlink-following reads/writes, unsafe archive extraction, insecure temporary names, broad permissions and sensitive host scope access (`D324`–`D326`, `D338`, `D348`; selected quality rules add related checks). |
| AI and LLM integration | Prompt injection exposure, untrusted prompt input, unsafe model output handling, sensitive data sent to a model, excessive agent tool privilege, malicious AI instruction/config files and unbounded consumption (`D260`–`D267`). |
| MCP application code | Poisoned tool descriptions, unauthenticated/exposed network transports, permissive resource URIs and hardcoded tool parameter secrets (`D240`–`D244`). These inspect target MCP integrations; they are distinct from running Skylos as an MCP server. |
| Shell and package trust | Data exfiltration, remote script piped to shell, destructive commands, registry/index overrides, persistent environment changes, unapproved publishing and untrusted package-managed tool execution (`D327`–`D329`, `D337`–`D341`). |
| Additional dangerous patterns | Dynamic `require`, remote command sinks, Trojan Source bidi Unicode, mutable Hugging Face revisions, Flask debug mode, unsafe logging listener (`D235`, `D245`, `D344`–`D347`). |
| Go-specific checks | Defer in loops, `unsafe` import, resource closure and TLS versions, plus Go implementations of SQL/command/path/SSRF/hash/random/cookie/redirect checks. Several legacy `SKY-G*` IDs are normalized to common `SKY-D*` IDs in scan results. |

The AI config scanner reads supported instruction locations such as AGENTS/CLAUDE-style files, Cursor rules and related project instructions, within bounded file/size limits. It does not need to execute the instructions it scans. Security findings can receive compliance mapping metadata where defined for OWASP Top 10, PCI DSS 4.0, SOC 2, HIPAA and ISO 27001; mappings are finding references, not a compliance certification.

`--verify-security` optionally asks a configured model to assess the highest-severity findings several times. Controls include run count, maximum findings, model and provider. It records evidence levels such as traced, AI-verified, likely false positive and unverified. Parser documentation explicitly says this enrichment is display-only and never changes which findings block the gate.

Security contracts can require named guards on configured FastAPI handlers and report a disappeared route or removed guard. This is the implementation behind `SKY-SC001`; the registry's historical label "Smart contract security issue" does not describe blockchain or Solidity analysis. Sources: [security contracts](../skylos/security/contracts.py), [route comparison](../skylos/security/contracts.py).

~~~bash
skylos . --danger --format json
skylos . --select SKY-D211,SKY-D215 --format concise
skylos . --danger --verify-security --verify-runs 3 --verify-max 20
~~~

Evidence: [security catalog](../skylos/rules/catalog.py), [Python dangerous/flow orchestration](../skylos/rules/danger/danger.py), [Python taint analysis](../skylos/rules/danger/taint.py), [TS binding and security-flow model](../skylos/visitors/languages/typescript/security_flow.py), [Java flow analysis](../skylos/visitors/languages/java/flow.py), [Go rule normalization](../skylos/visitors/languages/go/go.py), [AI instruction scanning](../skylos/security/injection_scanner.py), [security verification flags](../skylos/cli_core/main_parser.py), [compliance mappings](../skylos/rules/compliance.py).

#### CI container deployment and GPU configuration checks

Security scans inspect supported repository configuration even when a repository has no supported application source. CI contracts can also be inspected from a source subdirectory when Skylos establishes the owning Git repository.

| Configuration area | Features |
| --- | --- |
| GitHub Actions | Dangerous triggers, excessive permissions, unpinned actions/images, persisted checkout credentials, expression/template injection, self-hosted runners, inherited/overprovided/secrets outside environments, unsafe environment-file writes, literal container credentials, broad GitHub App tokens, unsound or spoofable conditions, insecure runner commands, cache poisoning, broad secret environments, OIDC exposure to build scripts, artifact-upload settings, JS install scripts and missing privileged-job timeout (`D290`–`D313`). |
| AI agents in Actions | Untrusted triggers without actor gates, widened write-access checks, shell access on untrusted triggers, untrusted text in agent prompts and known advisory/version patterns for agent actions (`D350`–`D354`). |
| GitLab CI | Mutable images, external includes without pinning, literal secret variables, untrusted eval, Docker-in-Docker without TLS, OIDC/local-script exposure, release cache poisoning, missing timeout, dynamic runner tags and ambiguous secret tokens (`D314`–`D323`). |
| Dockerfiles | Remote `ADD` without checksum and literal secret build arguments/environment values (`D342`, `D343`). |
| Edge Docker Compose | Privileged containers, host devices and host networking for supported edge services (`D330`–`D332`). |
| Edge systemd | Root execution, mutable paths executed by root, missing sandboxing and broad service privilege (`D333`–`D336`). |
| Deployment exposure | Cross-file Kubernetes Ingress/Service/workload/source evidence: externally deployed routes missing declared auth guards (`SKY-DEP001`), exposed Flask debugger (`DEP002`), and reload-mode app servers (`DEP003`). Supported annotations declare network scope, source file, backend protocol and required guards. |
| GPU release contract | `.skylos/gpu-targets.yml` / `.yaml` declaration, CUDA image/driver compatibility, missing target GPU architectures and TensorRT engine portability (`SKY-GPU000`–`GPU003`). Reads supported Docker/build/source evidence statically. The separate `preflight` command inspects a built artifact. |

Evidence: [configuration scanner registry](../skylos/rules/config/registry.py), [deployment evidence contract](../skylos/rules/config/deployment/exposure.py), [GPU scanner](../skylos/rules/config/gpu/compatibility.py), [configuration rule names](../skylos/rules/catalog.py).

### Secret detection and browser exposure

`--secrets` detects provider-shaped credentials and high-entropy values, plus credentials embedded in supported URLs and configuration files. Provider patterns include GitHub, GitLab, Slack, Stripe, AWS access IDs/secret keys, Google API keys, SendGrid, Twilio and private key material. Generic secret-key names and value entropy cover additional credentials without claiming provider validation. Recognized provider tokens can also be found in decoded representations.

The scanner distinguishes structural public values such as checksums, source-map data, lockfile integrity data and public key shapes from credential-like strings. It has placeholder and test-context handling. Default `scan_ctx` skips test paths; that matters when describing coverage. Findings provide masked previews rather than presenting a full detected token as their preview.

Client exposure detection (`SKY-S102`) recognizes supported client paths, Next.js `use client`, browser assets and public environment prefixes including `NEXT_PUBLIC_`, `REACT_APP_`, `VITE_`, `NUXT_PUBLIC_`, `EXPO_PUBLIC_` and `PUBLIC_`. It follows supported alias/destructuring references to `process.env` and `import.meta.env`, and reports sensitive names exposed through these client conventions. Server-only output paths are treated separately.

~~~bash
skylos . --secrets --format json
skylos . --select SKY-S101,SKY-S102 --format concise
~~~

Evidence: [provider patterns](../skylos/rules/secrets.py), [client prefixes and paths](../skylos/rules/secrets.py), [scan defaults and suffix gate](../skylos/rules/secrets.py), [masked provider findings](../skylos/rules/secrets.py), [credential tests](../test/test_secrets_credentials.py), [public structural-shape tests](../test/test_secrets_public_shapes.py).

### Dependency vulnerabilities inventory licenses and publisher changes

`--sca` builds a static dependency inventory and queries OSV for known vulnerabilities in exact supported public package/version identities. Findings can include advisory/CVE identifiers, severity, affected/fixed version information, references, manifest locations and dependency context. This is based on parsed dependency files rather than executing a package manager or interrogating a running deployment.

| Ecosystem | Parsed sources |
| --- | --- |
| PyPI | `requirements.txt` and supported recursive includes, project/Poetry dependencies in `pyproject.toml`, statically readable `install_requires` in `setup.cfg` / `setup.py`, `uv.lock`, `poetry.lock`, `Pipfile.lock`. |
| npm | `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`. Where npm shrinkwrap takes precedence, the corresponding package lock is not double counted. |
| Go | Supported exact dependency declarations in `go.mod`. |
| NuGet | Supported unconditional exact `PackageReference` declarations in `.csproj`. Minimum/ranged, conditional, centrally supplied or mutated version identities remain explicit gaps. |

Lockfiles can add transitive packages, occurrence locations and available graph context. Inventory and query receipts describe what was found, pinned, skipped, unresolved, unsupported, limited or not checked. Public registry identity is not guessed for private, local/workspace, URL/Git or otherwise unresolved sources. Lockfile freshness and environment-marker coverage have stated limits, so the existence of an inventory does not imply every dependency in every deployed environment was checked.

PyPI vulnerability findings can be enriched through the bundled ca9 integration with reachable, statically unreachable, dynamically unreachable or inconclusive verdicts and reasons. It can consume an existing `coverage.json` from supported locations. Other ecosystem findings pass through without that Python reachability enrichment.

License policy runs with dependency scanning when configured. `license_deny`, `license_allow`, package exceptions and severity can produce `SKY-SCA-LIC001`. Offline evidence uses supported npm lock/installed package metadata and matching installed Python distribution metadata. Unknown or ambiguous licenses remain `NOASSERTION`; optional deps.dev lookup is an explicit caller option used by the SBOM workflow. License checks do not establish legal compliance.

`--scan-publisher-changes` implies `--sca` and reviews direct npm dependencies using registry history for publisher changes after dormancy. It produces a separate publisher review status/finding area. It is a supply-chain review signal rather than a CVE verdict.

~~~bash
skylos . --sca --format json
skylos . --scan-publisher-changes --format json
skylos baseline . --sca
skylos . --sca --baseline --baseline-ref origin/main --gate
~~~

Evidence: [SCA inventory and limits](../skylos/rules/sca/vulnerability_scanner.py), [manifest/lockfile registry](../skylos/rules/sca/vulnerability_scanner.py), [setuptools support](../skylos/rules/sca/vulnerability_scanner.py), [coverage receipts](../skylos/rules/sca/vulnerability_scanner.py), [Python reachability enrichment](../skylos/rules/sca/reachability.py), [license evidence and normalization](../skylos/rules/sca/licenses.py), [publisher flag](../skylos/cli_core/main_parser.py), [publisher analysis](../skylos/rules/sca/publisher_changes.py), [NuGet scope tests](../test/test_sca_nuget.py).

### Code quality maintainability architecture and reliability

`--quality` enables the implemented quality families. They include measured advice, review signals and concrete defects; the presentation records those classifications separately.

| Family | Checks |
| --- | --- |
| Complexity and size | Cyclomatic and cognitive complexity, nesting, argument count, function length, duplicate branch logic, class/file size and code clones. Configurable defaults include complexity 10, nesting 3, maximum arguments 5 and function length 50 lines. |
| Architecture | Coupling, cohesion, instability, abstractness/distance from the main sequence, architecture zones, dependency inversion, circular dependencies and explicit layer allow/deny rules. Python and JS/TS have dedicated architecture inputs. Some architecture observations are explicitly advisory; layer policy supports strict unmapped-module handling. |
| Async and concurrency | Blocking calls in async functions, await in loops, inconsistent lock order and shared state mutation; JS/TS async Promise executors, async `forEach`, discarded async `map` results. |
| Logic and errors | Mutable defaults, repeated mutable aliases, dangerous comparisons, suspicious try blocks, unused exception variables, inconsistent return/loop-variable issues, empty/broad handlers, cleanup gaps, unreachable/no-effect statements. |
| Security-adjacent quality | Disabled security controls, hardcoded credentials, insecure randomness, error disclosure, broad file permissions, missing network timeouts, security TODOs and security-control regressions. |
| Incomplete or misleading code | Debug leftovers, undefined configuration, stale mocks, unfinished generation/placeholders, mock data, duplicate strings, too many returns, boolean traps, opaque names and blanket ESLint disable. |
| Performance | Inefficient loops, repeated expensive operations, suspicious operations and unbounded eager ORM query patterns. |
| Types and frameworks | Missing annotations, weak route typing, handler conventions and supported route auth checks; TypeScript chained assertions, compiler suppressions, unvalidated JSON assertions and unsafe exported API types. |
| Repository practices | Python type-check and lint policy, Skylos gate configuration, pre-commit policy and TypeScript type-check policy. |

PR source scans also separate selected class/file size and structural concerns into `code_health`. New or worsened metrics are marked `introduced` / `worsened`; preexisting ones are counted separately. This informational collection does not itself count as a gate finding. The classification is based on supported comparison evidence and should not be represented as all-language metric regression coverage.

Reliability has its own reporting category for deployment reload-server exposure and GPU contract/compatibility findings. It is not merely a synonym for all quality findings.

Evidence: [Python rule assembly](../skylos/analysis/file_processing.py), [quality/type/practice catalog](../skylos/rules/catalog.py), [architecture computation](../skylos/analysis/architecture.py), [layer policy](../skylos/analysis/architecture_layers.py), [TS quality and type checks](../skylos/visitors/languages/typescript/quality.py), [type safety](../skylos/visitors/languages/typescript/type_safety.py), [code health partition](../skylos/rules/quality/code_health.py).

### Static AI defect checks

`--ai-defects` identifies code and change patterns associated with generated-code mistakes using concrete source, manifest, package/API and diff evidence. The checks do not establish that code was generated by AI; provenance detection is a separate feature.

- Phantom symbol/API references and phantom decorators (`SKY-L012`, `SKY-L023`), including supported local project and package API surfaces for Python, JS/TS, Java and Go. This is bounded supported API resolution, not whole-program compiler equivalence.
- Nonexistent package/dependency declarations (`SKY-D222`), unsupported named dependency versions (`D225`), undeclared third-party dependencies (`D223`, catalogued under security), and supported API-call/signature mismatch (`D224`). Registry-backed truth checks may use network data, with explicit uncertainty and coverage when evidence is unavailable.
- Diff-based assertion weakening (`SKY-A101`), risky changes without matching tests (`A102`), CI permission expansion (`A103`), public CLI surface drift (`A104`) and suspicious dependency version bumps (`A106`).
- Declared route contracts with missing guard evidence (`A105`).
- AI reviewer configuration changes (`A122`) and scanner suppression marker additions (`A125`) in the supported diff path.

The wider catalog also contains deleted/skipped/loosened tests, test execution failures, test-aware shortcuts, coverage changes, CI/scanner weakening and newly unused-code change checks. Their implementation belongs to `done` / verification/change workflows; `-a` alone does not promise to perform the complete change-integrity review.

Evidence: [AI catalog](../skylos/rules/catalog.py), [diff check orchestration](../skylos/analyzer.py), [manifest truth checks](../skylos/rules/ai_defect/manifest_dependency_hallucination.py), [Python API truth](../skylos/rules/ai_defect/python_api_hallucination.py), [JS/TS API truth](../skylos/rules/ai_defect/js_api_hallucination.py), [Java API truth](../skylos/rules/ai_defect/java_api_hallucination.py), [Go API truth](../skylos/rules/ai_defect/go_api_hallucination.py).

### Filtering configuration and suppressions

Project settings live in `[tool.skylos]` in a discovered `pyproject.toml`; `--config-file PATH` or `SKYLOS_CONFIG_FILE` selects an explicit TOML file. Configuration includes analyzer family enablement, quality thresholds, ignore lists, path exclusions, whitelists, confidence adjustments, masking, architecture/layer rules, dead-code entrypoints, security contracts, license policy, model/template settings and gate policy. Configured default CLI arguments (`addopts`) are prepended to user arguments.

| Control | Behavior |
| --- | --- |
| `--exclude` | Repeatable extra path/folder exclusion, on top of common defaults. |
| `--include-folder` | Force inclusion of otherwise excluded matching folders. |
| `--no-default-excludes`, `--list-default-excludes` | Disable or inspect built-in excludes. |
| `--include-generated` | Include generated/vendored files normally skipped: Django migrations, selected static library trees, minified assets and recognized library banners. Summary counts report generated files skipped. |
| `--confidence N` | Dead-code threshold, default 60. |
| `--select RULE[,RULE]` | Exact, case-insensitive rule IDs; repeatable. Enables matching analyzer families. Mandatory contract rules remain visible and analysis errors remain visible. |
| `--severity LEVEL` | Minimum severity display/report filter. |
| `--category CATEGORIES` | Select security, reliability, secret, quality, ai_defects, dead_code, dependency or publisher_change categories. |
| `--file-filter TEXT` | Filter finding paths by substring. |
| `--limit N` | Cap displayed rows per category, with remaining counts. |
| `--expand-advice` | Expand each advisory observation instead of the default grouped advice; JSON records and gate calculations are unchanged. |
| Inline ignores | `# skylos: ignore`, rule-specific `# skylos: ignore[SKY-...]`, or `ignore-start` / `ignore-end` blocks; language-specific scanners support their implemented comment forms. |
| Whitelist | Symbol patterns, documented and temporary whitelist metadata, and path-scoped overrides. |
| AST masking | Python function/class bodies can be omitted by configured names, decorators or bases, optionally retaining docstrings. This changes analysis scope and can appear in coverage assessment. |

When scanning supported Git repositories, discovery uses tracked plus visible untracked files and respects Git ignore behavior, with a filesystem fallback. This does not add a separate `.skylosignore` file format.

~~~bash
skylos . --config-file config/skylos.toml --format json
skylos . --exclude generated --include-folder tools --format json
skylos . --severity high --category security,secret --format concise
skylos . --select SKY-L012 --format json-ci
~~~

Evidence: [config structure](../skylos/config.py), [inline ignore parsing](../skylos/config.py), [CLI filters](../skylos/cli_core/main_parser.py), [addopts argument precedence](../skylos/cli_core/main_parser.py), [discovery](../skylos/core/file_discovery.py), [body masking](../skylos/analysis/ast_mask.py).

#### Baselines and review of changed code

`skylos baseline .` saves existing findings so later `--baseline` runs emphasize new ones. Add `--sca` to include dependency vulnerabilities. A baseline scan that is incomplete does not replace the previous baseline. Baselines are scoped to the selected scan target.

`--diff REF` reports changed lines, including committed changes after the comparison, staged, unstaged and untracked changes. `--diff HEAD` covers uncommitted work. `--diff` without a ref can detect supported PR target environment variables or fall back to `origin/main`. `--diff-mode impact` additionally compares dead-code results with the base commit so symbols made unused outside changed lines can be reported. `--diff-base REF` reports changed files while retaining unchanged sources for cross-file resolution and skipping their ordinary quality/danger/secret rules.

Dependency baseline filtering in CI requires a trusted Git revision through `--baseline-ref REF`, which implies `--baseline`. Synced mandatory policy can lock baseline waivers. Required coverage rules and source-scan errors are preserved rather than being silently treated as old findings.

~~~bash
skylos baseline .
skylos . -a --baseline --format json
skylos . --diff origin/main --format json-ci
skylos . --diff origin/main --diff-mode impact --format json-ci
skylos . --diff HEAD --format concise
skylos . --diff-base origin/main --format json
~~~

Evidence: [baseline command](../skylos/commands/baseline_cmd.py), [baseline safety](../skylos/commands/baseline_cmd.py), [diff flags](../skylos/cli_core/main_parser.py), [impact analysis](../skylos/core/pr_impact.py), [dependency baseline policy](../skylos/core/sca_baseline.py).

### Custom rules and rule discovery

`skylos rules list` searches the built-in catalog by rule name, ID/category/aliases and returns finding type/severity metadata. JSON is available with `--json` or the trailing `json` alias. The reviewed catalog has 252 entries: 136 security, 70 quality, 28 AI defect, 10 dead-code, 5 reliability, 2 secrets and 1 license/dependency entry. This is a catalog count across workflows and legacy aliases, not a count of independent checks executed in one scan; dynamic advisory IDs and custom rules add other findings.

`rules init` creates a starter YAML rule pack; `rules validate FILE` validates the pack; `rules install PACK_OR_URL`, `rules list --packs`, and `rules remove NAME` manage installed packs. Installed community YAML files are read from `~/.skylos/rules/*.yml`; organization custom rules are loaded through the sync configuration path. The current `rules init` default is `.skylos/rules/local.yml`, but the inspected community loader does not automatically load that project directory, so the starter command should be described as authoring a template rather than activating it.

The YAML engine inspects Python ASTs and supports function decorator requirements, class name/inheritance rules, dynamic call arguments, and function-local source/sink/sanitizer taint patterns. Rules carry ID, name, severity, category, message and a revision hash. They are not a universal multi-language custom rule runtime. Custom findings are available in a dedicated result array and count toward the quality gate.

~~~bash
skylos rules list --json
skylos rules list injection
skylos rules init
skylos rules validate .skylos/rules/local.yml
skylos rules list --packs --json
~~~

Evidence: [rule management CLI](../skylos/commands/rules_cmd.py), [starter template](../skylos/commands/rules_cmd.py), [Python YAML rule types](../skylos/rules/custom.py), [installed loader](../skylos/rules/custom.py), [custom rule gate accounting](../skylos/core/gatekeeper.py).

### Reports review UI and automation outputs

| Format or UI | Feature |
| --- | --- |
| `rich` | Default terminal report with scan assessment, typed findings, grouped advice, scope/coverage and category information; tree layout available with `--tree`. |
| `pretty` | Compact findings grouped by file, intended for human review. |
| `json` / `--json` | Full machine-readable result, including evidence/context and analysis summary when present. Empty arrays may be omitted. |
| `json-ci` | Compact JSON preserving findings, per-finding evidence, counts, operational errors and exit behavior; omits only bulky top-level `dead_code_evidence` and `definitions`. |
| `llm` / `--llm` | Structured Markdown with code context for an external AI coding tool; choosing this output does not itself invoke a model. |
| `concise` | Untruncated `file:line RULE message` records suitable for editors and automation; findings produce a nonzero exit. |
| `github` / `--github` | GitHub Actions warning/error annotations. `--summary` writes a Markdown step summary through `GITHUB_STEP_SUMMARY`. |
| `gitlab` | GitLab code-quality/report output. |
| `--sarif [PATH]` | SARIF 2.1.0 export, defaulting to `skylos.sarif.json` when no path is supplied. |
| `--output FILE` | Save supported non-TUI report output. |
| `--tui` | Textual terminal dashboard: categories, overview, search, severity cycling, finding details, suppressed findings, evidence details and open in `$EDITOR`. |

The current assessment presents risk from open observations, maintainability advice measured against checked units, and analysis coverage/missing checks. Findings are classified as Defect, Review or Advice. Display filters can leave the assessment based on a broader result; scope notes say when filtered findings are included. Legacy numeric/letter grade payloads can still be rendered for historical data and are labelled as such.

Common JSON areas include `unused_functions`, `unused_imports`, `unused_variables`, `unused_classes`, `unused_parameters`, `unused_files`, `danger`, `reliability`, `ai_defects`, `quality`, `secrets`, `dependency_vulnerabilities`, `publisher_change_findings`, `custom_rules`, `circular_dependencies`, `code_health`, `analysis_errors`, `analysis_summary`, `assessment`, `provenance` and, when requested, `gate`. Consumers should use `.get(key, [])` for optional finding arrays.

~~~bash
skylos . -a --format json-ci --output findings.json
skylos . --danger --sarif findings.sarif.json --format concise
skylos . --quality --format github --summary
skylos . -a --tui
~~~

Evidence: [output choices](../skylos/cli_core/main_parser.py), [compact JSON contract](../skylos/commands/scan_cmd.py), [assessment](../skylos/reporting/assessment.py), [legacy score labelling](../skylos/ui/rich_report.py), [TUI controls](../skylos/ui/tui.py), [SARIF renderer](../skylos/reporting/sarif.py), [GitLab renderer](../skylos/reporting/gitlab.py).

### Local quality gates and exit outcomes

`--gate` applies `[tool.skylos.gate]` thresholds. `--strict` fails on any finding and can select strict gate behavior. Available limits cover critical/high/security/reliability/quality/AI defects/secrets/dependency vulnerabilities/dead code, with related circular/architecture/policy checks. Critical AI-defect severities block by default even when a count allowance is larger; `block_ai_defect_severities` configures that list.

Defaults in the baseline gate are critical 0, high 5, security 10, reliability 0, quality 10, secrets 0 and dependency vulnerabilities 0; dead-code count is unset by default. Repository/cloud configuration can change policy. Required scan coverage can demand SCA or custom-rule completion, and dependency policy can require resolved versions. Operational failures remain distinct from policy failures.

| Outcome | Behavior |
| --- | --- |
| Passed | Gate completed and policy passed; exit 0. |
| Failed | Gate completed and exceeded policy; exit 1. |
| Incomplete | A required check failed to finish or comparison/engine evidence was unavailable; exit 2 with named reasons and hints. |

`--force` / `-f` can bypass an ordinary failed gate exit but cannot turn incomplete required analysis into a pass. A command after `--` can run when the gate permits it, such as `skylos . --gate -- npm run build`. The command is user-selected execution and is not part of static scanning.

Machine output can include passed/reasons/scope/status/forced, a verdict and exit code, and structured reason details with affected files/counts and remediation hints. Human and CI output prints a clear final quality-gate verdict; concise and other stream-oriented formats send the verdict to stderr to preserve their stdout data.

~~~bash
skylos . -a --gate --format json-ci
skylos . --strict --format concise
skylos . --gate -- npm run build
~~~

Evidence: [default thresholds](../skylos/core/gatekeeper.py), [AI blocking policy](../skylos/core/gatekeeper.py), [incomplete outcome](../skylos/core/gatekeeper.py), [gate reason reporting](../skylos/core/gate_outcome.py), [coverage gate tests](../test/test_product_coverage_gates.py), [verdict output tests](../test/test_gate_verdict_output.py).

### AI integration discovery

`skylos discover DIRECTORY` statically inventories supported LLM integrations and builds an integration graph. It reports provider, integration type, source location and available prompt/output/tool evidence. Python detection supports recognized SDK imports/calls, supported framework calls and direct HTTP LLM API patterns; the separate JS/TS detector covers supported SDK integrations. This discovers source evidence without calling the application's model or starting its agent.

Recognized Python SDKs include OpenAI, Anthropic, Google Gemini, Cohere, Mistral, Ollama, Together, Groq, Fireworks, Replicate and LiteLLM. Recognized framework patterns include LangChain, LangGraph, LlamaIndex, CrewAI, AutoGen, Haystack, Semantic Kernel, DSPy, SmolAgents, PydanticAI, OpenAI Agents SDK, Claude Agent SDK and Google ADK. The detector also has supported server-side MCP tool detection, RAG/retrieval hints, PII filtering hints and direct HTTP host/API-path recognition. These are detection patterns rather than a claim of complete semantic coverage for every version of these products.

Output is a human table or `--json`, optionally saved with `--output`; `--exclude` adds directory exclusions. The target must be a directory.

~~~bash
skylos discover . --json --output ai-integrations.json
~~~

Evidence: [discover command](../skylos/commands/discover_cmd.py), [SDK/framework detection tables](../skylos/discover/detector.py), [JS/TS detector](../skylos/discover/detector_typescript.py), [integration graph](../skylos/discover/graph.py).

### AI defense and guardrail reports

`skylos defend DIRECTORY` reviews static guardrail evidence around supported Python and JS/TS LLM integrations. The current registry has 13 plugins: ten defense checks and three operational checks.

| Defense checks | Operational checks |
| --- | --- |
| Dangerous model-output sinks, restricted tool scope, explicit tool argument schemas, prompt delimiters, output validation, pinned model versions, input length bounds, untrusted input in prompts, RAG context isolation and output PII filtering. | Logging, cost controls and rate limiting. |

Reports include per-check evidence, integrations, pass/fail totals, a weighted defense score/risk rating, operational score, framework coverage and a source/policy attestation. Policy YAML can configure plugin settings/severities and gate thresholds. OWASP reporting can select LLM 2024/2025 or agentic 2026 mappings and filter relevant `LLM*` / `ASI*` categories. Additional EU AI Act, NIST AI RMF and ISO/IEC 42001 mappings describe static evidence toward controls; the code explicitly states they are not compliance determinations or certifications.

Formats are table, JSON, Markdown evidence report and SARIF. Options include minimum included severity, output file, explicit policy, OWASP framework/version/filter and opt-in Cloud upload. Findings are report-only by default: severity gating uses `--fail-on`, score gating uses `--min-score`, or an explicitly selected policy can supply gate settings. No integrations found means none were detected in supported source scope; the empty report's 100% score does not prove the application has no AI risk.

~~~bash
skylos defend . --format md --output ai-defense.md
skylos defend . --format json --fail-on high
skylos defend . --owasp-framework agentic --owasp-version 2026 --owasp ASI02
~~~

Evidence: [defend command/options](../skylos/commands/defend_cmd.py), [all 13 plugins](../skylos/defend/plugins/__init__.py), [policy schema](../skylos/defend/policy.py), [framework mapping scope](../skylos/defend/frameworks.py), [attestation](../skylos/defend/attestation.py).

### Technical debt hotspots and trends

`skylos debt [PATH]` turns supported quality, architecture, duplicate/circular dependency and dead-code evidence into ranked hotspots with source evidence and a debt score/breakdown. Dimensions include complexity, modularity, architecture, maintainability and dead code. It provides a triage view over existing static observations rather than monetary debt estimates.

The command supports a saved debt baseline, new/worsened hotspot comparison, local history append/view with entry limits, changed-file focus, table/JSON output, a top-hotspot display limit and opt-in Cloud upload. `--with-agent` can add model-written summaries for a configured number of the top static hotspots; model/provider/base URL controls are available. This optional advice does not replace static hotspot evidence.

Debt policy YAML can configure analysis/scoring and gating. `--min-score` sets a minimum score; `--fail-on-status new|worsened|new_or_worsened` fails for specified baseline changes. The debt baseline/history is separate from the ordinary source-finding baseline.

~~~bash
skylos debt . --json --save-baseline --history
skylos debt . --baseline --fail-on-status new_or_worsened
skylos debt . --show-history --history-limit 10
skylos debt . --with-agent --agent-top 5
~~~

Evidence: [debt command](../skylos/commands/debt_cmd.py), [baseline/history/gate options](../skylos/commands/debt_cmd.py), [signal dimensions](../skylos/debt/engine.py), [hotspot scoring](../skylos/debt/scoring.py), [debt baseline/history storage](../skylos/debt/baseline.py).

### Combined suite reports

`skylos suite DIRECTORY` builds one local report combining the main static families, debt, AI defense and automatic Git provenance when available. It accepts JSON/file output, additional exclusions, confidence and provenance controls. Its static family enables dependency vulnerability and dependency truth checks that may contact OSV and public registries; local analysis does not imply offline operation.

With `--upload`, selected `static`, `defense` and `debt` families are uploaded as separate Cloud scans linked by a suite bundle ID. `--static-categories` selects the supported code-scan categories uploaded within the static family. These switches select upload payloads, not a universal switch that proves omitted analyzers were not run locally. Findings are report-only for the default exit status; operational/output/upload errors and an uploaded Cloud gate failure return nonzero.

~~~bash
skylos suite . --json --output suite.json
skylos suite . --upload --families static,defense,debt
~~~

Evidence: [suite parser and exit contract](../skylos/commands/suite_cmd.py), [suite orchestration](../skylos/core/suite.py), [upload selections](../skylos/commands/suite_cmd.py).

### SBOM export

`skylos sbom DIRECTORY` exports the supported static dependency inventory as CycloneDX JSON or SPDX 2.3 JSON. It runs offline by default, includes available normalized license evidence and an inventory coverage receipt, and does not itself run the advisory scan. Unknown licenses remain `NOASSERTION`. `--license-lookup` explicitly permits deps.dev queries for missing license evidence.

Available packages are still exported when inventory coverage has gaps, with a warning. `--strict` returns exit 2 for an incomplete inventory. Output defaults to stdout or can be saved using `-o`; the command rejects overwriting recognized dependency inputs. SBOM scope follows supported manifest/lockfile identities rather than a complete installed runtime inventory.

~~~bash
skylos sbom . --format cyclonedx-json -o sbom.cdx.json
skylos sbom . --format spdx-json --strict -o sbom.spdx.json
skylos sbom . --license-lookup -o sbom-with-licenses.json
~~~

Evidence: [SBOM command and defaults](../skylos/commands/sbom_cmd.py), [CycloneDX exporter](../skylos/reporting/sbom.py), [SPDX exporter](../skylos/reporting/spdx.py).

### Container image vulnerability analysis and report import

`skylos image scan IMAGE@sha256:DIGEST --platform OS/ARCH` asks a trusted installed Trivy executable to scan a digest-pinned remote registry image. It needs network/registry access and scans OS plus library vulnerabilities. The target platform is required. It does not run the container and is separate from code dependency scanning and GPU artifact preflight.

The command produces normalized JSON and can additionally write image-aware SARIF. Its receipt records image identity/platform, scanner execution and scan/report completeness. Timeout defaults to 300 seconds and can be set within the supported 1–900 second range. Missing/untrusted Trivy, invalid identity, scanner failure, timeout or incomplete report returns exit 2. Findings are report-only unless `--fail-on low|medium|high|critical` requests a severity gate; a failed requested gate returns 1.

`skylos ingest trivy --input REPORT.json` imports a supplied Trivy SchemaVersion 2 image vulnerability report offline. It can verify expected digest/platform, write normalized JSON/SARIF and gate the supplied findings. A report gate requires `--expect-image`; successful import does not independently attest that the original scan covered the entire image. This importer does not call Trivy, pull/run an image or upload results.

~~~bash
skylos image scan registry.example/app@sha256:DIGEST --platform linux/amd64 --fail-on high -o image.json --sarif image.sarif
skylos ingest trivy --input trivy.json --expect-image registry.example/app@sha256:DIGEST --expect-platform linux/amd64 --fail-on high -o image-import.json
~~~

The `DIGEST` text in those examples must be replaced by the actual 64-character SHA-256 value.

Evidence: [direct image scan contract](../skylos/commands/image_cmd.py), [Trivy invocation and enabled vulnerability types](../skylos/commands/image_cmd.py), [offline image importer](../skylos/commands/trivy_image_cmd.py), [report-gate identity requirement](../skylos/commands/trivy_image_cmd.py), [image normalization](../skylos/integrations/trivy_image.py).

## CLI commands and workflows

### Packaging and entry points

Skylos requires Python 3.10 or later. The public executable is `skylos`; the current package console script points to `skylos.entry:main`, which dispatches frequent agent hooks through a lightweight shim and delegates other commands to `skylos.cli.main`. The package has no `skylos.__main__`, so `python -m skylos` is not a supported invocation. `pip install skylos` installs the base CLI and MCP dependency. Optional extras are `llm` (LiteLLM and aiohttp), `lint` (Ruff), `verdict` (cryptography for signed verdict verification), `dart` (Dart grammar that may require a C build), `test`, and `all`. Rust acceleration is optional; the Go engine and optional Dart support are exposed in Doctor. Sources: [pyproject.toml:5](../pyproject.toml), [pyproject.toml:102](../pyproject.toml), [pyproject.toml:126](../pyproject.toml), [skylos/entry.py:1](../skylos/entry.py), [skylos/commands/doctor_cmd.py:19](../skylos/commands/doctor_cmd.py).

The Python API is `skylos.analyze(path, **options)`, returning a JSON **string**, not a dictionary. Its defaults are confidence 60, core dead-code analysis enabled, danger/secrets/quality/AI-defect/SCA families disabled. It exposes family flags, exclusions, extra visitors, progress callback, custom rule data, changed files, grep verification/cache, trace file, configuration overrides, dependency bump comparison base, review proofs/context, and generated-file handling. The lower-level `Skylos` class is available from `skylos.analyzer`. Generated-file skipping is an explicit API argument (`skip_generated=False`); CLI behavior can differ. Sources: [skylos/__init__.py:37](../skylos/__init__.py), [skylos/analyzer.py:5924](../skylos/analyzer.py).

```python
import json
import skylos

report = json.loads(skylos.analyze("src", enable_danger=True, enable_secrets=True))
findings = report.get("danger", [])
```

### Complete command family inventory

The primary source scan is `skylos PATH [OPTIONS]`, including multiple path targets. There is no required `scan` word. Top-level dispatch currently registers the following command families; `agent` is handled separately. Sources: [skylos/cli_core/dispatch.py:10](../skylos/cli_core/dispatch.py), [skylos/cli.py:4279](../skylos/cli.py).

| Command family | Implemented purpose and operations |
| --- | --- |
| `commands`, `tour` | Command overview/reference and an interactive onboarding walkthrough. Invoking `skylos` or first-level help shows the overview. |
| `init` | Create/reset `[tool.skylos]` sections in `pyproject.toml`, with quality thresholds, gate policy, model selection, exclusions, dead-code entrypoints, architecture constraints, templates, and suppressions. **Reinitializing replaces existing Skylos TOML sections**; it is not a passive inspection. |
| `doctor` | Human or JSON installation/configuration diagnostics. Checks Python, Skylos version, Go engine, optional Rust acceleration, LLM support, Dart, interactive support, and grep backend. |
| `key` | Interactive provider credential menu; `list`/`ls`, `add`/`set`, and `remove`/`rm`/`delete`/`del`. Environment credentials take priority over system keyring. |
| `login`, `whoami`, `credits` | Browser-based Cloud project login; connected account/project/plan information; credit balance and recent transactions. |
| `sync` | `connect [token]`, `status`, `disconnect`, `pull`, `setup [token]`, `upgrade`; connects and imports Cloud policy/review state or generates local setup. |
| `project` | `status`, `list`, `use`, `create`, `unlink`; repository-to-Cloud project and monorepo subpath links. Selection/creation uses the browser login flow. |
| `upload` | List or retry queued failed scan uploads; `--list` (default), `--retry`, `--json`. |
| `baseline` | Record current findings for later `--baseline` new-issue scans; optional `--sca` includes dependency CVEs. |
| `review` | Interactive exact-finding false-positive or risk-acceptance decision; `list`, `restore`/`revoke`. |
| `whitelist` | Add name-pattern exemptions (optionally with a reason) and inspect ordinary, documented or configured temporary entries. Temporary expiry is configured in TOML. |
| `clean` | Preview or apply Python unused-function/import removal or commenting, with interactive and noninteractive modes. |
| `lint` | Forward arguments to optional `ruff check`; `.` when no target is supplied. |
| `cache` | `stats [path] [--json]` and `clear [path]` for cached run data under `.skylos/cache/runs`; this is not a promise to clear every analyzer cache. |
| `rules` | Built-in rule search/list/JSON, installed-pack listing, community/URL pack install/remove, project-local starter pack creation and YAML validation. |
| `contract` | `init`, `validate`, `inspect`/`explain`: explicit AI hallucination contracts used by focused verification. |
| `verify` | Local source verification of AI defects, quality, high/critical security, secrets, contracts and a bounded Python behavior model. |
| `done` | Run completion checks and tests, write an evidence receipt; `receipt` reads the latest receipt. |
| `hook` | Native agent-loop events and `recheck`; integrations for Claude Code, Codex, and Cursor. |
| `mcp` | Start MCP server using stdio, SSE, or streamable HTTP. |
| `discover` | Discover AI/LLM integrations and interaction graph. |
| `defend` | Static AI defense guardrail/OWASP assessment and optional gates. |
| `debt` | Technical-debt signals, ranked hotspots, baseline/delta and optional Cloud upload. |
| `suite` | Combined static, defense, debt and provenance report; optional selected-family uploads. |
| `provenance` | Recorded agent attribution and declared commit associations, optionally cross-referenced with AI defense risk. |
| `sbom` | Offline dependency inventory as CycloneDX JSON or SPDX 2.3 JSON, optional missing-license lookup. |
| `image scan` | Digest-pinned remote container image scan through installed Trivy, selected deployment platform and optional severity gate. |
| `ingest` | `claude-security` normalization/upload/cross-reference; `trivy` offline container-image report normalization and optional report gate. |
| `sonar import` | Translate supported Sonar properties into a Skylos migration plan and optionally write config. |
| `compare` | Nonblocking comparison with incumbent SARIF/Sonar/normalized JSON; optional Scanner Proof receipt upload. |
| `cicd` | `init`, `gate`, `annotate`, `review`, `risk-review`; generate workflows, evaluate policy, GitHub annotations and reviews, and human approval requirements. |
| `verify-verdict` | Independently verify a signed Cloud verdict and optionally require specific identity, age and pass conditions. |
| `preflight` | Static compatibility of an exact built CUDA artifact with a declared GPU hardware fleet. |
| `badge` | Print README badge Markdown and optionally copy it to the clipboard. |

`city` and `run` remain recognized only to print a removal error (exit 2), with migration guidance to `suite`, `debt`, `discover`, or normal source scans. They should not be presented as available product capabilities. Sources: [skylos/cli.py:2488](../skylos/cli.py), [skylos/cli.py:2505](../skylos/cli.py).

The `agent` family has 18 direct operations, with four further triage operations:

| Agent command | Purpose |
| --- | --- |
| `agent scan` | Hybrid static and LLM analysis; optional changed scope, dead-code verification and fix suggestions. |
| `agent security-quick` | One-shot LLM security audit (`scan --security` alias). |
| `agent security-deep` | Persistent three-stage threat-model/discovery/remediation-handoff workflow (`audit --deep` alias). |
| `agent audit --deep` | Explicit persistent Deep Mode audit, revalidation and exports. |
| `agent verify PATH` | LLM, Jev or mixed review of static dead-code candidates and optional removal-patch generation. |
| `agent remediate` | Plan/apply provider-generated repairs; optional trusted tests, PR creation and standards cleanup. |
| `agent replay` | Validate/inspect saved harness evidence. |
| `agent install-hooks` | Install/uninstall native coding-agent hooks. |
| `agent install-standards` | Install standards guidance and selected quality enforcement for coding agents. |
| `agent check-standards` | Statically gate selected quality rules. |
| `agent warm-cache` | Prebuild the Python module index used by edit hooks. |
| `agent init` | Create a runtime agent behavior contract. |
| `agent test` | Evaluate endpoint/fixture behavior against that contract. |
| `agent watch` | Continuously refresh local findings, ranked actions and optional learning. |
| `agent pre-commit` | Check staged source/config changes before a local commit. |
| `agent triage suggest\|dismiss\|snooze\|restore` | Suggest or change ranked-action triage. |
| `agent status` | Inspect the local agent state in table/JSON/feed form. |
| `agent serve` | Serve the optional local state/triage HTTP API. |

Source: [skylos/cli.py:3796](../skylos/cli.py) and parser registration helpers under `skylos/commands/`.

### LLM analysis verification deep audits and remediation

#### Shared provider support

Agent LLM commands support `--model`, `--provider`, `--base-url`, `--quiet`, and command-specific outputs. The default agent model is `gpt-4.1`. Explicit provider choices are OpenAI, Anthropic, Google, Mistral, Groq, xAI, Together, DeepSeek, and Ollama. Model prefixes/provider selection and `SKYLOS_LLM_PROVIDER` select the provider; endpoint precedence is explicit `--base-url`, `SKYLOS_LLM_BASE_URL`, then `OPENAI_BASE_URL`. Local Ollama/OpenAI-compatible endpoints such as LM Studio and vLLM can run without a provider key. Remote providers use their environment variables or OS keyring, with masked interactive prompting when supported. This source inventory does not claim that default model names are the latest offerings from those providers. Sources: [skylos/cli.py:143](../skylos/cli.py), [skylos/cli.py:5425](../skylos/cli.py), [skylos/llm/runtime.py:49](../skylos/llm/runtime.py), [skylos/cloud/credentials.py:8](../skylos/cloud/credentials.py).

Provider secrets recognized by the credential helper are `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, `MISTRAL_API_KEY`, `GROQ_API_KEY`, `XAI_API_KEY`, `TOGETHER_API_KEY`, and `DEEPSEEK_API_KEY`. Keys are saved using the system keyring, not project source. `skylos key list` shows presence/source rather than key values. Sources: [skylos/cloud/credentials.py:8](../skylos/cloud/credentials.py), [skylos/commands/key_cmd.py:86](../skylos/commands/key_cmd.py).

`--prompt-template KIND=PATH` is repeatable for `security`, `quality`, `security_audit`, and `review` prompts. It explicitly appends trusted templates; malformed kinds, missing files, symlinks and nonfiles are rejected. Project templates also have configuration support. Sources: [skylos/cli.py:3536](../skylos/cli.py), [skylos/cli.py:3742](../skylos/cli.py).

#### Agent scan and quick security

`skylos agent scan [path]` combines static results with LLM review, deduplicates findings, retains finding origin (static, LLM, or both), and supports table/tree/JSON/SARIF. Controls include `--llm-only`, `--changed`, minimum confidence `low|medium|high` (default low), `--strict`, optional `--upload`, and `--force` for Cloud gate handling. Fix suggestions are **off by default** and enabled by `--with-fixes`; `--no-fixes` is a compatibility switch. The slower dead-code verification pass is also **off by default**, enabled with `--verify-dead-code`; its default mode here is `production`. The main LLM source-discovery path handles Python `.py` files, while the static side can report supported other languages. Sources: [skylos/cli.py:3796](../skylos/cli.py), [skylos/cli.py:5481](../skylos/cli.py), [skylos/pipeline.py:414](../skylos/pipeline.py), [skylos/pipeline.py:624](../skylos/pipeline.py), [skylos/pipeline.py:784](../skylos/pipeline.py).

`skylos agent security-quick [path]` is an explicit alias for `agent scan --security`: a one-shot Python LLM security audit, optional interactive file selection, estimated token/cost display and table/tree/JSON/SARIF output. Its output blocker status controls exit 1. Code is sent to the configured provider unless a local endpoint is used. Sources: [skylos/cli.py:3988](../skylos/cli.py), [skylos/cli.py:4299](../skylos/cli.py), [skylos/cli.py:5482](../skylos/cli.py).

When a Cloud token is configured, successful agent scan/verify/remediate/cleanup commands also attempt an agent-run summary upload (command, summary counters, model/provider, duration, commit, branch, actor), independently of a full finding upload. Sources: [skylos/cli.py:2465](../skylos/cli.py), [skylos/api/__init__.py:3132](../skylos/api/__init__.py).

#### Dead-code review and Jev

`skylos agent verify PATH` first performs static dead-code analysis and then runs a saved verification harness. Default static confidence is 60; default main review cap is 50, survivor challenge cap 20, and `--verification-mode judge_all`. The `production` alternative conservatively routes candidates. Entry discovery and survivor challenge can each be disabled; parallel grep is opt-in with four default workers, and is automatically enabled for fix generation. Table and JSON output include retained findings, removed false positives, uncertainties, discovered entrypoints, new dead code, provider call counts, elapsed time and harness metadata. It refuses verification/fix generation after incomplete static analysis. Sources: [skylos/commands/agent_verify_cmd.py:19](../skylos/commands/agent_verify_cmd.py), [skylos/commands/agent_verify_cmd.py:155](../skylos/commands/agent_verify_cmd.py), [skylos/commands/agent_verify_cmd.py:338](../skylos/commands/agent_verify_cmd.py).

| Dead-code mode | Actual behavior |
| --- | --- |
| `--dead-code-review llm` | Default broad LLM verification, entry discovery and survivor challenge. Provider support/credentials required. |
| `--dead-code-review jev` | Jev-only judgment via TypeSafe. No LLM calls. Confident used results suppress candidates; uncertain/unavailable decisions stay visible as unverified static findings. Only available through `agent verify`. |
| `--dead-code-review jev-llm` | Jev judgment first, then broad LLM fallback for uncertain/unavailable/invalid decisions; requires both TypeSafe and a usable LLM provider. |
| Hidden legacy `--jev-precheck` | Agreement on unused at confidence >=0.8 skips broad verification for that candidate. Disagreement/uncertainty falls back. This mode does not let Jev suppress findings. |
| Hidden legacy `--jev-judge` | Jev can decide unused or used only with both confidence and chosen-answer probability >=0.9; fallback otherwise. Skips separate entry discovery, prefilter and survivor challenge even during Jev outage. |

Jev modes require explicit selection and `TYPESAFE_API_KEY`; missing keys produce a visible error. Jev can send a complete bounded project snapshot (currently 64 KB) to TypeSafe. Snapshot guards are not a secret scanner. `agent scan --dead-code-review jev` is rejected because scan has other LLM phases. `agent scan --dead-code-review jev-llm` additionally requires `--verify-dead-code`. Sources: repository `AGENTS.md`, [skylos/cli.py:4235](../skylos/cli.py), [skylos/llm/verification/jev_precheck.py:92](../skylos/llm/verification/jev_precheck.py).

`agent verify --fix` previews removal patches for confirmed dead code; `--fix-mode delete|comment` selects the transform, `--apply` applies validated patches, and `--pr` creates a local branch, applies changes and makes a commit, then prints PR-creation guidance. **That `--pr` flag does not itself open a GitHub PR.** Its current implementation stages with `git add -A`, so it should be described as a clean-checkout workflow. Jev-only decisions never authorize a removal patch; the generator excludes Jev-agreed/Jev-retained candidates and uses LLM-confirmed true positives/new dead code. Local trusted reviews are protected from being removed. Sources: [skylos/commands/agent_verify_cmd.py:569](../skylos/commands/agent_verify_cmd.py), [skylos/commands/agent_verify_cmd.py:602](../skylos/commands/agent_verify_cmd.py), [skylos/commands/agent_verify_cmd.py:667](../skylos/commands/agent_verify_cmd.py), [skylos/commands/agent_verify_cmd.py:715](../skylos/commands/agent_verify_cmd.py).

#### Persistent security deep mode

`skylos agent security-deep [path]` names a three-stage workflow: static threat-model/context, discovery/validation, and remediation handoff. It is an alias for `agent audit --deep`; plain `agent audit` without `--deep` returns an explanatory exit 2. Static candidates and file state are saved under `.skylos/audit/projects/...`; this supports incremental work, rescans and record history rather than requiring a fresh one-shot audit. Candidate discovery handles source and configuration across Python, JS/TS, Go, Java, PHP, Rust, Dart, C#, Kotlin and common config formats; exact reasoning coverage varies by language and candidate type. Sources: [skylos/cli.py:3573](../skylos/cli.py), [skylos/cli.py:3664](../skylos/cli.py), [skylos/cli.py:3994](../skylos/cli.py), [skylos/cli.py:5060](../skylos/cli.py), [skylos/audit/candidates.py:40](../skylos/audit/candidates.py).

`--scan-only` records static context/candidates without a provider call. Processing mode supports `--resume`, `--force` reprocessing, `--changed` or `--base REF`, processing `--limit`, and `--fail-on`. `--revalidate` reassesses stored findings; `--challenge` requires revalidation and revisits uncertain decisions. Exports are table, JSON, SARIF, Markdown, or per-file Markdown directory, filtered by minimum severity and repeatable verdict/status values (`true_positive`, `false_positive`, `fixed`, `uncertain`, `pending`, `not_analyzed`, `error`, `skipped`, `deleted`), with optional deleted records. Remediation remains a separate explicit handoff through `agent remediate`; deep mode does not silently apply source fixes. Sources: [skylos/cli.py:3573](../skylos/cli.py), [skylos/cli.py:3892](../skylos/cli.py), [skylos/cli.py:5060](../skylos/cli.py).

#### Remediation and cleanup

`skylos agent remediate [path]` performs a source scan, creates per-file fix batches, generates provider-backed code, applies patches, verifies that original finding rules were resolved and rolls back a file when enabled tests fail or finding verification fails. Low-confidence generated fixes are skipped. Maximum fixes defaults to 10; minimum severity, provider and branch prefix are configurable. The scanner enables danger, quality, AI defects and secrets; the ordinary remediation plan is oriented around security, quality and secret findings. It can add supported regression-test candidates after successful repair. Sources: [skylos/cli.py:4003](../skylos/cli.py), [skylos/llm/orchestrator.py:12](../skylos/llm/orchestrator.py), [skylos/llm/orchestrator.py:125](../skylos/llm/orchestrator.py), [skylos/llm/orchestrator.py:183](../skylos/llm/orchestrator.py).

`--dry-run` presents the plan without changing source. Tests are disabled by default; `--auto-test` opts in to detected trusted project tests, or `--test-cmd` supplies a trusted argument list parsed without a shell (shell metacharacters rejected). `--auto-pr` explicitly creates a remediation branch and can open a PR through the PR executor. `--standards` switches to guided cleanup with built-in standards; an optional Markdown path selects custom standards. These workflows require provider configuration even when a plan may ultimately contain no changes. Sources: [skylos/cli.py:4015](../skylos/cli.py), [skylos/cli.py:5784](../skylos/cli.py), [skylos/llm/executor.py:135](../skylos/llm/executor.py).

`skylos clean [path]` provides deterministic **Python function/import** transforms using LibCST, without requiring an LLM. Interactive mode asks about edits and requests final confirmation. `--dry-run` previews, `--apply` applies matching edits without prompting, `--types import,function` narrows selection, and `--comment-out` comments instead of deleting. Noninteractive minimum confidence defaults to 80; explicit confidence, excludes and include-folder overrides are supported. It does not remove every possible dead-code kind. Individual transform failures are printed but currently do not make the command nonzero, so exit 0 means command completion rather than proof every proposed edit succeeded. Sources: [skylos/commands/clean_cmd.py:23](../skylos/commands/clean_cmd.py), [skylos/commands/clean_cmd.py:70](../skylos/commands/clean_cmd.py).

### Focused verification and declarative contracts

`skylos verify [path]` is local deterministic source verification, separate from `agent verify`'s provider-backed dead-code review. It scans AI/quality defects and, by default, high/critical security and secret findings. Path targets enable dependency hallucination checks, which can query package registries. `--no-dependency-hallucinations`, `--no-security`, `--no-behavior`, `--no-contract` and exclusions control those parts independently. Default confidence is 60. Sources: [skylos/commands/verify_cmd.py:62](../skylos/commands/verify_cmd.py), [skylos/verify_change.py:32](../skylos/verify_change.py).

Targets include a path, a project plus `--file`, a restricted `--range L1:L2`, a JSON `--stdin` manifest containing `file`, `code` and optional range (for unsaved editor text), or `--diff [REF]` (default HEAD). Diff verification includes committed changes after REF plus staged, unstaged and untracked files, and returns findings on changed lines; incompatible target selectors are rejected. `--project-context` analyzes the full project while returning a chosen file's findings. Auto output is human on a terminal and JSON when redirected/stdin; `--format short` is one finding per line and a verdict. Exit 0 passes, 1 fails, 2 is incomplete; `--no-fail` preserves status but exits 0. Sources: [skylos/commands/verify_cmd.py:85](../skylos/commands/verify_cmd.py), [skylos/commands/verify_cmd.py:100](../skylos/commands/verify_cmd.py), [skylos/commands/verify_cmd.py:199](../skylos/commands/verify_cmd.py), [skylos/verify_change.py:182](../skylos/verify_change.py).

For Python working trees, source verification also models affected function behavior against Git HEAD through the shared source-comparison service. It is a bounded static source model and carries explicit assumptions/unsupported coverage; a detected modeled difference or unknown result can downgrade an otherwise passing source verdict to incomplete. External environment stability and unchanged Git submodules are assumptions. This is not runtime test execution or a universal equivalence proof. The diff path separately verifies changed lines and does not run that behavior model. Sources: [skylos/verify_change.py:110](../skylos/verify_change.py), [skylos/verification/changes.py:16](../skylos/verification/changes.py), [skylos/verify_change.py:182](../skylos/verify_change.py).

`skylos contract init` creates `.skylos/ai-contract.yml`; `validate` checks schema and `inspect`/`explain [--json]` explains effective policy. A contract can constrain declared dependencies, API signatures/references, required test changes and protected route guards; verification automatically discovers it or accepts `--contract PATH`. This is distinct from the runtime behavior contract used by `agent test`. Sources: [skylos/commands/contract_cmd.py:25](../skylos/commands/contract_cmd.py), [skylos/contracts/metadata.py:41](../skylos/contracts/metadata.py), [skylos/contracts/routes.py:12](../skylos/contracts/routes.py).

### Completion gate with skylos done

`skylos done [path]` checks that a change is finished and writes an evidence receipt to `.skylos/receipts/` (including `latest.json`). It compares against HEAD by default (uncommitted change), `--base REF` uses a PR target comparison, or `--session ID` uses an agent's captured baseline. It runs the trusted test command itself and reports text/JSON/Markdown; `--agent CLIENT` records the actor. `done receipt` displays the latest saved receipt. Exit 0 passes; exit 1 represents fail **or unfinished**; exit 2 means it could not run/write a valid receipt. `--no-tests` makes a required tests check unfinished, preventing a default-policy pass. Sources: [skylos/commands/done_cmd.py:30](../skylos/commands/done_cmd.py), [skylos/commands/done_cmd.py:97](../skylos/commands/done_cmd.py), [skylos/done/receipt.py:31](../skylos/done/receipt.py).

Policy comes from `[tool.skylos.done]` at the trusted base, so the change under review cannot loosen its own completion settings. Each check supports `block`, `advise`, `shadow`, or `off`; only block checks decide the completion verdict. Required earlier failures can defer test/coverage execution. The default test budget is 300 seconds, changed-line check budget 120 seconds, and stop-loop retry cap three. Non-pytest commands need configured JUnit evidence to produce a passing blocking tests check; process exit zero alone is insufficient. Sources: [skylos/done/config.py:16](../skylos/done/config.py), [skylos/done/config.py:88](../skylos/done/config.py), [skylos/done/engine.py:44](../skylos/done/engine.py).

| Done check | Default policy | What it examines |
| --- | --- | --- |
| `tests_pass` | Block | Tests run by Skylos, with evidence that tests actually ran. |
| `test_tampering` | Block | Deleted/skipped/focused tests, weakened assertions and test settings. Python and JS/TS test inventories have dedicated support. |
| `gate_tampering` | Block | Changes to Skylos settings and native agent hook/config files. |
| `secrets` | Block | Added secrets in the change. |
| `unknown_imports` | Advise | Packages/imports that cannot be justified. |
| `changed_lines_checked` | Advise | Whether tests check changed lines rather than merely touching them. |
| `test_special_casing` | Block | Exact test-input answers, test-run detection and comparison rigging; weaker indicators stay advice. |
| `silenced_checks` | Advise | Linters, type checkers, scanners and CI weakened or silenced. With block mode, inline suppressions can remain advice. |
| `security_controls` | Block | Removed authentication/CSRF/rate-limit and supported security controls. |
| `guardrail_tampering` | Advise | Changes to AI-reviewer guidance/settings and scanner suppression markers. |
| `branch_orphans` | Advise | Code made dead, new uncalled code, and code called only by tests; configured rule selection controls what blocks. |

The test failure-origin feature reruns failing tests against the base to label them introduced, preexisting, or undetermined. This labeling is enabled by default and does not automatically excuse failures; `allow_preexisting_failures` must be explicitly enabled at the trusted base to stop verified preexisting failures from blocking. Receipts include policy digest, base/head binding, agent/session metadata, per-check findings/evidence and unverified scope. Uploading a receipt requires matching current clean HEAD and upload commit; stale or dirty receipts cannot vouch for a different upload. Sources: [skylos/done/config.py:112](../skylos/done/config.py), [skylos/done/receipt.py:188](../skylos/done/receipt.py), [skylos/done/receipt.py:807](../skylos/done/receipt.py).

### Agent hooks and project standards

`skylos agent install-hooks` merges native hooks for Claude Code, Codex or Cursor without replacing unrelated hooks; rerunning is idempotent. Explicit client flags are `--claude`, `--codex`, `--cursor`; project or user scope, `--uninstall`, `--path`, an executable override, `--dry-run` and optional probe skipping are supported. The installer probes the chosen Skylos executable by default. Sources: [skylos/commands/install_hooks_cmd.py:96](../skylos/commands/install_hooks_cmd.py).

`skylos hook` supports `session-start`, `pre-edit`, `post-edit`, `pre-read`, `pre-bash`, `post-bash`, `post-failure`, and `stop`. It captures the starting checkout and before/after edit attribution; verifies new edited ranges; guards secret-containing reads; checks package installation and git-hook bypass attempts; records shell/failed-tool partial changes; and checks remaining issues at stop. Native adapter output differs per client. Normal hook events return exit 0 and communicate blocking decisions through the client's JSON contract. Internal failures allow continuation **with visible unchecked-action notices** and cannot produce a passing Done receipt. `SKYLOS_HOOKS_DISABLE` can disable hook events. Sources: [skylos/commands/hook_cmd.py:1](../skylos/commands/hook_cmd.py), [skylos/commands/hook_cmd.py:38](../skylos/commands/hook_cmd.py), [skylos/commands/hook_cmd.py:149](../skylos/commands/hook_cmd.py).

Edit blocking is evidence-sensitive: secrets, supported hallucinated dependencies/APIs/references, explicit contract violations, inherently dangerous sinks and disabled security verification block; source-to-sink security findings block when supported untrusted-source evidence exists. Other findings can be returned as notes. `[tool.skylos.hooks]` configures direct-source/unverified install decisions (`ask|deny|allow`), trusted registries and hook-bypass blocking. Default is to ask for unverified/direct-source installs and block git-hook bypasses. Codex's adapter uses deny for `ask`, because that hook contract does not support asking. Sources: [skylos/commands/hook_policy.py:1](../skylos/commands/hook_policy.py), [skylos/commands/hook_install_policy.py:1](../skylos/commands/hook_install_policy.py).

`skylos hook recheck FILE... [--range L1:L2]` and `recheck --session` rerun the same policy on disk, printing an actionable verdict (0 clean, 1 blocking issues, 2 usage/error). `skylos agent warm-cache [path]` prebuilds the Python module-facts index at `.skylos/cache/module-facts.json`, removing the initial full-index delay from the first post-edit hook. Sources: [skylos/commands/hook_cmd.py:302](../skylos/commands/hook_cmd.py), [skylos/commands/hook_cmd.py:452](../skylos/commands/hook_cmd.py), [skylos/commands/warm_cache_cmd.py:1](../skylos/commands/warm_cache_cmd.py).

`skylos agent install-standards --standards project.md --enforce SKY-Q...` creates native agent skills and `.skylos/agent-standards.json` pointing to a single project Markdown standards file. It supports dry run and selected built-in quality rules. `agent check-standards [path] --format text|json` performs local static enforcement of those selected rules (0 pass, 1 violation, 2 incomplete/error). No selected rule means guidance-only. The command does not invoke project tests, package scripts, dependency audits or provider calls. Hooks integrate the same standards policy. Sources: [skylos/commands/install_standards_cmd.py:1](../skylos/commands/install_standards_cmd.py), [skylos/commands/install_standards_cmd.py:60](../skylos/commands/install_standards_cmd.py), [skylos/commands/check_standards_cmd.py:1](../skylos/commands/check_standards_cmd.py).

### Runtime agent behavior contracts and saved harness evidence

`skylos agent init` creates `.skylos/agent-test.yml` (custom project-local path/force supported). `agent test [contract]` evaluates a declared suite against an OpenAI-compatible chat endpoint or evaluates normalized `--observations` JSON offline. Assertions cover required/excluded response strings; required, allowed and forbidden tool calls; tool arguments, exact sequence and call counts; refusal; and cited required sources. The verdict comes from deterministic assertions, not an LLM judge. Tool-call observations are evaluated as evidence rather than granting Skylos permission to execute arbitrary tools. Sources: [skylos/commands/agent_test_cmd.py:31](../skylos/commands/agent_test_cmd.py), [skylos/agents/evaluation/schema.py:69](../skylos/agents/evaluation/schema.py), [skylos/agents/evaluation/evaluator.py:25](../skylos/agents/evaluation/evaluator.py).

Live endpoint invocation requires explicit trust: `--endpoint`, optional bearer token from `--auth-env`, and `--allow-remote` for nonloopback HTTPS endpoints; a contract's unauthenticated loopback endpoint needs `--allow-contract-endpoint`. Repeated `--scenario` selects cases. Defaults cap a run at 25 scenarios, 300 seconds and a requested 1,024 output tokens; caps are configurable. Outputs are table/JSON with optional project-local file, and evidence/harness artifacts are saved by default unless `--no-artifacts`. Fixture observations remain identified as unverified data; offline fixture success is not proof of a live deployment's behavior. Sources: [skylos/commands/agent_test_cmd.py:51](../skylos/commands/agent_test_cmd.py), [skylos/agents/evaluation/runner.py:47](../skylos/agents/evaluation/runner.py), `skylos/agents/evaluation/_runner_evidence.py`.

`skylos agent replay RUN_DIR --format table|json` validates and inspects saved harness records such as `.skylos/runs/<run-id>`. It exposes run identity/status, phases, tool calls, decisions, duration, budgets used/remaining, artifacts and consistency issues. It returns 0 for a valid saved run and 1 for invalid evidence. It does not rerun provider calls. Sources: [skylos/commands/agent_replay_cmd.py:27](../skylos/commands/agent_replay_cmd.py).

### Continuous local triage and local API

`skylos agent watch [path]` continuously refreshes a local findings/action state. It polls at five seconds by default; `--once` or finite `--cycles` bound it; default confidence is 80, baseline support is on, and the default action display cap is 10. It tracks source/config signatures and reuses state when unchanged. It combines findings with debt hotspots, ranks actions using severity, change/freshness, baseline and fixability, and stores `.skylos/agent_state.json` (override supported). `--learn` opts into pattern learning from triage. This command runs before the LLM-provider setup branch and does not require provider credentials. Sources: [skylos/cli.py:4095](../skylos/cli.py), [skylos/cli.py:4357](../skylos/cli.py), [skylos/agents/center.py:405](../skylos/agents/center.py), [skylos/agents/center.py:736](../skylos/agents/center.py).

`agent status` reads state (optional `--refresh`) in table/JSON/feed format. `agent triage suggest`, `dismiss`, `snooze` (24 hours default), and `restore` manage ranked actions and learned suggestions. `agent serve` exposes the same state locally at `127.0.0.1:5089` by default, with optional bearer token and browser-origin allowlist. GET endpoints are `/health`, `/state`, `/command-center`, `/suggestions`; POST endpoints refresh, dismiss/snooze/restore and learn. It is an optional local API, distinct from the hosted Cloud application. Sources: [skylos/cli.py:4134](../skylos/cli.py), [skylos/cli.py:4195](../skylos/cli.py), [skylos/agents/service.py:295](../skylos/agents/service.py).

`agent pre-commit` analyzes the staged snapshot, including staged source/config secrets, dependency-change metadata and contract evidence. It filters findings to staged report files/changed ranges, honors baselines and trusted reviews, excludes dead-code/debt candidates from the blocking queue and suppresses selected nonblocking quality findings locally. A full repository/diff-aware CI scan remains broader. Confidence defaults to 80 and output is table/JSON. The checked-in pre-commit hook package also exposes `skylos-scan` (report-only Python security/dead-code scan) and `skylos-defend` (critical defense gate). Sources: [skylos/cli.py:4121](../skylos/cli.py), [skylos/cli.py:4441](../skylos/cli.py), [skylos/cli.py:4750](../skylos/cli.py), [.pre-commit-hooks.yaml:1](../.pre-commit-hooks.yaml).

### Runtime traces and coverage evidence

Ordinary source scans remain static. `--trace` explicitly executes pytest with call tracing, saves `.skylos_trace`, and lets executed definitions suppress dead-code candidates. `--pytest-fixtures` explicitly runs pytest fixture tracking and saves unused-fixture information. Coverage data can be consumed by `--coverage`; project tests are only started by coverage when `--allow-coverage-execution` is also set, with pytest then unittest fallback. Existing trace input is supported through the analyzer API. These modes require trusted project execution and should be documented as opt-ins. Sources: [skylos/cli_core/main_parser.py:61](../skylos/cli_core/main_parser.py), [skylos/cli_core/main_parser.py:81](../skylos/cli_core/main_parser.py), [skylos/cli.py:3229](../skylos/cli.py), `skylos/core/tracer.py`.

`--cache` caches successful traced pytest runs; `--refresh-cache` reruns them and `--no-cache` disables reuse. Cache keys include source/dependency/test context; partial/failed test traces can still inform the current analysis when usable but are not cached as successful trace runs. `skylos cache stats|clear` manages the run cache. Sources: [skylos/cli_core/main_parser.py:66](../skylos/cli_core/main_parser.py), [skylos/cli.py:3270](../skylos/cli.py), [skylos/commands/cache_cmd.py:13](../skylos/commands/cache_cmd.py).

### Cloud connection policy uploads and migration

`skylos login` launches the hosted CLI-login flow and waits up to 300 seconds on a state-protected localhost callback. It supplies repository identity/subpath context so a user can select/create a Cloud project and store the resulting local link/token. `project status/list` inspect active and locally known projects; `use/create` run selection; `unlink` removes the local repository link. `sync connect` also accepts an explicit token. Token lookup prioritizes `SKYLOS_TOKEN`, then supported CI OIDC, then project-linked/global local credentials. Sources: [skylos/cloud/login.py:1](../skylos/cloud/login.py), [skylos/cloud/sync.py:346](../skylos/cloud/sync.py), [skylos/cloud/sync.py:668](../skylos/cloud/sync.py).

`sync pull` fetches Cloud configuration and review decisions, validates project identity, activates `.skylos` config/suppression files together and stores trusted review state outside repository-controlled files. `--dry-run --format json` validates without changing files or trust. Failed normal pulls invalidate stale trusted suppression bundles instead of treating an outage as an authoritative empty review state. `sync setup` and `upgrade` configure local/pre-push/workflow integrations and paid features according to the connected account. Cloud custom rules also carry explicit loading/coverage receipts rather than silently disappearing when unavailable. Sources: [skylos/cloud/sync.py:770](../skylos/cloud/sync.py), [skylos/cloud/sync.py:961](../skylos/cloud/sync.py), [skylos/cloud/sync.py:1175](../skylos/cloud/sync.py), [skylos/cli.py:3392](../skylos/cli.py).

Source report uploads can include selected normalized findings, bounded context snippets for nonsecret categories, analysis coverage, provenance, dependency inventory and valid Done receipt. Secret findings have snippets stripped, including compatibility payloads. Suite upload can publish selected `static,defense,debt` families as separate scans tied to one suite bundle, with static-category selection. Upload is explicit in the command's options except external Claude Security ingestion, whose upload is **on by default** and can be disabled with `--no-upload`. Sources: [skylos/api/_findings.py:168](../skylos/api/_findings.py), [skylos/api/_upload_preflight.py:199](../skylos/api/_upload_preflight.py), [skylos/commands/suite_cmd.py:181](../skylos/commands/suite_cmd.py), [skylos/commands/ingest_cmd.py:19](../skylos/commands/ingest_cmd.py).

Transient upload failures (network, timeout, server errors, rate limiting or interruption) save signed pending records under `~/.skylos/pending-uploads/`, one folder per repository, for up to seven days. `skylos upload` lists them; `upload --retry` resends with the original idempotency key, preventing duplicate saving/charging. Delivered records are removed, permanent rejects move to `failed/`, and unreadable/unverifiable records are skipped visibly. Sources: [skylos/commands/upload_cmd.py:15](../skylos/commands/upload_cmd.py).

`skylos review` records a required reason for an exact false positive or a time-bounded risk acceptance (maximum 365 days). Identity is bound to fingerprint, context hash and rule revision, so material code/evidence changes bring a finding back. `review list` shows state/expiry/reason; `review restore|revoke ID` restores it. Local decisions are ignored in CI, and creation/mutation is rejected there; team/CI trust comes from synced Cloud review state. Sources: [skylos/commands/review_cmd.py:22](../skylos/commands/review_cmd.py), [skylos/commands/review_cmd.py:242](../skylos/commands/review_cmd.py), [skylos/commands/review_cmd.py:391](../skylos/commands/review_cmd.py), [skylos/commands/review_cmd.py:415](../skylos/commands/review_cmd.py).

`skylos sonar import [sonar-project.properties]` parses properties and emits an explicit migration plan; `--write-config` writes mapped `.skylos/config.yaml`, and `--config-output` changes destination. `skylos compare --against incumbent.sarif` normalizes SARIF, Sonar issues JSON or normalized findings, optionally reuses a Skylos JSON report, and reports same-location overlaps, incumbent-only/Skylos-only counts and review/deletion candidates. It tracks revision binding, repository scope, completeness and comparable categories; overlap is not proof of equivalent rules. Default comparison runs no network queries; `--sca` explicitly enables bounded direct-pin OSV checks. `--upload` explicitly sends a bounded Scanner Proof receipt to the token's project. Its usable comparison returns 0; unusable input or upload failure returns 2. Sources: [skylos/commands/sonar_cmd.py:7](../skylos/commands/sonar_cmd.py), [skylos/commands/compare_cmd.py:16](../skylos/commands/compare_cmd.py), [skylos/commands/compare_cmd.py:300](../skylos/commands/compare_cmd.py).

### CI and external review surfaces

`skylos cicd init` generates `.github/workflows/skylos.yml` with PR gates, changed-line scans and review comments, plus full default-branch uploads using GitHub OIDC by default. It detects `origin/HEAD` or falls back to main/master; scan subpath supports monorepos. Defaults are Python 3.12, pull_request/push triggers and dead-code/security/quality/AI-defect/secrets/dependency analysis. Baseline support defaults on. Optional switches add LLM analysis/model, Claude Security parallel job, AI defense, risk-review and advisory gate. Done is automatically included when a supported pytest project or configured test command can be detected, or explicitly selected with `--done`/`--no-done`. Existing identical workflows are a no-op; replacing a different workflow requires interactive confirmation or `--force` and creates a `.bak`. Sources: [skylos/commands/cicd_cmd.py:211](../skylos/commands/cicd_cmd.py), [skylos/commands/cicd_cmd.py:326](../skylos/commands/cicd_cmd.py).

`cicd gate` reads a JSON report or performs analysis, applies trusted base policy, supports strict/advisory mode and GitHub step summary. `cicd annotate` emits workflow annotations (default cap 50, optional severity threshold). `cicd review` posts PR review comments through `gh`, accepts existing static/LLM/defense input, supports summary-only, default 25 inline comments and evidence-card formatting (Proven/Likely/Speculative). Those publishing actions are actual GitHub writes when invoked. Sources: [skylos/commands/cicd_cmd.py:446](../skylos/commands/cicd_cmd.py), [skylos/commands/cicd_cmd.py:478](../skylos/commands/cicd_cmd.py), [skylos/commands/cicd_cmd.py:495](../skylos/commands/cicd_cmd.py).

`cicd risk-review` identifies nine configurable PR risk classes: weakened tests, removed auth/CSRF/rate limiting, dependency change, weakened CI/widened permissions, silenced checks, added secret, guardrail config change, migration change and very large diff. It compares a PR with its merge base and uses `[tool.skylos.approval]` from the base. In GitHub Actions, qualifying human write-access approval must apply to the head commit; bot approvals do not count. Exit 0 passes, 1 needs approval, 2 is undecidable; text/JSON/Markdown are available. Sources: [skylos/commands/risk_review_cmd.py:27](../skylos/commands/risk_review_cmd.py), [skylos/cicd/approval.py:40](../skylos/cicd/approval.py).

The repository's composite GitHub Action exposes `mode=scan|gate|review` (default gate), source path, analysis family selection (default dead-code/security), confidence 60, Python 3.11, optional legacy token, SARIF upload/category, max PR comments 15, and optional AI security verification/model. OIDC upload is preferred to a static token. Image mode takes digest-pinned `image`, required `image-platform` and gate threshold default high, and supports scan/gate only. Outputs are findings count, gate passed and report path. The action sets up Python, detects/builds Go engine when needed, installs Skylos with Dart support, and can publish SARIF to GitHub code scanning when permission is granted. Sources: [action.yml:1](../action.yml).

`skylos verify-verdict BUNDLE` independently checks the Cloud Ed25519 DSSE signature, in-toto/SLSA summary and committed check summary. Keys default to the published HTTPS key set; `--keys LOCAL_FILE` supports offline trust. Optional requirements bind full commit SHA, repository, project, workspace, repository verification, trusted upload and maximum age; `--require-passed` requires an actual policy pass. Admin overrides need `--allow-override`; disabled/unknown gates do not count as a policy pass. Exit 0 is verified/acceptable, 1 is verified but fails requested pass policy, 2 is unverified/invalid/missing crypto. This verifies the recorded check and policy over uploaded results; it does not establish universal source safety. Sources: [skylos/commands/verify_verdict_cmd.py:1](../skylos/commands/verify_verdict_cmd.py), [skylos/commands/verify_verdict_cmd.py:133](../skylos/commands/verify_verdict_cmd.py).

### GPU release preflight

`skylos preflight [ARTIFACT]` checks an exact local CUDA build against `.skylos/gpu-targets.yml` or `.yaml`; without an argument it discovers `.skylos/release.json`. It inventories embedded cubin/PTX architecture records with trusted `cuobjdump`, verifies file/tree identity, checks platform, selected executable-fatbin coverage, statically bound packaged CUDA runtime and driver-family compatibility for each fleet target. It never starts the artifact. Reports are concise on terminals and JSON when redirected. Exit 0 PASS requires all fleet targets to pass; 1 FAIL reflects proven incompatibility; 2 UNKNOWN covers missing/unsupported/incomplete evidence or invalid input. Sources: [skylos/commands/preflight_cmd.py:20](../skylos/commands/preflight_cmd.py), [skylos/preflight/profile.py:11](../skylos/preflight/profile.py), [skylos/preflight/inspector.py:141](../skylos/preflight/inspector.py), [skylos/preflight/evaluator.py:73](../skylos/preflight/evaluator.py).

Version-one preflight does not prove per-kernel symbol parity, nonselected/relocatable-fatbin completeness, loader environment behavior, workload correctness, memory requirements or performance. Digest-pinned OCI references are accepted as targets but are **not pulled** and remain UNKNOWN in the CLI. Source-change checks and container CVEs belong to other commands. Sources: [skylos/preflight/evaluator.py:112](../skylos/preflight/evaluator.py), [skylos/commands/preflight_cmd.py:23](../skylos/commands/preflight_cmd.py).

### MCP server

`skylos mcp` starts MCP over stdio by default; `--transport stdio|sse|streamable-http` or `MCP_TRANSPORT` selects transport. Network defaults are `MCP_BIND=127.0.0.1`, `PORT=8080`; network transports require a separate `SKYLOS_MCP_TOKEN` (at least 16 characters) for client authentication. `SKYLOS_API_KEY` authenticates the server to Skylos Cloud and is a distinct credential. Sources: [skylos/commands/mcp_cmd.py:10](../skylos/commands/mcp_cmd.py), [skylos_mcp/auth.py:30](../skylos_mcp/auth.py), [skylos_mcp/auth.py:129](../skylos_mcp/auth.py).

There are **16 registered tools**. Without `SKYLOS_API_KEY`, only `analyze` is allowed, with five calls/day. Authenticated MCP plans have their own call-rate and access checks. The current Cloud migration sets scan-family credit costs, including provenance, to zero; MCP remediation retains its ten-credit price. The local MCP client still contacts the access/credit endpoint for mapped tools, so authenticated use can depend on Cloud connectivity even for a zero-cost scan. These MCP limits do not apply to ordinary local CLI scans. Source scans run locally; LLM tools send selected context to their configured provider. Sources: [skylos_mcp/auth.py:16](../skylos_mcp/auth.py), [skylos_mcp/auth.py:250](../skylos_mcp/auth.py), [skylos_mcp/server.py:1046](../skylos_mcp/server.py), and Cloud `supabase/migrations/20261009183720_mcp_scans_no_credits.sql`.

| MCP tool | Capability |
| --- | --- |
| `analyze` | Dead-code candidates: functions, classes, imports, variables, parameters, files. |
| `security_scan` | Local source vulnerability checks. |
| `quality_check` | Function/code maintainability findings. |
| `architecture_check` | Architecture findings and metrics/cycles. |
| `health_score` | Separate Risk, Maintainability and Dead code assessment with coverage; retains old tool name but no longer creates a blended numeric grade. |
| `secrets_scan` | Redacted secret findings. |
| `remediate` | Static fix planning by default (dry run, max five findings); explicit application invokes the configured model. MCP refuses `test_cmd` and does not execute project tests. |
| `verify_dead_code` | LLM candidate review without edits; default main cap 30, challenge cap 10, confidence 60. |
| `provenance_scan` | Recorded/declared change attribution and optional risk intersection. |
| `generate_fix` | Deterministic grep-verified dead-code patch preview; optional apply, delete/comment mode and safety threshold. Incomplete analysis/grep refuses fixing. |
| `learn_triage` | Record accept/dismiss decisions for learned triage. |
| `get_triage_suggestions` | Suggestions from learned triage patterns. |
| `validate_code_change` | Analyze a unified diff before landing, including dependency-change checks. |
| `verify_change` | Focused source verification, including optional file/range/context/contract behavior. |
| `verify_agent` | Static AI integration/defense assessment, OWASP LLM or Agentic mappings, optional score/severity gate and reproducible attestation digest. |
| `get_security_context` | Framework/auth/middleware/security-header/rate-limit/validation and YAML policy context. |

Tools return compact results and `_run_id`/`_result_uri`; Defect/Review records remain present while Advice is grouped by default, expandable with `expand_advice`. Full saved results are exposed through `skylos://results/latest`, `skylos://results/{run_id}`, and `skylos://results`. Local stored results can be reread without rescanning. Sources: [skylos_mcp/server.py:1164](../skylos_mcp/server.py), [skylos_mcp/server.py:1302](../skylos_mcp/server.py), [skylos_mcp/server.py:1425](../skylos_mcp/server.py), [skylos_mcp/server.py:1456](../skylos_mcp/server.py), [skylos_mcp/server.py:1592](../skylos_mcp/server.py), [skylos_mcp/server.py:1947](../skylos_mcp/server.py), [skylos_mcp/server.py:2037](../skylos_mcp/server.py).

### VS Code extension

The bundled editor extension invokes the installed local CLI and provides workspace/file scans, cancellation, Doctor, save-triggered file refresh and optional first-file-on-open scan. Defaults enable danger, secrets, quality and dead-code display at confidence 80; CLI scan arguments enable those three extra families rather than blindly requesting every CLI capability. New-Issues mode uses configurable `--diff-base` (default `origin/main`). Provider chat/fixes are optional. Sources: `editors/vscode/package.json`, [editors/vscode/src/scanner.ts:53](../editors/vscode/src/scanner.ts), [editors/vscode/src/scanCore.ts:36](../editors/vscode/src/scanCore.ts).

Editor surfaces include a ranked Review Queue, Problems diagnostics, restrained inline decorations, hovers, CodeLens actions, file badges, next/previous navigation, finding detail panel, status bar and a dashboard. Details show prioritization reasons, evidence/trace metadata when available, likely CI effect and fix options. Filtering by category/severity/source/text and New-Issues mode changes presentation, not the underlying full workspace assessment. Problem/tree/decoration caps prevent editor overload; dead parameters and dead-code Problems are hidden by default. Editor signal modes are quiet/balanced/verbose and CodeLens modes off/activeLine/highValue/all. Sources: `editors/vscode/src/extension.ts`, `editors/vscode/src/reviewCore.ts`, `editors/vscode/src/assessmentCore.ts`, `editors/vscode/package.json`.

The current assessment distinguishes risk, maintainability, dead code, coverage and gate. A failed/focused file scan invalidates prior whole-workspace coverage while retaining known findings. Old CLI numeric grades appear only as explicitly labeled legacy scores. Exports are Markdown, JSON and SARIF; JSON retains complete extension findings plus original CLI report, and SARIF retains all extension findings with assessment. Sources: `editors/vscode/src/store.ts`, `editors/vscode/src/assessmentCore.ts`, [editors/vscode/src/export.ts:8](../editors/vscode/src/export.ts).

Security Copilot provides finding-context chat and optional application of code blocks. Manual AI actions support OpenAI, Anthropic and OpenAI-compatible local servers; provider/model/base URL are configurable. Individual fixes default to a diff preview and optionally run a configured post-fix shell command. Fix All supports severity selection, progress, a cap (default 50, maximum 200), separate undo steps and a dry-run preview. Fix All skips dead-code findings and does not use the individual preview/post-fix-command settings. Source context is sent to the chosen provider even for AI dry runs. Sources: `editors/vscode/src/ai.ts`, `editors/vscode/src/chatview.ts`, `editors/vscode/src/autoremediate.ts`, [editors/vscode/src/extension.ts:463](../editors/vscode/src/extension.ts), `editors/vscode/package.json`.

Engine fix actions preview engine-generated patches when available. Direct line-deletion commands for unused functions/imports are explicitly disabled. Preview Dead Code Removal invokes `skylos agent verify --fix`, requires a trusted workspace, and can call the CLI's configured provider. It is a preview action, not a claim of automatic safe deletion. Sources: [editors/vscode/src/extension.ts:245](../editors/vscode/src/extension.ts), [editors/vscode/src/extension.ts:347](../editors/vscode/src/extension.ts), [editors/vscode/src/extension.ts:563](../editors/vscode/src/extension.ts).

Optional idle-time verification is **off by default** (`skylos.enableRealtimeAI=false`). When enabled in a trusted workspace it sends unsaved file content/changed-function range to `skylos verify --stdin --no-fail`, publishes returned diagnostics and makes no model-provider call. The historical setting name still contains AI. `streamingInline` is explicitly reserved; current edit verification uses standard diagnostics, so streaming AI output should not be listed as active. Sources: [editors/vscode/src/verifyCore.ts:30](../editors/vscode/src/verifyCore.ts), [editors/vscode/src/extension.ts:640](../editors/vscode/src/extension.ts), `editors/vscode/package.json`.

The optional Automation Activity view reads the local command center, refreshes state and opens ranked action details, safe-fix preview, dismiss/snooze/restore. Automatic refresh on extension open/save defaults off. It integrates with `agent watch`/state and is separate from ordinary file scanning. Workspace trust guards provider-backed/editing features. CLI network lookups and Cloud sync continue to follow CLI configuration. Sources: `editors/vscode/src/commandcenter.ts`, `editors/vscode/src/automationCore.ts`, [editors/vscode/src/extension.ts:419](../editors/vscode/src/extension.ts), `editors/vscode/package.json`.

### Practical command examples

Inspect local state/configuration or preview source edits:

```bash
skylos doctor --format json
skylos commands
skylos verify src/service.py --format short --no-dependency-hallucinations
skylos verify . --diff HEAD --format json --no-dependency-hallucinations
skylos contract inspect .skylos/ai-contract.yml --json
skylos clean src --dry-run --types import,function --confidence 90
skylos agent status . --format json
skylos agent install-hooks --codex --project --dry-run
skylos done receipt . --format markdown
skylos sync pull --dry-run --format json
skylos upload --list --json
skylos compare . --against incumbent.sarif --format json
skylos agent replay .skylos/runs/RUN_ID --format json
```

Explicit workflows with state/output writes, trusted tests or configured providers:

```bash
skylos agent security-deep . --scan-only --format json
skylos agent verify src --format json
skylos agent verify src --dead-code-review jev --format json
skylos agent scan src --verify-dead-code --dead-code-review jev-llm --format json
skylos agent remediate src --dry-run --severity high
skylos agent watch . --once --format json
skylos agent test .skylos/agent-test.yml --observations observations.json --format json
skylos done . --base origin/main --format json
skylos mcp --transport stdio
skylos verify-verdict verdict.json --keys trusted-keys.json --commit FULL_COMMIT_SHA --require-passed
skylos preflight build/app
```

The Jev examples require the separately configured TypeSafe key; the mixed/LLM examples require provider configuration. `done` executes trusted project tests; `preflight` needs an existing fleet profile and built artifact. Example files and IDs are placeholders.

## Cloud features

### Product navigation and workspace model

The current application organizes the dashboard around Home, Pull requests, Issues, Policy, Not fixing, Audit reports, and Settings. Agents appears when agent checks are switched on; Deep scans appears when its worker is configured. Projects, Posture, Trends, all scan uploads, Rules, Compliance, Audit log, Access review, and Teams remain implemented destinations linked from those main areas. A repository has its own overview, issues, pull requests, scan history, and settings, with deeper views for technical debt, AI safeguards, attribution, the agent PR log, Scanner proof, controls, suppressions, and investigation.

Sources: [dashboard navigation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/dashboard-navigation.ts:1), [page definitions](/Users/oha/skylos-cloud/skylos-cloud/src/lib/page-guides.ts:22), [project navigation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/project-navigation.ts:1), [settings sections](/Users/oha/skylos-cloud/skylos-cloud/src/lib/settings-sections.ts:10).

### Home projects posture and trends

| Feature | Implemented behavior |
|---|---|
| Repository release board | Shows each repository's current default branch result, blockers, ownership, scan freshness, and the next useful action. Search/filter/page controls operate on the portfolio. |
| Attention queue | Surfaces protected path approvals, requests to accept risk, urgent assigned issues, setup gaps, and active cleanup work. |
| Trust-aware result selection | A repository verdict uses its newest complete native code scan on its default branch, preferring trusted uploads. Feature branch and PR scans have their own views. A claimed pass from an unverified upload never becomes an authoritative passing repository result. |
| Freshness | Repositories become stale after 14 days in the release board. Unknown default branches, missing results, incomplete ingestion, disabled gates, and overrides have distinct presentation. |
| Project management | Create projects, rename them, attach/change repository URLs and repository subpaths, connect existing repositories, delete projects individually or in bulk, and choose the owning team. |
| Portfolio posture | Lists unscanned, failing, unenforced, stale, incomplete, and unverified repositories alongside current critical/high issue counts, fix deadlines, safeguards, and uploader/attestation information. |
| GitHub coverage inventory | Compares GitHub repositories visible to the App with onboarded Skylos projects and required checks. Distinguishes not onboarded, not scanned, not enforced, enforced, and unknown evidence; offers relevant setup actions and inventory sync. Search, owner, archive, state, and stale filters are implemented. |
| Bulk onboarding | Previews eligible repositories and remaining project capacity; excludes archived/fork/empty repositories by default; supports repository search and exclusion globs. Can queue adding projects and separate setup workflow PRs, with progress/retry state. |
| Home trends | Weekly default branch gate results and issue movement feed the Home charts. Overrides, unfinished uploads, and disabled gates do not count as passing scans. |
| Project and workspace trends | Historical chart/table views show check counts, gate changes, grades where present, architecture findings, and risk/assessment data where present. Users can select a project and time window, inspect source scans, and see technical debt, AI code attribution, and AI safeguard summaries. Unrun checks remain unknown rather than becoming zero. |

Sources: [Home query and attention behavior](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/page.tsx:151), [repository verdict](/Users/oha/skylos-cloud/skylos-cloud/src/lib/repo-verdict.ts:1), [project API](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/route.ts:1), [posture](/Users/oha/skylos-cloud/skylos-cloud/src/lib/org-posture.ts:1), [coverage](/Users/oha/skylos-cloud/skylos-cloud/src/lib/repo-coverage-core.ts:26), [bulk onboarding](/Users/oha/skylos-cloud/skylos-cloud/src/lib/bulk-onboarding-core.ts:1), [Home trends](/Users/oha/skylos-cloud/skylos-cloud/src/lib/home-trends/core.ts:1), [project trends](/Users/oha/skylos-cloud/skylos-cloud/src/lib/project-trends/core.ts:1), [trend payload](/Users/oha/skylos-cloud/skylos-cloud/src/lib/trends.ts:15), [trend UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/trends/TrendsView.tsx:400).

### Connecting repositories and receiving results

The application supports CLI/browser connection, project keys, trusted CI keys, GitHub Actions OIDC, GitLab CI OIDC, native scan uploads, SARIF ingestion/normalization, staged upload initialization/completion, idempotent upload replay, root-aware project routing, and explicit ingestion completeness. The scan record can include branch/commit/PR identity, scanner version, command/check coverage, source snippets and evidence, baselines, provenance, debt and defense summaries, and an applied policy snapshot.

The GitHub App can link an existing Skylos project or create/connect a repository project; inventory synchronization and installation health have dedicated UI and endpoints. Setup can produce a workflow pull request. The generated workflow handles default branch scans, ordinary/fork PRs, a separate done-check job, and a publisher bound to the PR head and trusted workflow. The code explicitly instructs the user to make `Skylos Quality Gate` required in branch rules after verifying the workflow. Opening a setup PR does not itself enforce a branch protection rule.

Sources: [CLI connect](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cli-connect-core.ts:1), [report route](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/report/route.ts:1), [upload contract](/Users/oha/skylos-cloud/skylos-cloud/src/lib/upload-contract.ts:1), [SARIF normalization](/Users/oha/skylos-cloud/skylos-cloud/src/lib/sarif.ts:1), [GitHub installation binding](/Users/oha/skylos-cloud/skylos-cloud/src/lib/github-installation-binding.ts:1), [workflow generation and explanation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/github-skylos-workflow.ts:664), [GitHub health](/Users/oha/skylos-cloud/skylos-cloud/src/lib/github-health.ts:1).

### Automatic Cloud repository scans

An installed GitHub App can scan a repository without a developer installing the CLI. Supported triggers are manual scan, connection, and push. A job reports queued/running/done/failed/cancelled status and preparing/cloning/analyzing/saving phases, with clear limit and failure reasons. Automatic scans skip repositories with a verified CI scan from the preceding seven days.

This worker clones the exact resolved commit in a Vercel Sandbox, revokes its read token after cloning, and runs the scanner without repository code execution or scan-phase network access. Its fixed checks are dead code, security, quality, secrets, and AI defects. It uses its own fixed scanner configuration and disables CLI provenance capture. Dependency CVE scanning is absent from this worker command because `--sca` needs network access; dependency results can arrive through CLI/CI uploads. Cloud still applies its effective gate policy when receiving results.

Local configuration pins this worker to Skylos `4.45.0`. Scans use no Skylos credits. The configured rolling daily caps are Free 5, Workspace 50, Enterprise 250; one repository has ten-minute spacing. Default concurrency is two. Worker limits are 8,000 files, 80 MB scanned content, 5 MB per file, 250 MB download, 45-second clone, 120-second analysis, and 4 MB results. Repository/project limits also apply. These are operational configuration values, not promises about the deployed service.

Availability requires a configured `SKYLOS_CLOUD_SCAN_SANDBOX_SNAPSHOT_ID`; `SKYLOS_CLOUD_SCAN_DISABLED=1` or `true` disables it.

Sources: [configuration, caps, availability](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cloud-scan-config.ts:1), [job states and failure copy](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cloud-scan-core.ts:6), [trigger handling](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cloud-scan-server.ts:470), [sandbox boundary](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cloud-scan-sandbox.ts:1), [actual scan command](/Users/oha/skylos-cloud/skylos-cloud/services/cloud-scan-worker/worker.py:124).

### Scan history and finding review

| Feature | Implemented behavior |
|---|---|
| All uploads and project scan history | Paged records for native code, defense/safeguards, technical debt, and attribution report families; each opens its appropriate detail page. |
| Scan result summary | Stored gate verdict, scope, branch/commit, identity/trust, input warnings, analysis completeness, checks run, new issue counts, overrides, and blocking reasons. |
| Finding workbench | Search, category filters, new/all mode, AI-attributed filtering, page controls, persistent selection/deep links, severity/type badges, line location, code context, rule explanation, and fix guidance. |
| Findings versus advice | Current local changes classify observations as Defect, Review, or Advice, order them accordingly, and group advice by rule. Dead code appears as review evidence; maintainability advice has its own measured counts. |
| Source context | Shows saved snippets and flagged lines, with file-reading endpoints where available and links back to the original scan/finding. Missing snippets are stated explicitly. |
| AI verification evidence | Displays traced/AI-verified/refuted/unverified classifications, votes/dispute state, confidence and proof details where supplied. A refuted opinion does not silently remove an otherwise active gate issue. |
| Security evidence | Can display recorded source-to-sink proof, taint paths, exploit rationale and suggestions, including imported Claude Code Security metadata. |
| Dependency evidence | Ecosystem, CVE/advisory ID and aliases, package/version, affected range, fixed version, CVSS, references, and dependency occurrence/context data. |
| Data-flow view | Returns stored taint flow when present. For supported rule families it can return a template illustration when recorded flow is absent; `has_flow_data` distinguishes the two. The illustration should not be documented as independently proven reachability. |
| Exports | All stored finding rows can be downloaded as JSON or CSV with scan/upload metadata. Export fields differ from the interactive evidence panels and API projections. |
| Public sharing | Create/copy/revoke a public scan report link; shared report pages use a dedicated public presentation and policy. Revocation disables the link. |
| Scan comparison | Compare older/newer compatible scans of the same project, show new/fixed/unchanged findings and severity breakdowns, inspect each side, swap selection, and use stable fingerprints with legacy location fallback. Findings moved to architecture advice appear as reclassified; missing findings outside newer scan coverage appear as not checked. Comparison refuses incomplete or over-limit reads; current limit is 25,000 findings per scan and 10,000 changes. |
| Baseline-aware issue lifecycle | Newness and resolution depend on matching scan/baseline scope and completeness. A trusted default branch scan that no longer observes an issue can mark it fixed. A local `skylos login` upload cannot establish that result. |

Sources: [scan detail composition](/Users/oha/skylos-cloud/skylos-cloud/src/components/scans/ScanDetailView.tsx:1), [finding workbench](/Users/oha/skylos-cloud/skylos-cloud/src/components/ScanDetailsClient.tsx:2020), [exports/sharing](/Users/oha/skylos-cloud/skylos-cloud/src/components/ScanDetailsClient.tsx:2636), [check coverage](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scan-checks.ts:1), [types and ordering](/Users/oha/skylos-cloud/skylos-cloud/src/lib/finding-display.ts:1), [evidence panel](/Users/oha/skylos-cloud/skylos-cloud/src/components/scans/ScanFindingEvidence.tsx:1), [flow endpoint](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/findings/[id]/flow/route.ts:44), [comparison](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scan-comparison.ts:1), [issue fixed semantics](/Users/oha/skylos-cloud/skylos-cloud/src/components/mission-control/IssueDetailClient.tsx:425).

#### Local assessment and dead code explanation additions

The uncommitted local implementation adds a versioned assessment with independent risk, maintainability, dead-code review, and coverage summaries. Risk counts are derived from canonical stored findings and authorized suppressions rather than trusting an uploaded grade claim. Coverage distinguishes complete/partial/incomplete/unknown and records checks not assessed. Unknown scanner severity is retained for presentation. Older scans can still have legacy grade display; a versioned assessment suppresses the blended grade.

Dead-code findings can retain bounded decision/event evidence: classification, primary reason, confidence/threshold, dead/live/uncertainty evidence counts, static references, reachable roots, imports/exports, dynamic/framework patterns, coverage/trace hits, validator outcomes, and rescue signals. The UI groups evidence that supports dead code, supports live use, expresses uncertainty, or provides context; contradictory evidence and truncation remain visible. Older uploads explicitly show that no stored explanation exists. The panel says the evidence explains a report and does not establish deletion safety.

These features are present in local source and tests and require appropriate deployed code/schema to work; deployment remains unverified.

Sources: [assessment derivation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scan-assessment.ts:1), [assessment UI](/Users/oha/skylos-cloud/skylos-cloud/src/components/scans/ScanAssessmentSummary.tsx:1), [legacy grade handling](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scan-checks.ts:116), [dead-code evidence contract](/Users/oha/skylos-cloud/skylos-cloud/src/lib/dead-code-evidence.ts:1), [dead-code explanation UI](/Users/oha/skylos-cloud/skylos-cloud/src/components/scans/DeadCodeEvidencePanel.tsx:25).

### Issues and team workflow

Cloud groups repeated findings into recurring issues with a canonical location, affected files, occurrence count, first/last observation, scan history, status, and verification information. The workspace queue can filter by repository, priority, owning team, assigned-to-me, code-on-my-lines, all work, due this week, overdue, and fixed. A user's one active team can be the initial queue filter; team filtering does not alter authorization.

Issue detail includes source context, rule/risk explanation, stored fix guidance, commands to rerun the local check, a paged occurrence history grouped by scan, assignment to an individual, assignment progress/notes, owning team with automatic/manual attribution, comments, linked Jira tickets, exception state and history, and organization-wide triage actions. Repeated findings link back to the complete scan workbench.

AI triage is an explicit credit-backed action. It sends bounded finding context to a model and returns priority P1–P4, impact, remediation steps, effort hours, and rationale. It is advice for the reviewer; it does not independently validate exploitability.

Teams can be created, renamed, described, archived/restored, populated with workspace members, and connected to CODEOWNERS aliases (`@org/team`, `@user`, or email). Repositories have owner teams. Issue ownership resolves from CODEOWNERS, then repository ownership, with manual override. Teams are an ownership/filtering system; joining a team does not grant access beyond the workspace role.

Sources: [grouping/lifecycle storage](/Users/oha/skylos-cloud/skylos-cloud/src/lib/issue-group-rows.ts:1), [queue UI and filters](/Users/oha/skylos-cloud/skylos-cloud/src/components/issues/IssueQueue.tsx:161), [issue detail](/Users/oha/skylos-cloud/skylos-cloud/src/components/mission-control/IssueDetailClient.tsx:472), [assignment](/Users/oha/skylos-cloud/skylos-cloud/src/lib/issue-assignment.ts:1), [AI triage](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/triage/route.ts:15), [Teams contract](/Users/oha/skylos-cloud/skylos-cloud/src/lib/teams/core.ts:1), [ownership](/Users/oha/skylos-cloud/skylos-cloud/src/lib/codeowners/ownership.ts:1).

### Pull request decisions and merge blocking

The PR list collapses repeated uploads into the latest trusted result for each PR. Views include all, failing, and waiting for my approval. Each row can show passed, failed, waiting for approval, overridden, running, gate off, or unverified upload, alongside current blocking reasons, required team approvals, agent facts, commit, and source scan. The same verdict definitions feed Home, project overview, the PR list, and scan detail.

Protected path approvals are bound to project, exact PR head commit, zone, and required team. A new head requires fresh approval. Approval checks require a linked GitHub identity by default and exclude authors/committers. The UI distinguishes an issue failure from a case where only a team approval remains. Authorized users can record a reasoned per-scan merge override; it is shown and audited as an override, not a passed gate.

Workspace and Enterprise also provide a PR Review brief in the dashboard and GitHub Markdown output. It prioritizes findings on changed lines under **Read these first**, identifies blockers and owners/authorship, lists lower-confidence observations under **Also flagged**, and marks changed files without findings as **Safe to skim**. That last label describes the stored review evidence rather than proving a file is safe. Sources: [review brief panel](/Users/oha/skylos-cloud/skylos-cloud/src/components/scans/ReviewBriefPanel.tsx:101), [brief construction](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-brief/brief.ts:361).

Sources: [PR list definitions](/Users/oha/skylos-cloud/skylos-cloud/src/lib/pull-requests.ts:1), [approval binding](/Users/oha/skylos-cloud/skylos-cloud/src/lib/pull-requests.ts:242), [approval enforcement](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-policy/approvals.ts:1), [override API](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/override/route.ts:1).

### Policy management

The Policy page has five implemented areas: quality gate, agent rules, agent guardrails, custom rules, and policy history.

| Policy feature | Implemented controls |
|---|---|
| Workspace default and project custom policy | Projects inherit by default or save their own policy. The UI shows which repositories inherit and how custom policies differ. |
| Quality gate | Enable/disable; zero-new, category, severity, or combined thresholds; security, secret, quality, dead-code, and dependency buckets; optional always-block-exposed-secrets control. |
| Analysis settings | Enable security/secrets/quality/dead code, excluded paths, complexity/nesting/function length/argument thresholds, AI review instructions, required route guards, and legacy AI assurance. |
| Presets | Draft starting points populate the editor; review and explicit save are required before they take effect. |
| Impact preview | Re-evaluates the same gate evaluator against latest complete stored scans before saving, showing newly failing/passing, unchanged, and not evaluated repositories. It does not rerun analysis or retroactively discover findings under new thresholds. |
| Stricter-only inheritance | Owners/admins can prevent custom repository policies being saved looser than the default. Existing looser projects are listed; turning it on does not rewrite their policies. |
| Fix deadlines | Optional per-severity deadlines derived from issue first-seen time, with due/overdue states and queue filters. |
| History | Immutable saved versions show actor/time/reason, changes, fingerprint chain, project/default scope, and scans using each version. Date lookup shows the version at end of the selected UTC day. |
| Scan policy receipt | Every evaluated result can preserve the exact effective analysis policy, plan capabilities, inheritance mode, baseline, suppressions, evaluation time, commit, and hashes. It explicitly marks scanner execution against that policy as not attested. |

Sources: [policy sections](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/policy/PolicySections.tsx:28), [analysis/gate config](/Users/oha/skylos-cloud/skylos-cloud/src/lib/policy-config.ts:10), [presets](/Users/oha/skylos-cloud/skylos-cloud/src/lib/policy-presets.ts:1), [impact behavior](/Users/oha/skylos-cloud/skylos-cloud/src/lib/policy-impact-core.ts:5), [stricter-only UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/policy/StricterOnlySection.tsx:17), [deadline model](/Users/oha/skylos-cloud/skylos-cloud/src/lib/issue-sla.ts:1), [history](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/policy/PolicyHistorySection.tsx:81), [policy receipt](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scan-policy-receipt.ts:1).

#### Custom rules and required security controls

Custom rules support pattern configuration stored as JSON (internally the `yaml` rule type) and Python rule code, with plan-specific eligibility. Rule ID/name/description/severity/category, enabled state, and deletion are implemented. Templates cover required auth decorators, dynamic raw SQL, and service inheritance. Connected CLI scans can sync these rules; the cloud does not execute arbitrary Python rule code inside the web server.

The security control registry imports observed auth, authorization, tenant isolation, validation, rate limit, CSRF, webhook signature, middleware, audit logging, and security header controls with route/guard/last-seen evidence. The UI can filter controls and show active/missing/required state. Promotion of an observed control into a requirement is specifically limited to concrete active FastAPI dependency observations and a reviewed custom project policy. Broader imported control kinds are not all promotable.

Sources: [custom rule UI/templates](/Users/oha/skylos-cloud/skylos-cloud/src/components/rules/CreateRuleModal.tsx:13), [rule actions](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/rules/actions.ts:1), [control import types](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/control-registry/import/route.ts:15), [control UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/controls/page.tsx:195), [promotion restrictions](/Users/oha/skylos-cloud/skylos-cloud/src/lib/control-protection.ts:37).

### AI agent policy guardrails and done checks

These are three related implemented capabilities with distinct responsibilities.

1. **Agent merge rules:** Select a minimum severity that blocks an agent-authored change; choose block/warn/off for seven rule-backed signals; require a named team's approval for changes in protected paths. Signals are weakened tests, removed security controls, invented packages, undeclared packages, suspicious version bumps, wider CI permissions, and nonexistent code references. The cloud consumes scanner results for those signals; it does not redetect them.
2. **Cloud policy for local hook guardrails:** Cloud provides a policy editor, sync endpoint, device coverage and event ingestion for compatible CLI clients. Policy fields cover secrets in edits, nonexistent packages/versions, typosquats, security severity and protected paths; owners/admins can control local loosening and event reporting. The CLI source declares 4.50.1 and has native local hooks but does not implement the `agent guardrails` command or a consumer for these Cloud guardrail endpoints. Saving this Cloud policy therefore does not establish enforcement on that CLI. Check compatibility and actual device/version coverage before rollout. The dashboard's rollout commands are not sufficient evidence that the checked-out CLI supports the integration.
3. **Done-check policy:** Configure block/warn/off for tests passing, test tampering, Skylos settings/hook tampering, secrets, imports/dependencies, test special casing, and silenced linters/scanners/CI checks. Configure how often the stop hook can send an agent back before warning. Cloud parses uploaded done receipts and reapplies the workspace settings; it does not independently rerun or verify the test execution represented by an upload.

The agent check report explains each check and suggested remediation, links scan/commit/PR facts, displays unreadable/incomplete/failing/passing outcomes, and can display changed-line test/mutation evidence where provided. The agent activity endpoint/feed can record agent runs and validation receipts. Repeated blocking by the same agent in a project can emit an outbound event after three consecutive blocks.

Sources: [agent merge rule config](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-policy/config.ts:1), [risk signals](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-policy/signals.ts:1), [local guardrail policy](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-guardrails/core.ts:1), [guardrail coverage/event UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agents/guardrails/page.tsx:69), [done policy and trust wording](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-checks/core.ts:1), [check detail UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agent-checks/[scanId]/page.tsx:125), [repeated-block trigger](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-checks/repeated-block-alert.ts:1), [agent runs](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/agent-runs/route.ts:1).

Agent check UI/settings require `SKYLOS_AGENT_CHECKS_ENABLED=true`. This is separate from the saved policy's own enabled state.

### Attribution scorecards review exposure and the agent PR log

The attribution pipeline distinguishes **Named in commit**, derived from commit metadata, from **Edit log (exact lines)**, derived from Git AI/Agent Trace records. It preserves evidence source, scope, recorded lines, model/contributor metadata, and coverage gaps. A PR submitter can be displayed separately because submitting a PR does not establish who wrote its code. Unsupported, missing, conflicting, or wrong-revision records remain unknown.

Project attribution lists files in the latest attributed scan, evidence coverage, named agents, and historical attributed uploads. Agent overview and scorecard compare agents across repositories, owner teams, periods and weeks. The scorecard links counts to their underlying findings/scans/PRs: issues on recorded lines, failed gates, risk signals, agent-named commits, edit-log coverage, and PR outcomes. It keeps commit-name evidence separate from line evidence and unknown authorship.

Review exposure is a separate GitHub-backed view of merged PR review patterns. It aggregates by code area and shows merged changes, agent-named commit share, distinct approvers, one-person approvals, unapproved changes, median approval timing, and large changes approved within ten minutes. Flags indicate areas dependent on one reviewer or mostly agent-named changes approved quickly. The code describes these as review exposure; timing is not a measurement of reviewer understanding. It has 30/90/180-day windows and an explicit 90-day backfill operation. This entire feature is hidden unless `SKYLOS_REVIEW_EXPOSURE_ENABLED=true`.

The agent PR log preserves each qualifying CI upload's PR/commit, agent/model/prompt hash where supplied, uploader/workflow identity, reviewers, touched files, control changes, gate result, risk and chained evidence hashes. These are stored evidence records; a hash chain does not independently prove the truth of client-submitted agent/test facts.

Sources: [attribution presentation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/provenance-evidence-display.ts:1), [line record validation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-attribution-evidence.ts:1), [project attribution](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/provenance/page.tsx:100), [scorecard](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agents/scorecard/page.tsx:184), [agent overview](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agents/page.tsx:235), [review exposure definitions/flag](/Users/oha/skylos-cloud/skylos-cloud/src/lib/review-exposure/core.ts:1), [ledger](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/ledger/page.tsx:173), [ledger writes](/Users/oha/skylos-cloud/skylos-cloud/src/lib/ai-sdlc-ledger.ts:154).

### Not fixing suppressions risk acceptance and overrides

The Not fixing area brings together pending review requests, false positives, temporarily accepted risks, merge overrides, and ended decisions. Users can inspect scope, reasoning, requester/reviewer, expiry, recorded evidence snapshots, and decision/event history; filter/search decisions; and export evidence. Project suppression pages show decisions and allow revocation.

Risk acceptance on governed plans requires a justification, future expiry, current finding snapshot, and a different authorized reviewer. Reviewers approve/reject and can revoke an approval. Until approval the issue remains open. Expiry/revocation reactivates the issue for gate evaluation; scheduled jobs handle expiry and notifications. High risk findings route through reviewed per-project exceptions rather than broad suppression rules.

Organization triage rules can mark an exact rule plus fingerprint, symbol/language, restricted path glob, or exact message as not a problem in every repository. The UI previews affected groups and records who/why/expiry/revocation. Limits are 500 active rules and at most 500 affected open issue groups when creating a rule. Rules cannot hide secrets, high/critical security/dependency findings, or findings with malformed/missing labels. Current matching uses exact stable identities and bounded globs rather than arbitrary user SQL or code.

Sources: [decision model](/Users/oha/skylos-cloud/skylos-cloud/src/lib/exception-requests.ts:12), [request requirements](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/exception-requests/route.ts:28), [approval/revocation/expiry operations](/Users/oha/skylos-cloud/skylos-cloud/src/lib/exception-governance.ts:46), [decision detail UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/exceptions/[id]/page.tsx:122), [organization triage semantics](/Users/oha/skylos-cloud/skylos-cloud/src/lib/org-triage-core.ts:1), [expiry alert consequence](/Users/oha/skylos-cloud/skylos-cloud/src/lib/exception-expiry-alerts-core.ts:147).

### Fix proposals and dead-code cleanup

#### AI fix proposals for findings

An authorized workspace owner/admin can ask for a bounded generated patch based on the exact scanned file, commit and finding. The implementation supports Python and JavaScript/TypeScript variants, validates source syntax and the proposed edit, checks current GitHub state, reserves generation/creation to avoid duplicates, and accounts for credits/refunds. A small eligible change on an existing PR can be posted as a suggestion; default/feature branch findings can produce a separate fix PR. A model can decline to fix or return a likely-false-positive assessment instead.

For ordinary findings, accepted generation is deliberately narrow: one existing simple statement, unchanged bytes elsewhere, at most 12 lines/4 KB changed, without inserted statements or imports elsewhere. The generator has a separate dead-code deletion mode. This is narrower than claiming automatic repair of arbitrary security problems.

Fix results track the PR head, observed GitHub checks, merge state, and later matching scan observations: waiting, still reported, no longer reported, inconclusive, or unavailable. The code explicitly keeps coverage unverified and treats absence from a stored scan as an observation rather than a declaration that a patch is safe to merge.

Sources: [generator limits/prompts](/Users/oha/skylos-cloud/skylos-cloud/src/lib/fix-generator.ts:18), [supported syntax](/Users/oha/skylos-cloud/skylos-cloud/src/lib/fix-proposal-validation.ts:23), [fix request lifecycle](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/findings/[id]/fix/route.ts:124), [target selection](/Users/oha/skylos-cloud/skylos-cloud/src/lib/fix-target.ts:1), [result evidence](/Users/oha/skylos-cloud/skylos-cloud/src/lib/fix-results.ts:1).

#### Manual cleanup cycle

Dead-code cleanup has a dedicated five-step flow: select a complete source scan, review one eligible unused item, open a small cleanup PR, confirm the resulting code with a re-scan, and enable policy to block new dead code. It tracks open, closed-unmerged, merged-waiting-scan, ready-to-prevent, complete and abandoned states. Manual candidate rules include unused functions, imports, variables, and classes (`SKY-U001`–`SKY-U004`), subject to evidence and source validation. The source scan remains fixed throughout the cycle.

Source: [manual workflow](/Users/oha/skylos-cloud/skylos-cloud/src/components/CleanupWorkflow.tsx:527), [candidate/rule contract](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cleanup-flow.ts:1), [prevention policy endpoint](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/cleanup-prevention/route.ts:1).

#### Optional scheduled weekly cleanup PRs

A separate opt-in scheduler selects safe unused Python functions/methods only (`SKY-U001`) from a trusted default branch scan and deletes exact validated definition ranges without LLM generation. It proposes at most ten symbols in five files, avoids stale/changed/conflicting files, tests/entry points/generated/vendor files and suppressed/disputed/accepted-risk findings, and protects published library APIs by selecting private names. It does not reopen previously proposed/kept symbols. One cleanup PR can be open at a time, with roughly weekly spacing; two consecutive closed-unmerged PRs pause the feature. The UI shows state/history, merge rate, and lines removed. Creation consumes the configured fix-PR credit price.

Feature kill switches include `SKYLOS_CLEANUP_PRS_DISABLED` and `SKYLOS_FIX_PR_CREATION_ENABLED=false`.

Sources: [scheduled cleanup algorithm](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cleanup-prs/core.ts:1), [candidate restrictions/limits](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cleanup-prs/selection.ts:1), [kill switches and statistics](/Users/oha/skylos-cloud/skylos-cloud/src/lib/cleanup-prs/shared.ts:1), [project cleanup controls](/Users/oha/skylos-cloud/skylos-cloud/src/components/project-overview/CleanupPrsSection.tsx:1).

### AI deep scans of a repository

Deep scans use the VulnHunter worker for an AI security review of a connected GitHub repository. Users select an available repository and start a run; job pages show progress, run history, commit/model, timing, API cost, verdicts, findings and ruled-out leads. Finding reports can include how an attacker enters, the path through code, reached assets, missing invariants, impact, code evidence, verification steps, uncertainty, and review reasoning.

This is separate from the ordinary offline Cloud scanner. Local configuration uses the workspace's own encrypted/validated Anthropic API key and model `claude-sonnet-5-5`, with a $3 own-API-credit cap per run and a 1,500-second scan time budget. Vercel Sandbox clones the exact repository revision, then grants narrowly configured API/result delivery network access. It can report progress asynchronously. Per-day local caps are Free 2, Workspace 20, Enterprise 100; default concurrent scans are two; at most 200 findings/2 MB results are accepted.

Availability requires a configured `VULNHUNTER_SANDBOX_SNAPSHOT_ID`, an enabled feature, and usable workspace key/encryption configuration. A configured plan capability alone does not establish that a live deep scan can run.

Sources: [deep scan configuration](/Users/oha/skylos-cloud/skylos-cloud/src/lib/vulnhunter/config.ts:1), [repository/history UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/deep-scans/page.tsx:1), [finding story UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/deep-scans/[id]/page.tsx:92), [worker result contract](/Users/oha/skylos-cloud/skylos-cloud/src/lib/vulnhunter/core.ts:331), [key validation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/vulnhunter/server.ts:73), [sandbox](/Users/oha/skylos-cloud/skylos-cloud/src/lib/vulnhunter/sandbox.ts:1).

### Technical debt and AI feature safeguards

Technical debt report pages store/display the CLI's debt score, risk rating, dimensions, hotspot counts, trend, hardest-to-change files, priority score, changed/baseline state, score delta, supporting signals, and advisory data. The UI reports stored sample limits and omitted hotspots. Each scan has its own immutable debt result page as well as project history. Default upload limits retain 50 hotspots, five signals each, and a 25-file changed sample.

AI feature safeguard reports consume defense scan uploads. They display integration/file counts, weighted defense score and risk rating, severity breakdown, historical score, OWASP LLM Top 10 safeguard coverage, missing and present safeguards, ops checks, and scan fingerprint/attestation metadata. They cover the safety controls found in AI application features, independently from attribution of code written by coding agents.

Sources: [debt normalization/limits](/Users/oha/skylos-cloud/skylos-cloud/src/lib/debt.ts:1), [debt UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/debt/DebtClientPage.tsx:228), [defense normalization](/Users/oha/skylos-cloud/skylos-cloud/src/lib/defense-normalization.ts:1), [defense UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/defense/DefenseClientPage.tsx:294).

### Audit reports and compliance evidence

The Audit reports hub links change history, AI-agent-only change evidence, framework reports, audit log, access review, policy history and agent scorecard.

Rule-mapped evidence reports support OWASP Top 10 2025, CWE Top 25 2025, PCI DSS 4.0.1, SOC 2 (2017 TSC with 2022 points of focus), HIPAA Security Rule (45 CFR 164.312), and ISO/IEC 27001:2022. Mappings are generated from the CLI rule catalog's CWEs; the OWASP mapping has an explicit documented fallback for declared 2021 categories. Unmapped rules retain a no-standard-applies reason. GDPR and NIST CSF can appear as active framework cards but have no supported report mapping and offer no paid generation action.

Code reports select the newest complete native Skylos code scan per project across the workspace, excluding diff, defense, and debt scans. This selection does not filter to trusted uploads or the default branch, so confirm each project's branch, commit, and source before using the report as evidence. The current mapped requirement evaluator never infers a pass from absent findings: observed mapped findings produce **Finding observed** (`failed`), while other mapped requirements remain **Not evaluated**. Suppressed findings stay in the report and retain their suppression state; accepting a risk does not turn its mapped requirement into a verified pass. Evidence coverage describes evaluated requirements within the implemented mapping, not full-framework compliance or code coverage. These are evidence reports, not certification or a determination of compliance.

AI governance reports additionally support EU AI Act (Regulation (EU) 2024/1689), NIST AI RMF 1.0, and ISO/IEC 42001:2023 using CLI defense-attested outcomes and server-owned mappings. Their passing aggregation covers projects with recognized framework evidence; projects without such evidence do not establish organization-wide coverage. A passing result requires all expected recognized checks to be supplied exactly once with valid passing outcomes across that scope. Reports distinguish CLI assertions from independent verification and list controls/obligations outside the scan's scope.

Generating a report stores a point-in-time artifact with canonical JSON, its SHA-256 fingerprint, framework/date/generator metadata, scope notices, and history. HTML and CSV show requirement-level statuses, counts, and evidence notes; detailed per-rule finding records, locations, messages, and suppression states are in JSON. History downloads reuse the saved report data without a new generation charge; they do not pull newer scan results. The fingerprint applies to the original canonical JSON bytes, not the HTML, CSV, or printed PDF. Generation preserves request idempotency, and credit deduction, artifact insertion, and request completion commit in one database transaction. Compliance artifacts are excluded from ordinary scan age retention; this is not a promise of retention after workspace deletion.

Change-history evidence exports CSV or printable HTML over an inclusive UTC date range (default 90 days; maximum 366). The full scope covers recorded pull-request scans; the narrower scope covers scanned changes with recognized agent evidence and offers a project filter. Rows include repository, PR, commit, uploader identity and trust, findings, gate conditions/override state, protected path approvals, and accepted risks in force. Owners and admins can export on an eligible plan, and each export is audited. Bounds include 5,000 scans/5,000 exception records, with separate approval limits. These are scan and Skylos decision records; they do not establish unrecorded changes, merges, deployments, or ordinary GitHub/GitLab pull-request reviews.

The **Download not-fixing decisions (CSV)** action exports formal `policy_exception_requests`, their linked suppressions, requester/reviewer identities, justifications, review reasons, expiry, and decision events. The adjacent accepted-risk counters also count formal exception requests. Direct false positive/risk suppressions, gate overrides, and organization triage rules are outside this CSV and require their own decision and audit records when preparing a complete evidence pack.

Audit log and access review provide separate operational records. Access review includes members, invitations, roles, inactive/last-seen context, admin-managed keys, and uploads not tied to a member, with revocation/removal actions subject to permissions.

Sources: [evidence hub](/Users/oha/skylos-cloud/skylos-cloud/src/lib/evidence-hub.ts:1), [framework mapping and editions](/Users/oha/skylos-cloud/skylos-cloud/src/lib/compliance/mappings.ts:1), [requirement evaluation](/Users/oha/skylos-cloud/skylos-cloud/src/lib/compliance/report-generator.ts:143), [exact code scan selection](/Users/oha/skylos-cloud/skylos-cloud/supabase/migrations/20260923203000_compliance_code_scan_family.sql:1), [AI governance contract](/Users/oha/skylos-cloud/skylos-cloud/src/lib/compliance/ai-governance.ts:11), [server-owned AI controls](/Users/oha/skylos-cloud/skylos-cloud/src/lib/compliance/ai-governance-catalog.ts:1), [artifact generation API](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/compliance/report/route.ts:20), [stored artifact downloads](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/compliance/reports/[id]/route.ts:1), [readable report fields](/Users/oha/skylos-cloud/skylos-cloud/src/lib/compliance/render.ts:1), [change evidence fields and limits](/Users/oha/skylos-cloud/skylos-cloud/src/lib/agent-change-evidence.ts:1), [formal exception CSV](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/exception-requests/export/route.ts:1), [formal request selection](/Users/oha/skylos-cloud/skylos-cloud/src/lib/exception-requests.ts:95), [retention scope](/Users/oha/skylos-cloud/skylos-cloud/src/components/settings/RetentionSection.tsx:116), [access review](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/access-review/page.tsx:647), [audit log](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/activity/page.tsx:1).

### Investigator

The project Investigate view is a deterministic evidence explorer built over authorized Cloud records. It supports five fixed queries: open critical/high issue groups, a scan receipt, scan-count comparison, selected finding context by same rule/file, and a stored entity's neighborhood. It does not offer arbitrary database queries or LLM conversation.

Results include summary, metrics, scans/findings/issues, citations into the dashboard, trust/gate/coverage warnings, and a relationship graph. Six node kinds are project, scan, issue, finding, file and rule. Users can switch graph/list, select a node, inspect properties and recorded source fields, follow adjacent nodes, open the original record, or focus a new neighborhood. Depth is one to three connections. Issue/finding occurrence history has exact authorized totals and cursor pagination. The evidence schema panel documents entity identity, fields and relationship provenance.

The backend enforces workspace/project scope, read permission, validated query types, deadlines, body/response caps, row limits and graph caps. Query limits are 1–50 records; graphs cap at 150 nodes/250 relationships; the SVG renders 60 returned nodes while the list can show all returned nodes. Stored relationships do not establish execution paths, causality or exploitability, and count comparison is not equivalent to resolved-finding matching.

The entire feature is present in the current untracked code/tests and is on unless `SKYLOS_INVESTIGATOR_ENABLED=0`. No separate paid-plan check appears in its endpoint; it requires `view:findings`. Deployment remains unverified.

Sources: [query contracts](/Users/oha/skylos-cloud/skylos-cloud/src/lib/investigator/types.ts:1), [query validation and result construction](/Users/oha/skylos-cloud/skylos-cloud/src/lib/investigator/core.ts:1), [page](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/investigate/page.tsx:1), [read API](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/investigate/route.ts:1), [interactive graph](/Users/oha/skylos-cloud/skylos-cloud/src/components/investigator/EvidenceExplorer.tsx:36), [schema panel](/Users/oha/skylos-cloud/skylos-cloud/src/components/investigator/OntologySchemaPanel.tsx:1), [flag](/Users/oha/skylos-cloud/skylos-cloud/src/lib/investigator/config.ts:1).

### Scanner Proof and shadow comparison

Scanner proof compares an uploaded incumbent scanner report against a Skylos report on a user's own code. It retains external tool/version/format/revisions, categories/severities, location overlap, external-only/Skylos-only findings, and reachability context for findings in likely dead code. Results include input digest/integrity state, coverage/scope/revision checks, provisional versus verified evidence, and links to findings. The UI does not treat unique finding counts as proof that another tool missed issues; likely dead code remains a review/deletion candidate. It is hidden unless `SCANNER_PROOF_ENABLED=1` and also has plan eligibility.

Sources: [flag](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scanner-proof-config.ts:1), [receipt and comparison model](/Users/oha/skylos-cloud/skylos-cloud/src/lib/shadow-comparison.ts:1), [proof page](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/scanner-proof/page.tsx:195), [upload API](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/shadow/reports/route.ts:1).

### Integrations and notifications

| Integration | Implemented capability and practical boundary |
|---|---|
| GitHub | App installation/repository binding, org inventory, default branch coverage, OIDC uploads, check runs and gate status, PR summary/comment and inline evidence publishing, workflow setup PRs, protected-path approval verification, fix suggestions/PRs, cleanup PRs, PR review exposure, health/retry. Each write path has its own configuration/permission checks. |
| GitLab | GitLab.com project connection verification and encrypted token storage, GitLab CI OIDC identity, diff-aware MR inline discussions, stable comment updates and conservative resolution of owned unreplied discussions after complete scans. The code binds the head/diff and does not infer that arbitrary self-hosted GitLab is supported. |
| Bitbucket Cloud | Connection/test/disconnect, verified current same-repository PR delivery, commit build status, Code Insights report, bounded annotations when eligible, and an updated summary comment. Fork PR delivery is rejected. |
| Azure DevOps | Connection/test/disconnect, current active PR/head or valid merge-commit checks, PR status for branch policy, and a single summary thread updated on later scans. This provider has no Bitbucket-style annotation surface in the delivery code. |
| Jira Cloud | Workspace connection/test using classic or scoped Atlassian API tokens, project/issue type discovery, create-screen checks, explicit ticket creation from a recurring issue, duplicate protection, stored ticket links, status refresh, and permission-aware UI. Skylos rescan resolution does not silently close the Jira ticket. |
| Slack | Per-project webhook setup/test and gate-result notifications with summary/counts and dashboard links. |
| Discord | Per-project webhook setup/test and gate notifications. |
| Outbound workspace webhooks | Up to ten endpoints, selectable event subscriptions, HMAC-SHA256 signing secret shown at creation, test event, enabled state, delivery/result status. Events: scan completed, gate failed, exception requested/approved/rejected/revoked, and agent repeatedly blocked. Payloads exclude code/snippets/finding messages/secrets. |
| Weekly digest | Workspace enable/disable, member subscription and unsubscribe, preview email, weekly issue/gate/fix/expiry/stale-scan/agent-check summaries; email and paid-plan chat channels. Current schedule is Monday 00:30 UTC for the previous ISO week. |
| Exception expiry alerts | Scheduled warning/expiry notifications to relevant users and configured channels, with the consequence that the finding counts toward the gate again. |
| Lifecycle email | Implemented onboarding/activation email jobs and unsubscribe flow, using actual workspace/setup facts. |

Sources: [GitHub App integration](/Users/oha/skylos-cloud/skylos-cloud/src/lib/github-app.ts:1), [GitHub check publication](/Users/oha/skylos-cloud/skylos-cloud/src/lib/github-gate-delivery.ts:1), [GitLab project binding](/Users/oha/skylos-cloud/skylos-cloud/src/lib/gitlab/connections.ts:1), [GitLab review planner](/Users/oha/skylos-cloud/skylos-cloud/src/lib/gitlab/planner.ts:1), [GitLab publishing](/Users/oha/skylos-cloud/skylos-cloud/src/lib/gitlab/publisher.ts:1), [Bitbucket delivery](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scm/bitbucket/delivery.ts:1), [Azure delivery](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scm/azure-devops/delivery.ts:1), [Jira protocol and ticket content](/Users/oha/skylos-cloud/skylos-cloud/src/lib/jira/core.ts:1), [Jira issue panel](/Users/oha/skylos-cloud/skylos-cloud/src/components/issues/JiraLinkPanel.tsx:1), [Slack](/Users/oha/skylos-cloud/skylos-cloud/src/lib/slack.ts:148), [Discord](/Users/oha/skylos-cloud/skylos-cloud/src/lib/discord.ts:1), [webhook signing/payload](/Users/oha/skylos-cloud/skylos-cloud/src/lib/webhooks/core.ts:1), [webhook events](/Users/oha/skylos-cloud/skylos-cloud/src/lib/webhooks/events.ts:1), [digest definition](/Users/oha/skylos-cloud/skylos-cloud/src/lib/weekly-digest/core.ts:1), [digest preview](/Users/oha/skylos-cloud/skylos-cloud/src/lib/weekly-digest/job.ts:304), [expiry notices](/Users/oha/skylos-cloud/skylos-cloud/src/lib/exception-expiry-alerts-core.ts:140), [lifecycle jobs](/Users/oha/skylos-cloud/skylos-cloud/src/lib/lifecycle-email/job.ts:1).

### Workspace settings surfaces

The implemented settings UI includes workspace selection/creation, plan/balance/history, invitations and member role changes/removal, team management, GitHub installation/inventory, webhooks, Jira, deep-scan API keys, weekly digest, SSO, scoped API tokens, default policy, retention, and scheduled workspace deletion. Project settings add repository/subpath connection, inherited/custom policy, owner team, named project keys with rotation/revocation/CI trust/last-used history, notification endpoints, GitLab, Bitbucket, Azure DevOps, and cleanup options.

Retention settings have plan-specific choices, a 30-day minimum, daily deletion, and protection for each project's newest scan. Workspace deletion uses a typed-name request and grace period with cancellation, scheduled cleanup, key/token invalidation when deletion begins, and owner email notifications.

Sources: [workspace settings](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/settings/page.tsx:1), [project settings](/Users/oha/skylos-cloud/skylos-cloud/src/components/settings/ProjectSettingsSurface.tsx:1), [key management UI](/Users/oha/skylos-cloud/skylos-cloud/src/components/settings/ApiKeySection.tsx:19), [retention/deletion model](/Users/oha/skylos-cloud/skylos-cloud/src/lib/retention/core.ts:1).

### Public repository preview

The public `/scan` page accepts a public GitHub repository URL without requiring an account. It scans the latest default-branch commit and streams preparing, cloning, isolating, analyzing and finalizing progress before presenting the result. Findings can be searched and reviewed with category/severity, locations and available evidence. The preview result is returned to the current tab rather than saved as a Cloud project or shared report.

The preview uses a separate fixed-policy sandbox worker pinned locally to CLI 4.37.0. It enables dead code, security, secrets, quality and AI-defect analysis without running repository tests, tracing, install scripts or repository-controlled Skylos configuration. It excludes private repositories, custom branch/PR selection, SCA lookups, persistent history and workspace policy gates.

Its local bounds are a 100 MiB clone transfer, 50 MiB checked-out tree, 5,000 files, 5 MiB per file, 25-second clone, 55-second analysis and 105-second isolated session. The server enforces request/rate/concurrency limits and reports capacity errors. These constraints make it a bounded preview of supported source, not evidence of full current CLI feature coverage.

Sources: [public scan page](/Users/oha/skylos-cloud/skylos-cloud/src/app/(public)/scan/page.tsx), [result UI](/Users/oha/skylos-cloud/skylos-cloud/src/app/(public)/scan/ScanResults.tsx), [request endpoint](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scan/route.ts), [protocol and limits](/Users/oha/skylos-cloud/skylos-cloud/src/lib/public-scan-protocol.ts), [worker](/Users/oha/skylos-cloud/skylos-cloud/services/public-scan-worker/worker.py).

### Public repository examples and shared reports

`/judge` is an experimental gallery of pinned public repository examples. Repository scorecards retain repository/branch/commit, scanner timestamp, findings, assessment or explicitly labeled legacy grade, coverage and optional AI review context. The implementation includes repository suggestions and protected operator import/seed surfaces. A public example is a stored sample result; it does not continuously assess the repository's current head.

Shared scan reports at `/scan/{token}` are a separate publishing workflow: an authorized workspace administrator deliberately creates a read-only link for an existing scan and can revoke it. Their public presentation follows scan-sharing policy rather than exposing the private dashboard.

Sources: [example gallery](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/judge/page.tsx), [repository scorecard](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/judge/[owner]/[repo]/page.tsx), [Judge data](/Users/oha/skylos-cloud/skylos-cloud/src/lib/judge.ts), [report sharing policy](/Users/oha/skylos-cloud/skylos-cloud/src/lib/scan-share-policy.ts), [shared report](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/scan/[token]/page.tsx).

### Guides and public service information

The public site includes the product homepage, pricing, Workspace plan description, VS Code page, tokenless CI guide, security/trust pages, roadmap, documentation entry points, privacy, terms and cookies. The homepage includes copyable install/check commands and a recorded finding/fix walkthrough; its examples are saved outputs rather than an analysis run in the browser.

MDX collections power the research blog, comparison guides and use-case guides. The content system supports article type/topic/tag metadata, related articles, reading time, article navigation and structured metadata. Discovery routes include RSS at `/blog/feed.xml`, sitemap and robots files, plus `/llms.txt` and `/llms-full.txt` inventories for automated readers. The roadmap distinguishes availability states; planned entries are not counted here as implemented features.

The public status page and `/api/health` expose endpoint status. The live page explicitly says that this does not test sign-in, scans or connected dependencies and does not constitute an incident history or service-level guarantee.

Sources: [public application pages](/Users/oha/skylos-cloud/skylos-cloud/src/app/(public)), [content model](/Users/oha/skylos-cloud/skylos-cloud/src/lib/content.ts), [blog discovery](/Users/oha/skylos-cloud/skylos-cloud/src/lib/blog.ts), [RSS](/Users/oha/skylos-cloud/skylos-cloud/src/app/(public)/blog/feed.xml/route.ts), [AI-facing inventory](/Users/oha/skylos-cloud/skylos-cloud/src/lib/llms.ts), [status](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/status/page.tsx), [health](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/health/route.ts).

## Cloud plans and action costs

Cloud has three plan identifiers: `free`, `pro`, and `enterprise`. The user-facing name for `pro` is **Workspace**. The following matrix describes the inspected checkout. Live purchase terms differ, as recorded under **Live site differences and verification**.

| Capability | Free | Workspace | Enterprise |
| --- | --- | --- | --- |
| Projects | 1 | 10 | 9,999 |
| Stored scans per project | 10 | 500 | 10,000 |
| Project API request allowance | 20/hour | 500/hour | 5,000/hour |
| GitHub PR diff analysis and check runs | Yes | Yes | Yes |
| Finding suppressions | Up to 25/project | Up to 999,999/project | Up to 999,999/project |
| Custom rules | 3 | 50 | 999,999 |
| Failed gate overrides | No | Yes | Yes |
| Advanced gate modes and inline PR comments | No | Yes | Yes |
| Invitations issue comments and assignments; paid integrations | No | Yes | Yes |
| Compliance and suppression governance | No | Yes | Yes |
| Trends | Seven days | Across retained scans | Across retained scans |
| CSV and JSON exports; SARIF entitlement | No | Yes | Yes |
| Detailed provenance | No | Yes | Yes |
| Provenance audit export | No | No | Yes |
| Agent PR review brief and organization triage rules | No | Yes | Yes |
| Hosted Cloud scans per rolling 24 hours | 5 | 50 | 250 |
| VulnHunter deep scans per rolling 24 hours | 2 | 20 | 100 |

The large limits above are finite constants, including Enterprise's project and scan caps. The public read API has its own per-token rate limit; the hourly project API allowance must not be used to describe that API.

Team creation, membership, aliases and ownership mapping have their own role checks and are not gated by this collaboration capability in the inspected Teams routes. Paid collaboration specifically gates invitations, issue comments and assignments; the table does not imply that Free has no team ownership data or GitHub repository integration.

Source: Cloud `src/lib/entitlements.ts`, `src/lib/plan-names.ts`, `src/lib/cloud-scan-config.ts`, and `src/lib/vulnhunter/config.ts`.

### Credits and billing

Static CLI scans require no account or Cloud credits. Cloud uploads, ordinary hosted Cloud scans, PR checks, and the merge gate do not consume credits. MCP scan tools run locally without a credit charge; authenticated access requirements still apply.

| Cloud action | Standard displayed cost in the checkout | Additional condition |
| --- | --- | --- |
| Compare two scans | 2 credits | Workspace or Enterprise |
| Create an AI fix PR | 3 credits | Workspace or Enterprise; explicit creation action and repository access |
| AI issue triage | 5 credits | Workspace or Enterprise |
| MCP remediation | 10 credits | Authenticated local MCP workflow |
| Generate a compliance report | 500 credits | Compliance entitlement |
| VulnHunter deep scan | Workspace's own Anthropic API usage in this checkout | Configured worker snapshot and workspace API key; see live difference below |

Enabled costs are read from the database's `feature_credit_costs` table when charging. Enterprise bypasses prepaid deductions in the local code. A shared permission check restricts credit spending; failures may trigger a refund associated with the original operation. AI fix creation additionally retains request receipts so a replay or ambiguous attempt does not automatically create another PR or charge.

The local credit packs are Starter (50 credits, US$9), Builder (250, US$39), Team (1,000, US$129), and Scale (5,000, US$499). Checkout uses Lemon Squeezy, validates the configured product and price, limits checkout-link lifetime, tracks payment confirmation against the actual workspace, and records purchase/refund history. Only owners can manage billing. A paused or unconfigured checkout is represented in the UI.

The inspected purchase code describes a permanent Workspace unlock after a credit purchase. Its initial workspace offer is a seven-day trial plus 50 credits, once per account; later workspaces start Free. These local terms do **not** match the live public pricing page on 16 October 2026.

Source: Cloud `src/lib/payments.ts`, `src/lib/credits.ts`, `src/lib/require-credits.ts`, `src/lib/public-product.ts`, `src/app/api/billing/`, `src/app/api/credits/`, and `src/app/(request)/dashboard/billing/`.

## Cloud accounts and administration

### Sign in and workspace selection

GitHub sign-in is the default. The provider implementation can also enable GitLab, Google, email magic links, and SAML SSO through `NEXT_PUBLIC_AUTH_PROVIDERS` and the corresponding Supabase configuration. GitHub sign-in requests profile/email access; repository access is granted separately through the GitHub App connection.

Users can create and switch workspaces, select an active workspace, accept or decline invitations, and connect the CLI to a project through the browser flow. Active workspace membership determines access to dashboard records and session routes. A project binds a repository URL and optional repository subpath, allowing multiple separately analyzed projects within a monorepo.

### Roles and permissions

| Role | Actions provided by the shared permission matrix |
| --- | --- |
| Viewer | Read projects, scans, findings, trends, compliance, activity, and members, subject to the plan |
| Member | Viewer actions; create/edit projects, suppress findings, request exceptions, assign/comment on issues, create scans, spend credits, and connect their CLI |
| Admin | Member actions; delete/share, manage settings/integrations/rules/members, rotate keys, override gates, review exceptions, manage organization API tokens, and bulk delete |
| Owner | Admin actions; manage billing and the organization |

Capabilities and permissions are separate checks: permission to view compliance does not itself grant the compliance plan entitlement. Read-only screens can be accessible to viewers while write controls remain unavailable.

Source: Cloud `src/lib/permission-matrix.ts`, `src/lib/permissions.ts`, `src/lib/active-org-core.ts`, and `src/lib/auth-providers.ts`.

### Identity controls

Account settings support authenticator-based two-factor enrollment, challenge, and removal. Owners can require MFA for their workspace. SAML SSO supports owner-managed provider binding, provider/domain verification, required SSO sessions, and optional membership provisioning from an authorized SSO sign-in. An owner recovery path is retained. Enabling SSO requires a provisioned Supabase provider; a visible setting alone does not provision an identity provider.

Session policy applies to browser sessions. Project API keys, CI OIDC tokens, and organization API tokens have their own issuance, scopes, and revocation. The shared server code logs unreadable SSO/MFA policy and permits the request in that error case, while the database has additional enforcement for core records. This implementation should not be described as universally failing closed.

Invitations and membership controls include role changes, revocation/removal, resend and acceptance flows, allowed email-domain rules, blocked-domain rules, and invitation expiry where configured. Teams, repository ownership and CODEOWNERS mappings supplement organization roles.

Source: Cloud `src/app/(request)/dashboard/account/`, `src/app/api/sso/`, `src/lib/session-policy.ts`, `src/lib/session-policy-server.ts`, `src/lib/team-invitations.ts`, and `src/lib/invite-domain-controls.ts`.

### Project credentials and upload trust

Projects have a rotatable primary API key and registered secondary keys. Secondary keys can be named and revoked, and usage is visible. The local constant allows ten active secondary keys. Browser CLI connection mints a user-attributed CLI key; owners/admins separately designate eligible keys for trusted CI use.

| Upload identity | Stored trust label | Cloud consequence |
| --- | --- | --- |
| Accepted GitHub or GitLab OIDC identity | `verified_ci` | Eligible for trusted checks, baselines, issue resolution, and signed verdicts |
| API key explicitly trusted for CI | `trusted_api_key` | Eligible for trusted outcomes, with the identity limits of a shared secret |
| Browser CLI key or other untrusted project key | `unverified` | Stored for review; cannot supply a trusted pass, resolve issues, set a trusted baseline, or receive a signed verdict |

GitHub OIDC validation constrains upload event and workflow identity. The accepted GitHub paths include default-branch push and the pinned `pull_request_target` workflow; an arbitrary PR workflow is not equivalent. GitLab OIDC proves project/job identity, but an MR pipeline can run its own changed CI configuration. The stored identity retains the event so consumers can assess that distinction.

Unverified uploads are labeled in the dashboard and notifications. A public API response reports an unverified passing gate as unknown. History pruning prevents unverified uploads from displacing trusted scan history. CI key trust changes and revocations are logged.

Source: Cloud `src/lib/project-api-keys.ts`, `src/lib/upload-trust.ts`, `src/lib/github-oidc.ts`, `src/lib/gitlab/oidc.ts`, `src/lib/report-findings-storage.ts`, `src/app/api/report/`, and `docs/cloud-authentication.md`.

### Retention and deletion

Owners can retain scans by plan count limit alone or add an age limit. All plans offer 30, 90, 180, or 365 days; Workspace and Enterprise also offer 730 or 1,095 days. The age policy retains the latest scan per project. Scan count caps still apply independently.

Pruning a scan removes its findings and scan details while preserving records designed for longer evidence retention, including policy versions, exception history, audit entries, compliance artifacts, signed verdicts, grouped issues, and scan deletion tombstones. A retained verdict can become historical when its source scan is gone.

Workspace deletion is an owner action requiring the exact workspace name and a recent sign-in. It is scheduled with a default seven-day grace period, during which an owner can cancel. Execution revokes credentials and integrations, deletes data in batches, and leaves a minimal deletion receipt. Other workspaces and the person's login account remain separate. Email notifications depend on configured email delivery.

Source: Cloud `src/lib/retention/core.ts`, `src/lib/retention/server.ts`, `src/app/api/cron/retention/route.ts`, and the retention/deletion migration.

## Cloud public API and signed verdicts

### Read API

The versioned API is a read-only integration surface at `/api/v1`. Its OpenAPI 3.1 schema is public. Owners/admins can issue up to 25 active organization tokens, choose scopes, select a required expiry of 30, 90, or 365 days, and revoke a token immediately. Tokens are shown once and stored as hashes; losing the creator's eligible membership also invalidates access.

| GET endpoint | Required scope | Purpose |
| --- | --- | --- |
| `/api/v1/projects` and `/api/v1/projects/{id}` | `read:projects` | Projects and latest code scan |
| `/api/v1/scans` and `/api/v1/scans/{id}` | `read:scans` | Scan metadata, gate and trust summaries |
| `/api/v1/scans/{id}/findings` | `read:findings` | Findings; snippets require `include_snippets=true` |
| `/api/v1/issues` | `read:issues` | Grouped issue queue |
| `/api/v1/exceptions` | `read:exceptions` | Exception decisions and expiry; paid entitlement |
| `/api/v1/posture` | `read:posture` | Per-project gate, freshness, and risk counts |
| `/api/v1/audit-events` | `read:audit` | Workspace audit events; paid entitlement |
| `/api/v1/verdicts` | `read:findings` | Current and historical signed decisions for a project commit |
| `/api/v1/openapi.json` | None | Machine-readable API definition |

List endpoints use page/limit pagination with exact totals. The normal default is 50 rows, maximum 100; posture has a smaller 25/50 default/maximum. Tokens default to 300 requests per minute, independently of project API hourly quotas. Errors have stable codes and request IDs, and rate-limit headers are returned. All records are scoped to the token's workspace. This API provides no general write operations, webhook management, or per-project restrictions within an organization token.

Source: Cloud `src/lib/public-api/`, `src/app/api/v1/`, and `docs/public-api.md`.

### Signed gate decisions

When signing is configured, Cloud produces an Ed25519-signed DSSE envelope around an in-toto/SLSA verification summary for a trusted, complete code scan. The accompanying summary binds the project, workspace, commit, repository binding, policy hash/version, analyzer version, upload identity, gate decision, and bounded finding summary.

The stored decision distinguishes a policy pass, an admin override, a disabled gate, unknown gate state, and failure. Fetching the current commit verdict can refresh its signature after a relevant decision change, key change, or age threshold. Up to 19 historical records follow the current record. A deleted/pruned source scan can leave historical evidence without a current verifiable decision.

The CLI's `skylos verify-verdict` checks a downloaded bundle and can require the expected commit, expected repository, verified repository identity, maximum age, and a passing policy. An override requires an explicit allowance. Public verification keys can be downloaded; `--keys` supports fully offline verification. A signature attests to the recorded Skylos decision and identity conditions; it does not establish code safety or complete scan coverage.

Source: Cloud `docs/signed-verdicts.md`, `src/lib/check-verdict.ts`, `src/lib/check-verdict-server.ts`, and CLI `skylos/commands/verify_verdict_cmd.py`.

## Live site differences and verification

### Local checkout and published website

The original 16 October inventory inspected CLI 4.49.0 at `f0bea18f85d928e605003e45ae2eb6a312372ee2` and the Cloud checkout at `6f38702f6bee5a082db750b28c776d215c633afb`, including then-uncommitted additions. The CLI quality notes in this document now follow the accompanying source, whose package declares 4.50.1; the historical live-site observations below have not been rerun. Those additions include Investigator, scan assessments, and dead-code evidence views. Working-tree content, deployed application behavior, and public commercial copy are separate evidence sources.

Public HTTP pages were checked directly on 16 October 2026. The following differences are material to using the catalog:

| Topic | Inspected local cloud code | Live published page on the review date |
| --- | --- | --- |
| Initial workspace trial | Seven days and 50 credits | Fourteen days and 50 credits |
| Credit-pack access term | Permanent Workspace unlock | Twelve months of Workspace for up to three people; credits remain available |
| Workspace pass | Not represented by the local four-pack purchase implementation | US$990 for twelve months; unlimited members and 1,000 credits included |
| Enterprise | Prepaid credit deductions bypassed locally | Advertised from US$5,000/year with 5,000 annual credits |
| Paid actions on Free | Comparison, AI triage, and AI fix PR require Workspace in local routes | Public pricing says credit actions work on every plan when credits are available |
| Deep scans | Workspace Anthropic key and provider usage cap | Published as ten credits, refunded if no report is produced |

The live terms above are published product copy, not evidence that authenticated billing or entitlements were exercised. Confirm the deployed implementation before using either set as a commercial commitment. Sources: [live pricing](https://skylos.dev/pricing), [live Workspace description](https://skylos.dev/workspace-governance), and [live sign-in](https://skylos.dev/login).

### Historical verification from 16 October 2026

These results belong to that source snapshot. They were not rerun for the accompanying quality-rule changes.

| Check | Result | What it establishes |
| --- | --- | --- |
| Cloud logic suite compiled with the installed TypeScript toolchain | Passed | The suite compiled against the current checkout |
| Cloud logic/build contract tests | 3,615 passed, one skipped, zero failed | Local business logic and source contracts across 328 compiled logic test files plus the project-secret build contract |
| Focused CLI static-analysis tests | 92 passed | Selected language integration, parser-extra handling, secrets, NuGet SCA and gate output behavior |
| Focused CLI workflow tests | 77 passed | Agent parser, MCP descriptions, preflight, done receipts, and terminal probing |
| Live `/`, `/pricing`, `/workspace-governance`, `/login`, `/scan`, `/judge`, `/status` | HTTP 200 | Public pages are reachable and their returned content was inspected |
| Live `/dashboard` without a session | Redirected to `/login?next=%2Fdashboard` | Dashboard entry requires sign-in |
| Live `/api/health` | HTTP 200 | Status endpoint responds; its own text explicitly excludes probing sign-in, scans, or dependencies |
| Live `/api/v1/openapi.json` | HTTP 200; eleven route definitions | Public schema is available |
| Browser rendering and interactive UI | Passed locally in an isolated Linux Chromium renderer | Actual Cloud UI rendered with illustrative fixtures at a 1600 px desktop width; fourteen screenshots captured with zero browser errors |
| Customer guide visuals and sample compliance evidence | Fourteen desktop screenshots, nine interactive views, and example report exports | Local links, anchors, embedded image widths and canonical JSON SHA-256 checked; browser checks passed for all fourteen images, search/reset, full-size screenshot viewing and the embedded desktop Compliance reports page |
| Authenticated production workflows | Not exercised | Captures use isolated illustrative data; production billing, notifications, scans and repository mutations are not claimed tested |

The local checks used controlled fixtures. They do not establish production configuration, applied database migrations, delivery of external notifications, or end-to-end repository access. No production purchase, PR, comment, invitation, or customer-data mutation was made for this inventory.

### Deployment prerequisites that affect availability

Ordinary hosted Cloud scans require their configured Vercel Sandbox snapshot and GitHub installation. Deep scans require their own worker snapshot and provider configuration. Public preview uses a separate isolated worker. The 16 October source inventory recorded hosted scanner versions 4.45.0 for ordinary Cloud scanning and 4.37.0 for public preview. These are historical observations, not a fresh worker-version check; do not infer parity with the CLI package version or accompanying source changes.

Investigator defaults on unless `SKYLOS_INVESTIGATOR_ENABLED=0`; its schema dependencies must exist. Agent checks and review exposure have explicit enable flags. Scanner Proof is a pilot hidden unless `SCANNER_PROOF_ENABLED=1`. SAML SSO, email delivery, billing checkout, GitHub/GitLab/Jira/Bitbucket/Azure integrations, and signed verdicts each depend on configured external services or credentials. Features with these conditions are implementations in the codebase, not unconditional deployment guarantees.

## Complete built-in rule catalog

The current catalog contains **252 entries**: ai defect (28), dead code (10), dependency (1), quality (70), reliability (5), secrets (2), security (136).

This is the registry of rule identities. Individual entries have different language support and activation paths; the list includes change checks, configuration checks and special command rules as well as ordinary source scans. A catalog default severity can be absent or differ from a contextual finding. Additional community or organization rules are separate. Names below reproduce catalog labels verbatim. Some shared IDs have language-specific meanings: Python `SKY-L006` checks inconsistent returns and Python `SKY-Q502` checks oversized files. `SKY-SC001` checks FastAPI security contracts despite its historical catalog label.

Source: [rule catalog](../skylos/rules/catalog.py).

### Ai Defect

| Rule | Name | Finding type | Catalog severity |
| --- | --- | --- | --- |
| `SKY-A101` | Test assertion weakening | review | MEDIUM |
| `SKY-A102` | High-risk change without tests | review | LOW |
| `SKY-A103` | CI permission expansion | review | HIGH |
| `SKY-A104` | Public CLI surface drift | review | MEDIUM |
| `SKY-A105` | Contract route guard missing | review | HIGH |
| `SKY-A106` | Suspicious dependency version bump | review | LOW |
| `SKY-A110` | Test deleted | review | HIGH |
| `SKY-A111` | Test newly skipped | review | HIGH |
| `SKY-A112` | Test settings loosened | review | HIGH |
| `SKY-A113` | Tests fail when Skylos runs them | defect | HIGH |
| `SKY-A114` | Skylos settings or hooks changed | review | HIGH |
| `SKY-A115` | Test answer hard-coded in code | review | HIGH |
| `SKY-A116` | Code detects the test run | review | HIGH |
| `SKY-A117` | Comparison rigged to always pass | review | HIGH |
| `SKY-A118` | Inline suppression added | review | LOW |
| `SKY-A119` | Linter or scanner settings weakened | review | HIGH |
| `SKY-A120` | Changed line not checked by tests | review | MEDIUM |
| `SKY-A121` | CI check weakened | review | HIGH |
| `SKY-A122` | AI-reviewer settings changed | review | MEDIUM |
| `SKY-A125` | Scanner suppression marker added | review | MEDIUM |
| `SKY-A135` | Code left unused by the change | review | MEDIUM |
| `SKY-A136` | New code nothing calls | review | LOW |
| `SKY-A137` | New code only tests call | review | LOW |
| `SKY-D222` | Dependency hallucination | review | CRITICAL |
| `SKY-D224` | API signature hallucination | review | HIGH |
| `SKY-D225` | Dependency version hallucination | review | HIGH |
| `SKY-L012` | Phantom symbol reference | review | Contextual |
| `SKY-L023` | Phantom decorator | review | Contextual |

### Dead Code

| Rule | Name | Finding type | Catalog severity |
| --- | --- | --- | --- |
| `SKY-E002` | Empty file | review | LOW |
| `SKY-E003` | Unused TypeScript/JavaScript file | review | LOW |
| `SKY-U001` | Unused function | review | Contextual |
| `SKY-U002` | Unused import | review | Contextual |
| `SKY-U003` | Unused variable | review | Contextual |
| `SKY-U004` | Unused class | review | Contextual |
| `SKY-U005` | Unused dependency | review | Contextual |
| `SKY-U006` | Unused parameter | review | Contextual |
| `SKY-UC001` | Unreachable Python code | defect | Contextual |
| `SKY-UC002` | Unreachable statement | defect | Contextual |

### Dependency

| Rule | Name | Finding type | Catalog severity |
| --- | --- | --- | --- |
| `SKY-SCA-LIC001` | Dependency license policy violation | review | HIGH |

### Quality

| Rule | Name | Finding type | Catalog severity |
| --- | --- | --- | --- |
| `SKY-C303` | Too many function arguments | advice | Contextual |
| `SKY-C304` | Function too long | advice | Contextual |
| `SKY-C401` | Duplicated code clone | advice | Contextual |
| `SKY-CIRC` | Circular dependency | review | Contextual |
| `SKY-F101` | Framework handler practice issue | advice | Contextual |
| `SKY-F102` | Framework route missing auth | review | Contextual |
| `SKY-L001` | Mutable default argument | defect | Contextual |
| `SKY-L002` | Bare except block | review | Contextual |
| `SKY-L003` | Dangerous comparison | review | Contextual |
| `SKY-L004` | Anti-pattern try block | advice | Contextual |
| `SKY-L005` | Unused exception variable | advice | Contextual |
| `SKY-L006` | Shadowed loop variable | review | Contextual |
| `SKY-L007` | Empty error handler | review | Contextual |
| `SKY-L008` | Missing resource cleanup | review | Contextual |
| `SKY-L009` | Debug leftover | review | Contextual |
| `SKY-L010` | Security TODO marker | review | Contextual |
| `SKY-L011` | Disabled security control | review | Contextual |
| `SKY-L013` | Insecure randomness | review | Contextual |
| `SKY-L014` | Hardcoded credential | review | Contextual |
| `SKY-L016` | Undefined config | review | Contextual |
| `SKY-L017` | Error information disclosure | review | Contextual |
| `SKY-L020` | Overly broad file permissions | review | Contextual |
| `SKY-L021` | Security regression | review | Contextual |
| `SKY-L024` | Stale mock | review | Contextual |
| `SKY-L026` | Unfinished code or placeholder default | review | Contextual |
| `SKY-L027` | Duplicate string literal | advice | Contextual |
| `SKY-L028` | Too many returns | advice | Contextual |
| `SKY-L029` | Boolean trap | advice | Contextual |
| `SKY-L030` | Broad exception with trivial handler | review | Contextual |
| `SKY-L031` | Missing network timeout | review | Contextual |
| `SKY-L032` | Mock or placeholder data | review | Contextual |
| `SKY-L033` | No-effect statement | defect | Contextual |
| `SKY-L034` | Repeated mutable alias | defect | MEDIUM |
| `SKY-L035` | Blanket ESLint disable | review | HIGH |
| `SKY-P401` | Inefficient loop pattern | advice | Contextual |
| `SKY-P402` | Repeated expensive operation | advice | Contextual |
| `SKY-P403` | Suspicious performance pattern | advice | Contextual |
| `SKY-P404` | Unbounded eager ORM query | review | MEDIUM |
| `SKY-Q301` | Cyclomatic complexity | advice | Contextual |
| `SKY-Q302` | Deep nesting | advice | Contextual |
| `SKY-Q305` | Duplicate branch logic | review | Contextual |
| `SKY-Q306` | Cognitive complexity | advice | Contextual |
| `SKY-Q401` | Async blocking call | defect | Contextual |
| `SKY-Q402` | Await in loop | review | LOW |
| `SKY-Q403` | Inconsistent lock acquisition order | review | HIGH |
| `SKY-Q404` | Thread shared state mutation | review | MEDIUM |
| `SKY-Q405` | Async Promise executor | defect | HIGH |
| `SKY-Q406` | Async Array.forEach callback | defect | HIGH |
| `SKY-Q407` | Discarded async Array.map result | defect | HIGH |
| `SKY-Q501` | God class | advice | Contextual |
| `SKY-Q502` | Class too large | advice | Contextual |
| `SKY-Q701` | High coupling | advice | Contextual |
| `SKY-Q702` | Low cohesion | advice | Contextual |
| `SKY-Q801` | High instability | advice | MEDIUM |
| `SKY-Q802` | High distance from main sequence | advice | Contextual |
| `SKY-Q803` | Architecture zone warning | advice | Contextual |
| `SKY-Q804` | Dependency inversion violation | advice | Contextual |
| `SKY-Q805` | Architecture layer policy violation | review | Contextual |
| `SKY-Q806` | Opaque identifier | advice | LOW |
| `SKY-R101` | Python type-check policy | advice | MEDIUM |
| `SKY-R102` | Python lint policy | advice | LOW |
| `SKY-R103` | Skylos gate policy | advice | LOW |
| `SKY-R104` | Pre-commit policy | advice | LOW |
| `SKY-R105` | TypeScript type-check policy | advice | LOW |
| `SKY-T101` | Missing type annotations | advice | Contextual |
| `SKY-T102` | Weak framework route typing | advice | Contextual |
| `SKY-T103` | Suspicious chained type assertion | review | MEDIUM |
| `SKY-T104` | TypeScript compiler suppression directive | review | MEDIUM |
| `SKY-T105` | Unvalidated JSON type assertion | review | MEDIUM |
| `SKY-T106` | Unsafe exported API type | review | MEDIUM |

### Reliability

| Rule | Name | Finding type | Catalog severity |
| --- | --- | --- | --- |
| `SKY-DEP003` | External Ingress routes to a reload-mode application server | review | MEDIUM |
| `SKY-GPU000` | GPU release contract is invalid or incomplete | review | HIGH |
| `SKY-GPU001` | CUDA image requires newer NVIDIA driver | review | HIGH |
| `SKY-GPU002` | CUDA target architecture missing from build | review | HIGH |
| `SKY-GPU003` | TensorRT engine is not portable across target GPUs | review | HIGH |

### Secrets

| Rule | Name | Finding type | Catalog severity |
| --- | --- | --- | --- |
| `SKY-S101` | Secret detected | review | CRITICAL |
| `SKY-S102` | Client-side secret exposure | review | HIGH |

### Security

| Rule | Name | Finding type | Catalog severity |
| --- | --- | --- | --- |
| `SKY-D200` | Dangerous call pattern | review | Contextual |
| `SKY-D201` | Dynamic code execution via eval | review | HIGH |
| `SKY-D202` | Dynamic code execution via exec | review | HIGH |
| `SKY-D203` | OS command execution | review | CRITICAL |
| `SKY-D204` | Unsafe pickle deserialization | review | CRITICAL |
| `SKY-D205` | Unsafe pickle.loads deserialization | review | CRITICAL |
| `SKY-D206` | Unsafe YAML load | review | HIGH |
| `SKY-D207` | Weak MD5 hash | review | MEDIUM |
| `SKY-D208` | Weak SHA1 hash | review | MEDIUM |
| `SKY-D209` | Subprocess shell execution | review | HIGH |
| `SKY-D210` | TLS verification disabled | review | HIGH |
| `SKY-D211` | SQL injection | review | CRITICAL |
| `SKY-D212` | Command injection | review | CRITICAL |
| `SKY-D215` | Path traversal | review | HIGH |
| `SKY-D216` | Server-side request forgery | review | CRITICAL |
| `SKY-D217` | Raw SQL execution | review | CRITICAL |
| `SKY-D223` | Undeclared third-party dependency | review | MEDIUM |
| `SKY-D226` | Cross-site scripting: untrusted content marked safe | review | CRITICAL |
| `SKY-D227` | Cross-site scripting: unsafe inline template | review | HIGH |
| `SKY-D228` | Cross-site scripting: HTML built from user input | review | HIGH |
| `SKY-D230` | Open redirect | review | HIGH |
| `SKY-D231` | Unsafe CORS configuration | review | HIGH |
| `SKY-D232` | Unsafe JWT handling | review | CRITICAL |
| `SKY-D233` | Unsafe deserialization | review | CRITICAL |
| `SKY-D234` | Mass assignment | review | HIGH |
| `SKY-D235` | Remote command execution sink | review | HIGH |
| `SKY-D240` | MCP tool description poisoning | review | CRITICAL |
| `SKY-D241` | MCP unauthenticated network transport | review | HIGH |
| `SKY-D242` | MCP overly permissive resource URI | review | HIGH |
| `SKY-D243` | MCP network-exposed server without auth | review | CRITICAL |
| `SKY-D244` | MCP hardcoded tool parameter secret | review | CRITICAL |
| `SKY-D245` | Dynamic require | review | HIGH |
| `SKY-D246` | JWT decode without verification | review | HIGH |
| `SKY-D247` | CORS wildcard origin | review | MEDIUM |
| `SKY-D248` | Hardcoded internal URL | review | MEDIUM |
| `SKY-D250` | Weak random source | review | MEDIUM |
| `SKY-D251` | Sensitive data in logs | review | HIGH |
| `SKY-D252` | Insecure cookie | review | MEDIUM |
| `SKY-D253` | Timing-unsafe comparison | review | MEDIUM |
| `SKY-D254` | HTTP session trust boundary violation | review | HIGH |
| `SKY-D260` | Prompt injection exposure | review | HIGH |
| `SKY-D261` | Untrusted input to LLM prompt | review | HIGH |
| `SKY-D262` | Unsafe LLM output handling | review | CRITICAL |
| `SKY-D263` | Sensitive data sent to LLM | review | HIGH |
| `SKY-D264` | Excessive agent tool privilege | review | HIGH |
| `SKY-D265` | Unsafe ML model deserialization | review | CRITICAL |
| `SKY-D266` | AI config instruction injection | review | CRITICAL |
| `SKY-D267` | Unbounded LLM consumption | review | MEDIUM |
| `SKY-D270` | Sensitive data in storage | review | MEDIUM |
| `SKY-D271` | Error information disclosure over HTTP | review | MEDIUM |
| `SKY-D280` | Next.js mutating API route missing authentication | review | HIGH |
| `SKY-D281` | Next.js server action SQL injection | review | CRITICAL |
| `SKY-D282` | Webhook signature verification issue | review | HIGH |
| `SKY-D290` | GitHub Actions dangerous trigger | review | HIGH |
| `SKY-D291` | GitHub Actions excessive permissions | review | HIGH |
| `SKY-D292` | GitHub Actions unpinned action | review | HIGH |
| `SKY-D293` | GitHub Actions persisted checkout credentials | review | MEDIUM |
| `SKY-D294` | GitHub Actions template injection | review | CRITICAL |
| `SKY-D295` | GitHub Actions self-hosted runner | review | HIGH |
| `SKY-D296` | GitHub Actions unpinned container image | review | HIGH |
| `SKY-D297` | GitHub Actions secrets inheritance | review | HIGH |
| `SKY-D298` | GitHub Actions overprovisioned secrets | review | HIGH |
| `SKY-D299` | GitHub Actions secret outside environment | review | HIGH |
| `SKY-D300` | GitHub Actions unsafe environment file write | review | HIGH |
| `SKY-D301` | GitHub Actions hardcoded container credential | review | HIGH |
| `SKY-D302` | GitHub Actions broad GitHub App token | review | HIGH |
| `SKY-D303` | GitHub Actions unsound contains condition | review | MEDIUM |
| `SKY-D304` | GitHub Actions spoofable bot condition | review | MEDIUM |
| `SKY-D305` | GitHub Actions unsound multiline condition | review | MEDIUM |
| `SKY-D306` | GitHub Actions insecure commands enabled | review | HIGH |
| `SKY-D307` | GitHub Actions anonymous definition | review | LOW |
| `SKY-D308` | GitHub Actions cache poisoning risk | review | HIGH |
| `SKY-D309` | GitHub Actions broad secret environment | review | HIGH |
| `SKY-D310` | GitHub Actions OIDC build-script exposure | review | HIGH |
| `SKY-D311` | GitHub Actions lax artifact upload | review | MEDIUM |
| `SKY-D312` | GitHub Actions JavaScript install scripts | review | HIGH |
| `SKY-D313` | GitHub Actions privileged job missing timeout | review | MEDIUM |
| `SKY-D314` | GitLab CI mutable container image | review | HIGH |
| `SKY-D315` | GitLab CI unpinned external include | review | HIGH |
| `SKY-D316` | GitLab CI literal secret variable | review | HIGH |
| `SKY-D317` | GitLab CI untrusted eval | review | HIGH |
| `SKY-D318` | GitLab CI Docker-in-Docker TLS disabled | review | HIGH |
| `SKY-D319` | GitLab CI OIDC local-script exposure | review | HIGH |
| `SKY-D320` | GitLab CI release cache poisoning risk | review | HIGH |
| `SKY-D321` | GitLab CI privileged job missing timeout | review | MEDIUM |
| `SKY-D322` | GitLab CI dynamic runner tag | review | MEDIUM |
| `SKY-D323` | GitLab CI ambiguous secret token | review | MEDIUM |
| `SKY-D324` | Symlink-following file write | review | HIGH |
| `SKY-D325` | Symlink-following file read | review | MEDIUM |
| `SKY-D326` | Unsafe archive extraction | review | HIGH |
| `SKY-D327` | Shell or agent data exfiltration | review | CRITICAL |
| `SKY-D328` | Remote script piped to shell | review | HIGH |
| `SKY-D329` | Broad destructive shell command | review | HIGH |
| `SKY-D330` | Docker Compose privileged edge container | review | HIGH |
| `SKY-D331` | Docker Compose host device exposure | review | HIGH |
| `SKY-D332` | Docker Compose host networking on edge service | review | MEDIUM |
| `SKY-D333` | Systemd edge service runs as root | review | HIGH |
| `SKY-D334` | Systemd root service executes mutable path | review | HIGH |
| `SKY-D335` | Systemd edge service missing sandboxing | review | MEDIUM |
| `SKY-D336` | Systemd broad edge service privilege | review | HIGH |
| `SKY-D337` | Package registry or index override | review | HIGH |
| `SKY-D338` | Sensitive host scope access | review | CRITICAL |
| `SKY-D339` | Persistent environment mutation | review | HIGH |
| `SKY-D340` | Unapproved package or artifact publish | review | HIGH |
| `SKY-D341` | Untrusted package-managed tool execution | review | HIGH |
| `SKY-D342` | Dockerfile remote ADD without checksum | review | HIGH |
| `SKY-D343` | Dockerfile literal secret build value | review | HIGH |
| `SKY-D344` | Trojan Source bidirectional Unicode | review | HIGH |
| `SKY-D345` | Mutable Hugging Face artifact revision | review | HIGH |
| `SKY-D346` | Flask debug mode enabled | review | HIGH |
| `SKY-D347` | Unsafe logging config listener | review | MEDIUM |
| `SKY-D348` | Insecure temporary filename | review | HIGH |
| `SKY-D349` | Server-side template injection | review | CRITICAL |
| `SKY-D350` | GitHub Actions AI agent on untrusted trigger without actor gate | review | CRITICAL |
| `SKY-D351` | GitHub Actions AI agent write-access check widened | review | CRITICAL |
| `SKY-D352` | GitHub Actions AI agent with shell on untrusted trigger | review | HIGH |
| `SKY-D353` | GitHub Actions untrusted text in AI agent prompt | review | HIGH |
| `SKY-D354` | GitHub Actions AI agent action with published advisory | review | HIGH |
| `SKY-D510` | Prototype pollution | review | HIGH |
| `SKY-DEP001` | Externally deployed route is missing a required auth guard | review | HIGH |
| `SKY-DEP002` | External Ingress exposes the Flask development debugger | review | HIGH |
| `SKY-G203` | Go defer in loop | review | HIGH |
| `SKY-G206` | Go unsafe package import | review | HIGH |
| `SKY-G207` | Go weak MD5 hash | review | MEDIUM |
| `SKY-G208` | Go weak SHA1 hash | review | MEDIUM |
| `SKY-G209` | Go weak RNG | review | MEDIUM |
| `SKY-G210` | Go TLS verification disabled | review | HIGH |
| `SKY-G211` | Go SQL injection | review | CRITICAL |
| `SKY-G212` | Go command injection | review | CRITICAL |
| `SKY-G215` | Go path traversal | review | HIGH |
| `SKY-G216` | Go SSRF | review | CRITICAL |
| `SKY-G220` | Go open redirect | review | HIGH |
| `SKY-G221` | Go insecure cookie | review | MEDIUM |
| `SKY-G260` | Go unclosed resource | review | HIGH |
| `SKY-G280` | Go weak TLS version | review | HIGH |
| `SKY-SC001` | Smart contract security issue | review | HIGH |

## Cloud dashboard screen reference

The checkout has **64 dashboard page routes**. Dynamic identifiers are shown in brackets. Several routes are scoped views of the same feature; this count is a route inventory, not a count of independent product capabilities.

| Route | Implementation |
| --- | --- |
| `/dashboard/access-review` | [src/app/(request)/dashboard/access-review/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/access-review/page.tsx) |
| `/dashboard/account` | [src/app/(request)/dashboard/account/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/account/page.tsx) |
| `/dashboard/activity` | [src/app/(request)/dashboard/activity/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/activity/page.tsx) |
| `/dashboard/agent-activity` | [src/app/(request)/dashboard/agent-activity/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agent-activity/page.tsx) |
| `/dashboard/agent-checks/[scanId]` | [src/app/(request)/dashboard/agent-checks/[scanId]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agent-checks/[scanId]/page.tsx) |
| `/dashboard/agent-checks/agents` | [src/app/(request)/dashboard/agent-checks/agents/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agent-checks/agents/page.tsx) |
| `/dashboard/agent-checks` | [src/app/(request)/dashboard/agent-checks/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agent-checks/page.tsx) |
| `/dashboard/agent-checks/review` | [src/app/(request)/dashboard/agent-checks/review/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agent-checks/review/page.tsx) |
| `/dashboard/agents/evidence` | [src/app/(request)/dashboard/agents/evidence/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agents/evidence/page.tsx) |
| `/dashboard/agents/guardrails` | [src/app/(request)/dashboard/agents/guardrails/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agents/guardrails/page.tsx) |
| `/dashboard/agents` | [src/app/(request)/dashboard/agents/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agents/page.tsx) |
| `/dashboard/agents/scorecard` | [src/app/(request)/dashboard/agents/scorecard/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/agents/scorecard/page.tsx) |
| `/dashboard/billing/history` | [src/app/(request)/dashboard/billing/history/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/billing/history/page.tsx) |
| `/dashboard/billing` | [src/app/(request)/dashboard/billing/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/billing/page.tsx) |
| `/dashboard/compliance` | [src/app/(request)/dashboard/compliance/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/compliance/page.tsx) |
| `/dashboard/credits` | [src/app/(request)/dashboard/credits/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/credits/page.tsx) |
| `/dashboard/deep-scans/[id]` | [src/app/(request)/dashboard/deep-scans/[id]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/deep-scans/[id]/page.tsx) |
| `/dashboard/deep-scans` | [src/app/(request)/dashboard/deep-scans/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/deep-scans/page.tsx) |
| `/dashboard/evidence` | [src/app/(request)/dashboard/evidence/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/evidence/page.tsx) |
| `/dashboard/exceptions/[id]` | [src/app/(request)/dashboard/exceptions/[id]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/exceptions/[id]/page.tsx) |
| `/dashboard/exceptions/org-rules` | [src/app/(request)/dashboard/exceptions/org-rules/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/exceptions/org-rules/page.tsx) |
| `/dashboard/exceptions` | [src/app/(request)/dashboard/exceptions/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/exceptions/page.tsx) |
| `/dashboard/get-started` | [src/app/(request)/dashboard/get-started/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/get-started/page.tsx) |
| `/dashboard/issues/[id]` | [src/app/(request)/dashboard/issues/[id]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/issues/[id]/page.tsx) |
| `/dashboard/issues` | [src/app/(request)/dashboard/issues/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/issues/page.tsx) |
| `/dashboard` | [src/app/(request)/dashboard/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/page.tsx) |
| `/dashboard/policy` | [src/app/(request)/dashboard/policy/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/policy/page.tsx) |
| `/dashboard/posture` | [src/app/(request)/dashboard/posture/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/posture/page.tsx) |
| `/dashboard/projects/[id]/activity` | [src/app/(request)/dashboard/projects/[id]/activity/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/activity/page.tsx) |
| `/dashboard/projects/[id]/cleanup` | [src/app/(request)/dashboard/projects/[id]/cleanup/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/cleanup/page.tsx) |
| `/dashboard/projects/[id]/controls` | [src/app/(request)/dashboard/projects/[id]/controls/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/controls/page.tsx) |
| `/dashboard/projects/[id]/debt` | [src/app/(request)/dashboard/projects/[id]/debt/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/debt/page.tsx) |
| `/dashboard/projects/[id]/defense` | [src/app/(request)/dashboard/projects/[id]/defense/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/defense/page.tsx) |
| `/dashboard/projects/[id]/insights` | [src/app/(request)/dashboard/projects/[id]/insights/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/insights/page.tsx) |
| `/dashboard/projects/[id]/investigate` | [src/app/(request)/dashboard/projects/[id]/investigate/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/investigate/page.tsx) |
| `/dashboard/projects/[id]/issues/[issueId]` | [src/app/(request)/dashboard/projects/[id]/issues/[issueId]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/issues/[issueId]/page.tsx) |
| `/dashboard/projects/[id]/issues` | [src/app/(request)/dashboard/projects/[id]/issues/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/issues/page.tsx) |
| `/dashboard/projects/[id]/ledger` | [src/app/(request)/dashboard/projects/[id]/ledger/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/ledger/page.tsx) |
| `/dashboard/projects/[id]` | [src/app/(request)/dashboard/projects/[id]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/page.tsx) |
| `/dashboard/projects/[id]/provenance` | [src/app/(request)/dashboard/projects/[id]/provenance/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/provenance/page.tsx) |
| `/dashboard/projects/[id]/pull-requests/[scanId]` | [src/app/(request)/dashboard/projects/[id]/pull-requests/[scanId]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/pull-requests/[scanId]/page.tsx) |
| `/dashboard/projects/[id]/pull-requests` | [src/app/(request)/dashboard/projects/[id]/pull-requests/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/pull-requests/page.tsx) |
| `/dashboard/projects/[id]/scanner-proof` | [src/app/(request)/dashboard/projects/[id]/scanner-proof/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/scanner-proof/page.tsx) |
| `/dashboard/projects/[id]/scans/[scanId]/debt` | [src/app/(request)/dashboard/projects/[id]/scans/[scanId]/debt/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/scans/[scanId]/debt/page.tsx) |
| `/dashboard/projects/[id]/scans/[scanId]/defense` | [src/app/(request)/dashboard/projects/[id]/scans/[scanId]/defense/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/scans/[scanId]/defense/page.tsx) |
| `/dashboard/projects/[id]/scans/[scanId]` | [src/app/(request)/dashboard/projects/[id]/scans/[scanId]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/scans/[scanId]/page.tsx) |
| `/dashboard/projects/[id]/scans/[scanId]/provenance` | [src/app/(request)/dashboard/projects/[id]/scans/[scanId]/provenance/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/scans/[scanId]/provenance/page.tsx) |
| `/dashboard/projects/[id]/scans` | [src/app/(request)/dashboard/projects/[id]/scans/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/scans/page.tsx) |
| `/dashboard/projects/[id]/settings` | [src/app/(request)/dashboard/projects/[id]/settings/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/settings/page.tsx) |
| `/dashboard/projects/[id]/suppressions` | [src/app/(request)/dashboard/projects/[id]/suppressions/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/[id]/suppressions/page.tsx) |
| `/dashboard/projects` | [src/app/(request)/dashboard/projects/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/projects/page.tsx) |
| `/dashboard/pull-requests` | [src/app/(request)/dashboard/pull-requests/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/pull-requests/page.tsx) |
| `/dashboard/rules` | [src/app/(request)/dashboard/rules/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/rules/page.tsx) |
| `/dashboard/scans/[id]/debt` | [src/app/(request)/dashboard/scans/[id]/debt/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/scans/[id]/debt/page.tsx) |
| `/dashboard/scans/[id]/defense` | [src/app/(request)/dashboard/scans/[id]/defense/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/scans/[id]/defense/page.tsx) |
| `/dashboard/scans/[id]` | [src/app/(request)/dashboard/scans/[id]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/scans/[id]/page.tsx) |
| `/dashboard/scans/[id]/provenance` | [src/app/(request)/dashboard/scans/[id]/provenance/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/scans/[id]/provenance/page.tsx) |
| `/dashboard/scans/compare` | [src/app/(request)/dashboard/scans/compare/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/scans/compare/page.tsx) |
| `/dashboard/scans` | [src/app/(request)/dashboard/scans/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/scans/page.tsx) |
| `/dashboard/settings/github` | [src/app/(request)/dashboard/settings/github/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/settings/github/page.tsx) |
| `/dashboard/settings` | [src/app/(request)/dashboard/settings/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/settings/page.tsx) |
| `/dashboard/teams/[id]` | [src/app/(request)/dashboard/teams/[id]/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/teams/[id]/page.tsx) |
| `/dashboard/teams` | [src/app/(request)/dashboard/teams/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/teams/page.tsx) |
| `/dashboard/trends` | [src/app/(request)/dashboard/trends/page.tsx](/Users/oha/skylos-cloud/skylos-cloud/src/app/(request)/dashboard/trends/page.tsx) |

## Cloud API route reference

The checkout contains **172 application API route handlers**. The stable integration surface is the versioned read API described above. This inventory also includes session UI actions, repository webhooks, scheduled jobs, worker callbacks and operator routes, each with its own authorization requirements.

| Route | Exported HTTP methods |
| --- | --- |
| [`/api/agent/validate`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/agent/validate/route.ts) | GET |
| [`/api/agent-guardrails`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/agent-guardrails/route.ts) | PUT |
| [`/api/agent-runs`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/agent-runs/route.ts) | POST, GET |
| [`/api/analytics/page-view`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/analytics/page-view/route.ts) | POST |
| [`/api/auth/exchange`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/auth/exchange/route.ts) | GET |
| [`/api/badge/[projectId]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/badge/[projectId]/route.ts) | GET |
| [`/api/billing/checkout`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/billing/checkout/route.ts) | GET, POST |
| [`/api/billing/status`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/billing/status/route.ts) | GET |
| [`/api/billing/webhook`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/billing/webhook/route.ts) | POST |
| [`/api/cli/connect`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cli/connect/route.ts) | POST |
| [`/api/cli/org`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cli/org/route.ts) | GET |
| [`/api/cloud-scan/jobs/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cloud-scan/jobs/[id]/route.ts) | GET |
| [`/api/cloud-scan/projects/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cloud-scan/projects/[id]/route.ts) | DELETE |
| [`/api/cloud-scan/repos`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cloud-scan/repos/route.ts) | POST |
| [`/api/cloud-scan/worker`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cloud-scan/worker/route.ts) | POST |
| [`/api/compliance/agent-changes`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/compliance/agent-changes/route.ts) | POST |
| [`/api/compliance/report`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/compliance/report/route.ts) | POST |
| [`/api/compliance/reports/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/compliance/reports/[id]/route.ts) | GET |
| [`/api/compliance/reports`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/compliance/reports/route.ts) | GET |
| [`/api/control-registry/import`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/control-registry/import/route.ts) | POST |
| [`/api/credits/balance`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/credits/balance/route.ts) | GET |
| [`/api/credits/costs`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/credits/costs/route.ts) | GET |
| [`/api/credits/deduct`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/credits/deduct/route.ts) | POST |
| [`/api/cron/cleanup-prs`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/cleanup-prs/route.ts) | GET |
| [`/api/cron/cloud-scan`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/cloud-scan/route.ts) | GET |
| [`/api/cron/exception-expiry`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/exception-expiry/route.ts) | GET |
| [`/api/cron/github-inventory`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/github-inventory/route.ts) | GET |
| [`/api/cron/github-onboarding`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/github-onboarding/route.ts) | GET |
| [`/api/cron/lifecycle-emails`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/lifecycle-emails/route.ts) | GET |
| [`/api/cron/retention`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/retention/route.ts) | GET |
| [`/api/cron/vulnhunter`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/vulnhunter/route.ts) | GET |
| [`/api/cron/weekly-digest`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/cron/weekly-digest/route.ts) | GET |
| [`/api/digest/preview`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/digest/preview/route.ts) | POST |
| [`/api/digest/settings`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/digest/settings/route.ts) | GET, POST |
| [`/api/digest/subscription`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/digest/subscription/route.ts) | POST |
| [`/api/digest/unsubscribe`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/digest/unsubscribe/route.ts) | POST |
| [`/api/exception-requests/[id]/decision`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/exception-requests/[id]/decision/route.ts) | POST |
| [`/api/exception-requests/[id]/revoke`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/exception-requests/[id]/revoke/route.ts) | POST |
| [`/api/exception-requests/export`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/exception-requests/export/route.ts) | GET |
| [`/api/exception-requests`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/exception-requests/route.ts) | GET |
| [`/api/exceptions/[id]/export`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/exceptions/[id]/export/route.ts) | GET |
| [`/api/exceptions/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/exceptions/[id]/route.ts) | GET |
| [`/api/findings/[id]/fix`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/findings/[id]/fix/route.ts) | GET, POST |
| [`/api/findings/[id]/flow`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/findings/[id]/flow/route.ts) | GET |
| [`/api/findings/[id]/suppress`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/findings/[id]/suppress/route.ts) | POST |
| [`/api/findings/export`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/findings/export/route.ts) | POST |
| [`/api/fix-proposals/[id]/abandon`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/fix-proposals/[id]/abandon/route.ts) | POST |
| [`/api/fix-proposals/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/fix-proposals/[id]/route.ts) | GET |
| [`/api/github/callback`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/github/callback/route.ts) | GET |
| [`/api/github/inventory/sync`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/github/inventory/sync/route.ts) | POST |
| [`/api/github/onboarding/preview`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/github/onboarding/preview/route.ts) | POST |
| [`/api/github/onboarding/runs`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/github/onboarding/runs/route.ts) | POST |
| [`/api/github/onboarding/setup-prs`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/github/onboarding/setup-prs/route.ts) | POST |
| [`/api/github/webhook`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/github/webhook/route.ts) | POST |
| [`/api/health`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/health/route.ts) | GET |
| [`/api/integrations/jira/issue-types`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/integrations/jira/issue-types/route.ts) | POST |
| [`/api/integrations/jira`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/integrations/jira/route.ts) | GET, PUT, DELETE |
| [`/api/integrations/jira/test`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/integrations/jira/test/route.ts) | POST |
| [`/api/issue-groups/[id]/assign`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/assign/route.ts) | GET, POST, PATCH, DELETE |
| [`/api/issue-groups/[id]/comments/[commentId]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/comments/[commentId]/route.ts) | PATCH, DELETE |
| [`/api/issue-groups/[id]/comments`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/comments/route.ts) | GET, POST |
| [`/api/issue-groups/[id]/exception-requests`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/exception-requests/route.ts) | POST |
| [`/api/issue-groups/[id]/jira/refresh`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/jira/refresh/route.ts) | POST |
| [`/api/issue-groups/[id]/jira`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/jira/route.ts) | GET, POST |
| [`/api/issue-groups/[id]/org-triage-rule`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/org-triage-rule/route.ts) | GET, POST |
| [`/api/issue-groups/[id]/owner-team`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/owner-team/route.ts) | PUT |
| [`/api/issue-groups/[id]/suppress`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/suppress/route.ts) | POST |
| [`/api/issue-groups/[id]/triage`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/[id]/triage/route.ts) | POST |
| [`/api/issue-groups`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/issue-groups/route.ts) | GET |
| [`/api/judge/admin/import`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/judge/admin/import/route.ts) | POST |
| [`/api/judge/admin/seed`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/judge/admin/seed/route.ts) | POST |
| [`/api/judge/admin/suggestions`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/judge/admin/suggestions/route.ts) | GET, POST |
| [`/api/judge/suggestions`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/judge/suggestions/route.ts) | POST |
| [`/api/lifecycle-emails/unsubscribe`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/lifecycle-emails/unsubscribe/route.ts) | POST |
| [`/api/org/context`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/org/context/route.ts) | GET, POST |
| [`/api/org-tokens/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/org-tokens/[id]/route.ts) | DELETE |
| [`/api/org-tokens`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/org-tokens/route.ts) | GET, POST |
| [`/api/org-triage-rules/[id]/revoke`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/org-triage-rules/[id]/revoke/route.ts) | POST |
| [`/api/policy/agent-rules/impact`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/policy/agent-rules/impact/route.ts) | POST |
| [`/api/policy/agent-rules`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/policy/agent-rules/route.ts) | POST |
| [`/api/policy/impact`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/policy/impact/route.ts) | POST |
| [`/api/policy`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/policy/route.ts) | POST |
| [`/api/projects/[id]/api-keys/[keyId]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/api-keys/[keyId]/route.ts) | DELETE, PATCH |
| [`/api/projects/[id]/api-keys`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/api-keys/route.ts) | GET, POST |
| [`/api/projects/[id]/azure-devops`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/azure-devops/route.ts) | GET, POST, DELETE |
| [`/api/projects/[id]/azure-devops/test`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/azure-devops/test/route.ts) | POST |
| [`/api/projects/[id]/bitbucket`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/bitbucket/route.ts) | GET, POST, DELETE |
| [`/api/projects/[id]/bitbucket/test`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/bitbucket/test/route.ts) | POST |
| [`/api/projects/[id]/cleanup-prevention`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/cleanup-prevention/route.ts) | POST |
| [`/api/projects/[id]/cleanup-prs`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/cleanup-prs/route.ts) | POST |
| [`/api/projects/[id]/controls/[controlId]/protect`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/controls/[controlId]/protect/route.ts) | POST |
| [`/api/projects/[id]/debt`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/debt/route.ts) | GET |
| [`/api/projects/[id]/defense`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/defense/route.ts) | GET |
| [`/api/projects/[id]/discord`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/discord/route.ts) | GET, POST, DELETE |
| [`/api/projects/[id]/github-config`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/github-config/route.ts) | PATCH |
| [`/api/projects/[id]/github-health/retry`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/github-health/retry/route.ts) | POST |
| [`/api/projects/[id]/github-health`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/github-health/route.ts) | GET |
| [`/api/projects/[id]/github-link-existing`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/github-link-existing/route.ts) | POST |
| [`/api/projects/[id]/github-workflow-pr`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/github-workflow-pr/route.ts) | POST |
| [`/api/projects/[id]/gitlab`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/gitlab/route.ts) | GET, POST, DELETE |
| [`/api/projects/[id]/investigate`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/investigate/route.ts) | POST |
| [`/api/projects/[id]/owner`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/owner/route.ts) | PUT |
| [`/api/projects/[id]/rotate`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/rotate/route.ts) | POST |
| [`/api/projects/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/route.ts) | PATCH, DELETE |
| [`/api/projects/[id]/slack`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/slack/route.ts) | GET, POST, DELETE |
| [`/api/projects/[id]/suppressions/revoke`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/suppressions/revoke/route.ts) | POST |
| [`/api/projects/[id]/suppressions`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/[id]/suppressions/route.ts) | GET |
| [`/api/projects/bulk-delete`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/bulk-delete/route.ts) | POST |
| [`/api/projects`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/projects/route.ts) | GET, POST |
| [`/api/provenance/audit`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/provenance/audit/route.ts) | GET |
| [`/api/provenance/risk-intersection`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/provenance/risk-intersection/route.ts) | POST |
| [`/api/report/complete`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/report/complete/route.ts) | POST |
| [`/api/report/contract`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/report/contract/route.ts) | GET |
| [`/api/report/init`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/report/init/route.ts) | POST |
| [`/api/report`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/report/route.ts) | POST |
| [`/api/review-exposure/backfill`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/review-exposure/backfill/route.ts) | POST |
| [`/api/scan`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scan/route.ts) | POST |
| [`/api/scans/[id]/agent-approvals`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/agent-approvals/route.ts) | POST |
| [`/api/scans/[id]/export`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/export/route.ts) | GET |
| [`/api/scans/[id]/file`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/file/route.ts) | GET |
| [`/api/scans/[id]/findings`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/findings/route.ts) | GET |
| [`/api/scans/[id]/override`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/override/route.ts) | POST |
| [`/api/scans/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/route.ts) | DELETE |
| [`/api/scans/[id]/share`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/[id]/share/route.ts) | POST, DELETE |
| [`/api/scans/compare`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/scans/compare/route.ts) | POST |
| [`/api/shadow/reports`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/shadow/reports/route.ts) | POST |
| [`/api/sso/lookup`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sso/lookup/route.ts) | POST |
| [`/api/sso/membership`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sso/membership/route.ts) | POST |
| [`/api/sso/settings`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sso/settings/route.ts) | GET, POST |
| [`/api/sync/agent-guardrails/events`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sync/agent-guardrails/events/route.ts) | POST |
| [`/api/sync/agent-guardrails`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sync/agent-guardrails/route.ts) | POST |
| [`/api/sync/config`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sync/config/route.ts) | GET |
| [`/api/sync/rules`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sync/rules/route.ts) | GET |
| [`/api/sync/suppressions`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sync/suppressions/route.ts) | GET |
| [`/api/sync/whoami`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/sync/whoami/route.ts) | GET |
| [`/api/team/activity`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/team/activity/route.ts) | GET |
| [`/api/team/invite/accept`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/team/invite/accept/route.ts) | POST |
| [`/api/team/invite/decline`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/team/invite/decline/route.ts) | POST |
| [`/api/team/invite`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/team/invite/route.ts) | GET, POST, DELETE |
| [`/api/team/invite-controls`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/team/invite-controls/route.ts) | GET, PATCH |
| [`/api/team/members`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/team/members/route.ts) | GET, PATCH, DELETE |
| [`/api/teams/[id]/aliases`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/teams/[id]/aliases/route.ts) | POST, DELETE |
| [`/api/teams/[id]/members`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/teams/[id]/members/route.ts) | POST, DELETE |
| [`/api/teams/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/teams/[id]/route.ts) | PATCH |
| [`/api/teams/from-codeowners`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/teams/from-codeowners/route.ts) | POST |
| [`/api/teams`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/teams/route.ts) | POST |
| [`/api/trends`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/trends/route.ts) | GET |
| [`/api/v1/audit-events`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/audit-events/route.ts) | GET |
| [`/api/v1/exceptions`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/exceptions/route.ts) | GET |
| [`/api/v1/issues`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/issues/route.ts) | GET |
| [`/api/v1/openapi.json`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/openapi.json/route.ts) | GET |
| [`/api/v1/posture`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/posture/route.ts) | GET |
| [`/api/v1/projects/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/projects/[id]/route.ts) | GET |
| [`/api/v1/projects`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/projects/route.ts) | GET |
| [`/api/v1/scans/[id]/findings`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/scans/[id]/findings/route.ts) | GET |
| [`/api/v1/scans/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/scans/[id]/route.ts) | GET |
| [`/api/v1/scans`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/scans/route.ts) | GET |
| [`/api/v1/verdicts`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/v1/verdicts/route.ts) | GET |
| [`/api/verdicts/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/verdicts/[id]/route.ts) | GET |
| [`/api/verify`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/verify/route.ts) | POST |
| [`/api/vulnhunter/jobs/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/vulnhunter/jobs/[id]/route.ts) | GET |
| [`/api/vulnhunter/key`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/vulnhunter/key/route.ts) | GET, PUT, DELETE |
| [`/api/vulnhunter/progress`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/vulnhunter/progress/route.ts) | POST |
| [`/api/vulnhunter/results`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/vulnhunter/results/route.ts) | POST |
| [`/api/vulnhunter/scans`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/vulnhunter/scans/route.ts) | POST |
| [`/api/vulnhunter/worker`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/vulnhunter/worker/route.ts) | POST |
| [`/api/webhooks/[id]`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/webhooks/[id]/route.ts) | DELETE |
| [`/api/webhooks/[id]/test`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/webhooks/[id]/test/route.ts) | POST |
| [`/api/webhooks`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/webhooks/route.ts) | GET, POST |
| [`/api/workspace/deletion`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/workspace/deletion/route.ts) | GET, POST, DELETE |
| [`/api/workspace/retention`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/workspace/retention/route.ts) | GET, POST |
| [`/api/workspaces`](/Users/oha/skylos-cloud/skylos-cloud/src/app/api/workspaces/route.ts) | POST |
