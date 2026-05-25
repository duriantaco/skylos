<div align="center">
    <img src="../../assets/DOG_1.png" alt="Skylos" width="260">
    <h1>Skylos</h1>
    <h3>Open Source, lokal zuerst: Prüfungen auf toten Code, Sicherheitsprobleme, Secrets, Qualitätsregressionen und AI-Code-Fehler vor dem Merge.</h3>
</div>

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
[![PyPI version](https://img.shields.io/pypi/v/skylos)](https://pypi.org/project/skylos/)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)
[![Astronomer Trust](https://img.shields.io/badge/Astronomer%20Trust-A-brightgreen?style=flat&logo=github&logoColor=white)](#star-authenticity-audit)
[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.gg/Ftn9t9tErf)

[Website](https://skylos.dev) |
[Docs](https://docs.skylos.dev) |
[Repo Map](https://duriantaco.github.io/skylos/repo-map/) |
[Quick Start](https://docs.skylos.dev/quick-start) |
[GitHub Action](../../action.yml) |
[VS Code Extension](../../editors/vscode/README.md) |
[Real-World Results](../../REAL_WORLD_RESULTS.md) |
[Benchmarks](../../BENCHMARK.md) |
[Roadmap](../../ROADMAP.md) |
[Contributing](../../CONTRIBUTING.md)

[English](../../README.md) | **Deutsch** | [简体中文](./README.zh-CN.md) | [Translations](./README.md)

## Was ist Skylos?

Skylos ist eine Open-Source-CLI für statische Analyse in Python-, TypeScript-,
JavaScript-, Java-, Go-, PHP-, Rust-, Dart-, C#- und Shell-Repositories.
Skylos läuft standardmäßig lokal und kann auch als CI/CD-PR-Gate verwendet
werden.

Nutze Skylos, wenn du mit einem Befehl ein Repository oder einen Pull Request
prüfen möchtest auf:

- toten Code und ungenutzte Dateien
- Sicherheitslücken und gefährliche Datenflüsse
- Secrets und Dependency-CVEs
- Qualitätsregressionen wie Komplexität, doppelte Branches und tiefe
  Verschachtelung
- typische Fehler in AI-generiertem Code, etwa fehlende Guards oder erfundene
  Helper
- Risiken in LLM-Apps, etwa unsichere Tool-Nutzung und fehlende
  Ausgabevalidierung

## Start in 60 Sekunden

```bash
pip install skylos
skylos .
```

Der Standardscan fokussiert sich auf toten Code. Mit `-a` aktivierst du
zusätzlich Security-, Secret-, Quality- und Dependency-Prüfungen:

```bash
skylos . -a
```

Erzeuge eine Projektkonfiguration mit Grenzwerten, Ignorierregeln,
Template-Hooks und Erweiterungen für Vibe-Wörterbücher:

```bash
skylos init
```

Erzeuge ein lokales Starter-Rule-Pack:

```bash
skylos rules init
skylos rules validate .skylos/rules/local.yml
skylos rules list --json
skylos rules list cross --json
skylos rules list --packs --json
skylos cache stats
```

Erzeuge ein GitHub-Actions-PR-Gate:

```bash
skylos cicd init
git add .github/workflows/skylos.yml
git commit -m "Add Skylos CI gate"
git push
```

Mehr Befehle stehen in der [CLI Reference](https://docs.skylos.dev/cli-reference).

## Häufige Workflows

| Ziel | Befehl | Ergebnis | Details |
|:---|:---|:---|:---|
| Erster Dead-Code-Scan | `skylos .` | Findet ungenutzte Funktionen, Klassen, Imports, Dateien und Fehler bei Framework-Entrypoints | [Dead-code docs](https://docs.skylos.dev/dead-code-detection) |
| Security- und Quality-Audit | `skylos . -a` | Aktiviert gefährliche Datenflüsse, Secrets, Dependencies und Quality-Prüfungen | [Security docs](https://docs.skylos.dev/security-analysis) |
| PR-Gate | `skylos cicd init` | Erzeugt einen GitHub-Actions-Workflow mit Annotationen und Failure-Thresholds | [CI/CD guide](https://docs.skylos.dev/ci-cd) |
| Lesbarer Terminalreport | `skylos . --format pretty` | Gruppiert Findings nach Datei, mit Severity, Snippets und kopierbaren `file:line`-Positionen | [CLI output modes](../cli-output.md) |
| Interaktive Terminaltriage | `skylos . --tui` | Öffnet eine tastaturgesteuerte Ansicht für Kategorien, Findings und Details | [CLI output modes](../cli-output.md) |
| IDE- und Testscript-Ausgabe | `skylos --format concise src/test.py` | Gibt nur `file:line`-Findings aus und endet mit Non-Zero-Exit, wenn Findings existieren | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| Review geänderter Zeilen | `skylos . -a --diff origin/main` | Fokussiert Findings auf aktive Arbeit statt auf Legacy-Schulden | [Quality gate docs](https://docs.skylos.dev/quality-gate) |
| Laufzeitgestützter Dead-Code-Check | `skylos . --trace` | Nutzt Runtime-Traces, um False Positives bei dynamischem Code zu reduzieren | [Smart tracing](https://docs.skylos.dev/smart-tracing) |
| Lokales Rule-Pack | `skylos rules init` | Erstellt YAML-Regeln für projektspezifische Security- und Quality-Prüfungen | [Custom rules](https://docs.skylos.dev/custom-rules) |
| AI-gestütztes Review | `skylos agent scan .` | Statische Analyse plus optionales LLM-Review und Fix-Vorschläge | [AI features](https://docs.skylos.dev/ai-features) |
| LLM-App-Defense | `skylos defend .` | Findet fehlende AI-App-Guardrails, gemappt auf OWASP-LLM-Risiken | [AI defense](https://docs.skylos.dev/ai-defense) |
| Technical-Debt-Triage | `skylos debt .` | Sortiert Hotspots und Debt-Trends | [Technical debt](https://docs.skylos.dev/technical-debt) |

## Was Skylos findet

| Kategorie | Beispiele | Warum es wichtig ist |
|:---|:---|:---|
| Toter Code | ungenutzte Funktionen, Klassen, Imports, Paket-Entrypoints, Route-Handler | reduziert Wartungskosten, ohne dynamische Frameworks unnötig zu beschädigen |
| Sicherheitsprobleme | SQL Injection, XSS, SSRF, Path Traversal, Command Injection, unsichere Deserialisierung | findet ausnutzbare Pfade, bevor Code in `main` landet |
| Secrets | API-Keys, Tokens, private Credentials, Strings mit hoher Entropie | verhindert, dass Credentials über Commits und PRs leaken |
| CI/CD-Workflows | gefährliche GitHub-Actions- und GitLab-CI-Trigger, unpinned Actions/Includes, breite Tokens, OIDC-Missbrauch, Cache Poisoning, mutable Images | reduziert Supply-Chain-Risiken in CI/CD vor Release-Jobs |
| Qualitätsregressionen | Komplexität, tiefe Verschachtelung, doppelte Branches, lange Funktionen, inkonsistente Returns | verhindert, dass AI-gestützte Refactorings fragilen Code erzeugen |
| AI-Code-Fehler | erfundene Security-Calls, fehlende Decorators, unfertige Stubs, deaktivierte Controls, Netzwerkaufrufe ohne Timeouts | findet häufige halluzinierte oder unvollständige Codepfade |
| LLM-App-Risiken | unsichere Tool-Nutzung, Prompt-Injection-Exposition, fehlende Ausgabevalidierung, fehlende Rate Limits | hilft Teams, AI-Features mit Guardrails zu veröffentlichen |

Siehe die vollständige [Rules Reference](https://docs.skylos.dev/rules-reference).

## Wie Skylos einzuordnen ist

Skylos ersetzt nicht jeden spezialisierten Scanner. Es ist ein lokaler Repo-
und PR-Checker, der mehrere häufige Review-Prüfungen hinter einer CLI bündelt.

- **Framework-aware Dead-Code-Erkennung:** FastAPI, Django, Flask, pytest,
  SQLAlchemy, Next.js, React, Paket-Entrypoints und gängige Plugin-Muster.
- **PR-fokussierte Ausgabe:** Diff-Scanning, CI-Grenzwerte,
  GitHub-Annotationen und Baselines für bestehende Findings.
- **Local-first-Betrieb:** Die Kernanalyse benötigt keinen Cloud-Upload und
  keine LLM-Aufrufe.
- **Review AI-gestützter Änderungen:** prüft auf entfernte Validierung, Auth,
  Logging, CSRF, Rate Limiting, Timeouts und andere Guards in generiertem oder
  editiertem Code.
- **Projektspezifische Regeln:** lokale YAML-Regeln sowie erweiterbare Prompt-,
  Credential-, Sensitive-File- und Timeout-Wörterbücher über Config.
- **Eine CLI-Oberfläche:** Dead Code, Security, Secrets, Dependencies, Quality,
  Technical Debt, Agent Review und AI Defense nutzen dieselbe CLI.

## Installation

```bash
# Kernanalyse
pip install skylos

# LLM-gestützte Agent-Workflows
pip install "skylos[llm]"

# Alle veröffentlichten optionalen Extras
pip install "skylos[all]"
```

Container-Image:

```bash
docker pull ghcr.io/duriantaco/skylos:latest
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest . --json --no-provenance
```

Quellinstallation, Container-Nutzung und optionale Dependencies stehen in der
[Installation](https://docs.skylos.dev/installation).

## Templates und Vibe-Checks konfigurieren

`skylos init` ergänzt diese Abschnitte in `pyproject.toml`:

```toml
[tool.skylos.templates]
# security = ".skylos/templates/security.md"
# quality = ".skylos/templates/quality.md"
# security_audit = ".skylos/templates/security_audit.md"
# review = ".skylos/templates/review.md"

[tool.skylos.vibe]
extra_phantom_names = ["verify_enterprise_auth"]
extra_phantom_decorators = ["tenant_admin_required"]
extra_credential_names = ["tenant_signing_secret"]
extra_network_timeout_calls = ["vendor_sdk.fetch"]
```

Template-Dateien erweitern die eingebauten Prompts von Skylos. Sie ersetzen
nicht den JSON-only-Ausgabevertrag und nicht die Sicherheitsregeln für
untrusted code. Vibe-Wörterbücher helfen Teams, Skylos lokale Fake-Auth-Helper,
projektspezifische Credential-Namen, sensible Dateien und Netzwerkaufrufe mit
Timeout-Pflicht beizubringen.

## Sprachunterstützung

| Sprache | Dead Code | Security | Quality | Hinweise |
|:---|:---:|:---:|:---:|:---|
| Python | Ja | Ja | Ja | stärkste Abdeckung; framework-aware statische Analyse und optionales Tracing |
| TypeScript / JavaScript | Ja | Ja | Ja | Tree-sitter-Parsing, Paketgraph-Reachability, Framework-Konventionen |
| Java | Ja | Ja | Ja | Tree-sitter-Parsing und strukturierte Security-Flow-Analyse |
| Go | Ja | Teilweise | Teilweise | Dead-Code- und ausgewählte Security-Benchmark-Abdeckung |
| PHP | Ja | Ja | Teilweise | PHP-Parser-Abdeckung plus taint-artige Security-Sinks und -Sources |
| Rust | Ja | Ja | Teilweise | Rust-Parser-Abdeckung plus Security-Sink/Source-Prüfungen |
| Dart | Ja | Ja | Teilweise | Dart-Parser-Abdeckung plus ausgewählte Security-Sinks und -Sources |
| C# | Ja | Ja | Teilweise | C#-Symbolabdeckung plus ausgewählte ASP.NET-, Process-, SQL-, HTTP- und File-Sinks |
| Shell | Nein | Ja | Teilweise | Shell-Script-Security-Prüfungen für Command Injection, SSRF und Path Traversal |

Regelfamilien und Scanner-Scope stehen in der
[Rules Reference](https://docs.skylos.dev/rules-reference).

## Benchmark-Snapshot

Skylos enthält Regression-Benchmarks für Dead Code, Security, Quality und
Agent Review. Diese sind strikte Regression-Gates, kein umfassender Beweis,
dass ein Tool in jeder Situation State of the Art ist.

| Suite | Aktuelles Skylos-Ergebnis | Baseline |
|:---|:---|:---|
| Dead-code regression | 16 cases, TP=36 FP=0 FN=0 TN=59, score 100.0 | Ruff score 62.67; Vulture im letzten lokalen Rerun nicht installiert |
| Security regression | 56 cases, TP=35 FP=0 FN=0 TN=23, score 100.0 | Bandit score 47.14 auf Python-anwendbaren Cases |
| Quality regression | 13 cases, score 100.0 | nur Regression-Gate |
| Agent review | 25 cases, score 100.0 | nur Regression-Gate |

Highlights aus `golden-v0.2`:

| Frozen Suite | Skylos-Ergebnis | Hinweis |
|:---|:---|:---|
| Dead code seeded dev | overall score 96.28; TS/JS/Go/Java score 100.0; Python score 93.33 | Python-Restpunkte sind Label-Review-Themen |
| Security seeded dev | overall score 96.52; vollständige Recall mit einem Python-`urljoin`-False-Positive | Label sollte geprüft werden |
| OWASP Java security dev | TP=105 FP=0 FN=15 TN=120, score 94.37 | request-wrapper-, LDAP-, XPath- und property-weak-hash-Lücken bleiben |
| Quality seeded dev | TP=1 FP=0 FN=0 TN=1, score 100.0 | aktuell nur ein seeded case |

Methodik, Befehle, Vergleichszeilen und Caveats stehen in
[BENCHMARK.md](../../BENCHMARK.md).

## Projektnachweise

Skylos-unterstützte Dead-Code-Cleanup-PRs wurden in
[Black](https://github.com/psf/black/pull/5041),
[NetworkX](https://github.com/networkx/networkx/pull/8572),
[Optuna](https://github.com/optuna/optuna/pull/6547),
[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136),
[pypdf](https://github.com/py-pdf/pypdf/pull/3685),
[beets](https://github.com/beetbox/beets/pull/6473) und
[Flagsmith](https://github.com/Flagsmith/flagsmith/pull/6953) gemerged. Das
sind akzeptierte Cleanup-PRs, keine Empfehlungen oder Endorsements dieser
Projekte. Siehe [Real-World Results](../../REAL_WORLD_RESULTS.md).

<a id="star-authenticity-audit"></a>

Ein lokaler Astronomer-Scan vom 26. April 2026 zählte 420 Stargazer und gab
**overall trust: A** zurück. StarGuard meldete außerdem **low fake-star risk**.

## Integrationen

| Integration | Link | Zweck |
|:---|:---|:---|
| GitHub Action | [GitHub Action](../../action.yml) | PR-Gates, Annotationen und CI-Enforcement |
| VS Code Extension | [VS Code extension](../../editors/vscode/README.md) | Findings im Editor und AI-gestützte Fixes |
| MCP server | [MCP setup](https://docs.skylos.dev/mcp-server) | Skylos-Scans für AI Agents und Coding Assistants bereitstellen |
| Docker image | [Installation](https://docs.skylos.dev/installation) | Skylos ohne lokale Python-Installation ausführen |
| Skylos Cloud | [Cloud workflow](https://docs.skylos.dev/cloud-workflow) | optionale Upload- und Dashboard-Workflows |

GitHub-Actions-Workflow über die CLI erzeugen:

```bash
skylos cicd init --upload
skylos cicd init --upload --scan-path apps/api
```

Der erzeugte Upload-Workflow nutzt GitHub OIDC, sendet PR-Head-Commit- und
Branch-Metadaten und unterstützt Monorepo-Subprojekte über `--scan-path`.

## Dokumentationskarte

| Bedarf | Dokument |
|:---|:---|
| Installation, Quellinstallation und Docker | [Installation](https://docs.skylos.dev/installation) |
| Erster Scan und Kernworkflows | [Quick Start](https://docs.skylos.dev/quick-start) |
| CLI-Befehle, Flags und Beispiele | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| CLI-Ausgabemodi, Pretty Reports und TUI-Steuerung | [CLI Output Modes](../cli-output.md) |
| CI-Setup, PR-Gates, Annotationen und Branch Protection | [CI/CD](https://docs.skylos.dev/ci-cd) |
| Dead-Code-Verhalten und Framework-Awareness | [Dead Code Detection](https://docs.skylos.dev/dead-code-detection) |
| Security-Scanning und Taint-Analyse | [Security Analysis](https://docs.skylos.dev/security-analysis) |
| Rule-ID-Präfixe und Produktterminologie | [Rule Dictionary](../../dictionary.md) |
| Agent Scan, Verifikation, Remediation und Modellsetup | [AI Features](https://docs.skylos.dev/ai-features) |
| AI-Defense-Prüfungen und LLM-Guardrails | [AI Defense](https://docs.skylos.dev/ai-defense) |
| MCP-Server-Setup | [MCP Server](https://docs.skylos.dev/mcp-server) |
| Real-world gemergte Cleanup-PRs | [Real-World Results](../../REAL_WORLD_RESULTS.md) |
| Baselines, Filtering, Suppressions und Whitelists | [Configuration](https://docs.skylos.dev/configuration) |
| Smart Tracing | [Smart Tracing](https://docs.skylos.dev/smart-tracing) |
| Regelfamilien und Sprachunterstützung | [Rules Reference](https://docs.skylos.dev/rules-reference) |
| Cloud-Uploads und Dashboard-Flow | [CLI to Dashboard](https://docs.skylos.dev/cloud-workflow) |
| VS Code Extension | [VS Code Extension](https://docs.skylos.dev/vscode) |
| Benchmarks und Methodik | [BENCHMARK.md](../../BENCHMARK.md) |
| Security Policy | [SECURITY.md](../../SECURITY.md) |
| Release-Prozess | [RELEASE_WORKFLOW.md](../../RELEASE_WORKFLOW.md) |
| Contribution-Prioritäten | [ROADMAP.md](../../ROADMAP.md) |
| Contributing | [CONTRIBUTING.md](../../CONTRIBUTING.md) |

## Häufige Fragen

**Ersetzt Skylos Bandit, Semgrep, CodeQL oder Vulture?**

Nein. Skylos kann parallel zu diesen Tools laufen. Der Fokus liegt auf
framework-aware Dead-Code-Signal, PR-Gating, AI-era Regression Checks und einem
kombinierten Workflow für Dead Code, Security, Secrets und Quality.

**Benötigt Skylos ein LLM?**

Nein. Die Kernanalyse läuft lokal ohne API Keys. LLM-Funktionen sind optional
über `skylos[llm]` und Agent-Befehle.

**Kann ich nur geänderten Code prüfen?**

Ja. Lokal mit `skylos . -a --diff origin/main` oder in CI-Gates, die auf neue
Findings fokussieren.

**Wie gehe ich mit absichtlich dynamischem Code um?**

Nutze Baselines, Whitelists, Inline-Suppressions oder Runtime-Tracing. Siehe
[configuration docs](https://docs.skylos.dev/configuration) und
[smart tracing docs](https://docs.skylos.dev/smart-tracing).

## Mitwirken und Support

- Sicherheitsprobleme über [SECURITY.md](../../SECURITY.md) melden.
- Bugs und False Positives mit minimaler Reproduktion öffnen.
- [ROADMAP.md](../../ROADMAP.md) für sinnvolle Contribution-Bereiche prüfen.
- Vor Pull Requests [CONTRIBUTING.md](../../CONTRIBUTING.md) lesen.
- [QUALITY.md](../../QUALITY.md) beschreibt Qualitäts- und Gate-Erwartungen.
- Für Community-Support dem [Discord](https://discord.gg/Ftn9t9tErf) beitreten.

## Lizenz

Skylos steht unter der [Apache License 2.0](../../LICENSE).

<!-- mcp-name: io.github.duriantaco/skylos -->
