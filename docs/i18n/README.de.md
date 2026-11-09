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
JavaScript-, Java-, Go-, PHP-, Rust-, Ruby-, Dart-, C#-, C++-, Kotlin- und
Shell-Repositories. Python, TypeScript/JavaScript und Java haben die tiefste
Abdeckung; die Tabelle unter Sprachunterstützung zeigt die übrigen Sprachen.
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
skylos .            # Probleme finden; Code und Funde bleiben auf deinem Rechner
skylos cloud        # optional: Ergebnisse pro Branch in Skylos Cloud verfolgen
skylos cicd init    # jedem Pull Request eine Skylos-Prüfung hinzufügen
```

Mit einem Coding-Agenten reichen zwei Befehle:

```bash
skylos setup   # einmal pro Repository: verbindet Claude Code und Codex, installiert ihre Hooks, lässt Done die Tests ausführen, schreibt die PR-Prüfung, kartiert den Code
skylos open    # jeden Tag: Diagramm des Codes, Änderungen in einfacher Sprache, jeder Prüflauf
```

Dein Agent führt die Prüfungen selbst aus. Das [Tutorial](../workflow.md) zeigt
eine echte Sitzung: Der Agent beschreibt den Code, ändert ihn, wird blockiert
und behebt das Problem anhand der Fix-Anleitung von Skylos.

`skylos cloud` führt alle Prüfungen aus, zeigt die Funde, lädt sie hoch und
zeigt das Quality Gate dieses Branches mit einem Link:

```text
✗ Quality gate on feat/login: FAILED (was PASSED on 24 Oct 15:38 UTC, 1ba9895) · 1 critical security issue
  Open: https://skylos.dev/dashboard/projects/<project>?branch=feat%2Flogin
  Sent: findings and the Done receipt (fail) · laptop upload, unverified until CI runs the workflow
  Next: fix the issues behind the failed gate, then run skylos cloud again.
```

Beim ersten Mal öffnet sich der Browser zum Anmelden und zur Projektauswahl.
Gesendet werden die Funde mit Dateipfaden und Codeausschnitten von bis zu 7
Zeilen (keine bei Secrets), Branch, Commit, die Git-Autor-E-Mail jeder
markierten Zeile und eine Übersicht deiner Funktionen und Klassen (Namen,
Dateien, Zeilen, Größe, wer wen aufruft). Nicht dein Repository. Hat das
Repository eine committete `[tool.skylos.done]`-Tabelle (`skylos setup`
schreibt sie) und einen sauberen Arbeitsbaum, geht auch der Done-Beleg dieses
Commits mit (ohne Beleg läuft `skylos done` zuerst); die Zeile `Sent:` sagt,
was Skylos Cloud erreicht hat. Uploads vom Laptop gelten als unverifiziert,
bis CI den Workflow ausführt. Der Exit-Code
ist auch bei fehlgeschlagenem Skylos-Cloud-Gate `0`; mit `--gate` ist er `1`
(für CI). Einen Schlüssel
zum Bestehen des Gates brauchst du nie: Behebe die Funde, die es blockieren.
Mehr dazu: [Skylos Cloud](../skylos-cloud.md).

Der Standardscan fokussiert sich auf toten Code. Mit `-a` aktivierst du
zusätzlich Security-, Secret-, Quality- und Dependency-Prüfungen:

```bash
skylos . -a
```

Erzeuge eine Projektkonfiguration mit Grenzwerten, Ignorierregeln und
Erweiterungen für Vibe-Wörterbücher:

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

Scans mit `--quality` oder `-a` wenden jedes `.yml`/`.yaml`-Pack in einem
`.skylos/rules/`-Ordner zwischen gescannter Datei und Repository-Root an. In
PR-CI kommen die Packs wie `[tool.skylos]` aus dem Base-Branch, ein Pull
Request kann seine eigenen Regeln also nicht entfernen oder ändern.

Erzeuge ein GitHub-Actions-PR-Gate:

```bash
skylos cicd init
git add .github/workflows/skylos.yml
git commit -m "Add Skylos CI gate"
git push
```

Auf GitLab CI, Jenkins, Bitbucket Pipelines, Azure Pipelines oder CircleCI
richtet derselbe Befehl das Gate für dieses CI ein; siehe
[Skylos on any CI](../ci-platforms.md).

Mehr Befehle stehen in der [CLI Reference](https://docs.skylos.dev/cli-reference).

## Häufige Workflows

| Ziel | Befehl | Ergebnis | Details |
|:---|:---|:---|:---|
| Erster Dead-Code-Scan | `skylos .` | Findet ungenutzte Funktionen, Klassen, Imports, Dateien und Fehler bei Framework-Entrypoints | [Dead-code docs](https://docs.skylos.dev/dead-code-detection) |
| Security- und Quality-Audit | `skylos . -a` | Aktiviert gefährliche Datenflüsse, Secrets, Dependencies und Quality-Prüfungen | [Security docs](https://docs.skylos.dev/security-analysis) |
| Einseitiger Bericht zum Teilen | `skylos report .` | Schreibt `skylos-report.html`: Urteil („Not ready: 1 blocking issue“), die fünf zuerst zu behebenden Risiken mit Fix und Doku-Link, Zahlen pro Kategorie, Unterdrücktes und nicht Geprüftes; nichts wird hochgeladen | [CLI output modes](../cli-output.md) |
| KI-Gegenprüfung der Findings | `skylos . -a --ai-review` | Dead-Code-Findings in jeder Sprache und Security-Findings in Python-Dateien bekommen ein KI-Urteil: bestätigt, KI widerspricht oder unsicher. Nichts wird ausgeblendet, das Gate ändert sich nie; mit `skylos cloud --ai-review` erscheinen die Urteile in Skylos Cloud | [AI review](../ai-review.md) |
| Optionales Python-Linting | `pip install "skylos[lint]" && skylos lint .` | Führt Ruff mit nativer Konfiguration, Ausgabe, Fixes und Exit-Codes über die Skylos-CLI aus | [Python linting](../python-linting.md) |
| PR-Gate | `skylos cicd init` | Richtet das PR-Gate für dein CI ein: einen GitHub-Actions-Workflow mit Annotationen und Failure-Thresholds, oder ein Gate für GitLab CI, Jenkins, Bitbucket Pipelines, Azure Pipelines und CircleCI | [CI/CD guide](https://docs.skylos.dev/ci-cd) |
| Lesbarer Terminalreport | `skylos . --format pretty` | Gruppiert Findings nach Datei, mit Severity, Snippets und kopierbaren `file:line`-Positionen | [CLI output modes](../cli-output.md) |
| Interaktive Terminaltriage | `skylos . --tui` | Öffnet eine tastaturgesteuerte Ansicht für Kategorien, Findings und Details | [CLI output modes](../cli-output.md) |
| IDE- und Testscript-Ausgabe | `skylos --format concise src/test.py` | Gibt nur `file:line`-Findings aus und endet mit Non-Zero-Exit, wenn Findings existieren | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| Change Map fürs Review | `skylos done map --base origin/main` | Zeigt jede geänderte Python- oder TypeScript/JavaScript-Funktion mit altem und neuem Code, hinzugefügten und entfernten Aufrufen, ihren Aufrufern, entfernten Sicherheitsprüfungen und dem, was zuerst zu lesen ist; aus dem Code berechnet, nicht von einem Modell geschrieben | [Change map](../change-map.md) |
| Codebase-Graph | `skylos graph open` | Zeigt jede Python- und TypeScript/JavaScript-Funktion und -Klasse (Go, Java, Rust und PHP als erster Schritt, Aufrufe nach Namen zugeordnet), gruppiert in Bereiche, wer was aufruft, Tests und ihre erwarteten Ausgaben in einer lokalen Browseransicht; markiert geänderten Code und sagt, ob die Logik gleich geblieben ist (nur wenn bewiesen). Beschreibungen in einfachem Englisch schreibt Ihr Coding-Agent, Ihr eigener Modell-Key oder Skylos gegen Credits; Skylos Cloud kann zu jedem Pull Request einen Kommentar zu Logikänderungen posten. `skylos done map` sortiert jede Änderung in „zuerst lesen“, „lesen“, „überfliegen“ und „überspringen“ (nur bei bewiesen gleicher Logik); die MCP-Tools dafür brauchen keinen Key | [Codebase graph](../graph.md) |
| Review geänderter Zeilen | `skylos . -a --diff origin/main` | Fokussiert Findings auf aktive Arbeit statt auf Legacy-Schulden | [Quality gate docs](https://docs.skylos.dev/quality-gate) |
| Laufzeitgestützter Dead-Code-Check | `skylos . --trace` | Nutzt Runtime-Traces, um False Positives bei dynamischem Code zu reduzieren | [Smart tracing](https://docs.skylos.dev/smart-tracing) |
| Lokales Rule-Pack | `skylos rules init` | Erstellt `.skylos/rules/local.yml`, projektspezifische YAML-Prüfungen, die Scans mit `--quality` und `-a` anwenden | [Custom rules](https://docs.skylos.dev/custom-rules) |
| AI-gestütztes Review | `skylos agent scan .` | Statische Analyse plus optionales LLM-Review und Fix-Vorschläge | [AI features](https://docs.skylos.dev/ai-features) |
| LLM-App-Defense | `skylos defend .` | Findet fehlende AI-App-Guardrails, gemappt auf OWASP-LLM-Risiken | [AI app safety](https://docs.skylos.dev/ai-defense) |
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
  Technical Debt, Agent Review und AI app safety nutzen dieselbe CLI.

## Installation

```bash
# Kernanalyse
pip install skylos

# LLM-gestützte Agent-Workflows
pip install "skylos[llm]"

# Ruff-Python-Linting über `skylos lint`
pip install "skylos[lint]"

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

## Vibe-Checks konfigurieren

`skylos init` ergänzt diesen Abschnitt in `pyproject.toml`:

```toml
[tool.skylos.vibe]
extra_phantom_names = ["verify_enterprise_auth"]
extra_phantom_decorators = ["tenant_admin_required"]
extra_credential_names = ["tenant_signing_secret"]
extra_network_timeout_calls = ["vendor_sdk.fetch"]
```

LLM-Prompt-Templates liest Skylos nicht aus dem Repository: Übergib eine
vertrauenswürdige Datei mit `--prompt-template KIND=PATH` an `skylos agent
scan`, `agent audit`, `agent security-quick` oder `agent security-deep`. Ein
Template erweitert den eingebauten Prompt; es ersetzt weder den
JSON-only-Ausgabevertrag noch die Sicherheitsregeln für untrusted code.
Vibe-Wörterbücher helfen Teams, Skylos lokale Fake-Auth-Helper,
projektspezifische Credential-Namen, sensible Dateien und Netzwerkaufrufe mit
Timeout-Pflicht beizubringen.

## Sprachunterstützung

| Sprache | Dead Code | Security | Quality | Hinweise |
|:---|:---:|:---:|:---:|:---|
| Python | Ja | Ja | Ja | stärkste Abdeckung; framework-aware statische Analyse und optionales Tracing |
| TypeScript / JavaScript | Ja | Ja | Ja | Tree-sitter-Parsing, Paketgraph-Reachability, Framework-Konventionen |
| Java | Ja | Ja | Ja | Tree-sitter-Parsing und strukturierte Security-Flow-Analyse |
| Go | Ja¹ | Teilweise¹ | Teilweise | Dead-Code- und ausgewählte Security-Benchmark-Abdeckung |
| PHP | Ja | Ja | Nein | PHP-Parser-Abdeckung; Security verfolgt Request-Daten (Superglobals, Laravel/Symfony/PSR-7/CodeIgniter-Requests, Drupal Form API) innerhalb einer Funktion oder Datei bis zu Command- und Code-Ausführung, `include`, XSS über `echo`/`<?= ?>`/Blade `{!! !!}`, SQL, SSRF, `unserialize` und Dateipfaden; nicht über Funktions- oder Dateigrenzen und nicht in Twig-Templates |
| Rust | Experimentell⁴ | Teilweise | Teilweise | Rust-Parser; Command Injection, Path Traversal, direkt unerreichbare Anweisungen und doppelte Zweige |
| Ruby | Teilweise | Teilweise | Nein | Tree-sitter-Parsing; private Hilfsmethoden, eindeutig zugeordnete Aufrufe und Rails-Controller-Callbacks mit festen Namen; begrenzte Command-Injection-Prüfung für explizite `Kernel`-Aufrufe und Backticks |
| Dart | Ja³ | Teilweise³ | Nein | Dart-Parser-Abdeckung; Security prüft Command Injection, Path Traversal und SSRF |
| C# | Teilweise | Teilweise | Teilweise | C#-Symbole, unerreichbare Anweisungen in direkten Blöcken, ASP.NET-bewusste Security-Prüfung (Anfragequellen, typgebundene Senken, unsichere Deserialisierung, XSS) und NuGet-Inventarisierung (`.csproj` und `packages.lock.json`) |
| C++ | Teilweise | Nein | Nein | nur scheinbar ungenutzte dateilokale Funktionen in `.cpp`, `.cc`, `.cxx`; C++-Header werden für Referenzen gelesen |
| Kotlin | Teilweise² | Teilweise² | Nein | lexikalische Symbolerkennung; meldet nur private Deklarationen und Imports; Security-Prüfungen für Spring, Ktor, Servlets und Android-WebView |
| Swift | Teilweise | Nein | Nein | syntaxbasierte Erreichbarkeit privater und dateiprivater Deklarationen; berücksichtigt Besitzer, lokale Bindungen, Callbacks und Aufrufzyklen; unbekannte Laufzeitkontexte bleiben konservativ |
| Shell | Nein | Teilweise | Nein | Shell-Script-Security-Prüfungen für Command Injection, SSRF und Path Traversal |

¹ Dead-Code- und Security-Prüfungen für Go brauchen die native
`skylos-go`-Engine. Seit 4.50 enthalten die PyPI-Wheels für Linux, macOS und
Windows (x86_64 und arm64) sie, ebenso das Container-Image; die offizielle
GitHub Action baut sie. Auf anderen Plattformen zeigt `skylos doctor` den
Befehl zum Bauen. Ohne sie laufen nur die Go-Quality-Prüfungen, und die
Go-Dateien werden als nicht analysiert gemeldet.

² Kotlin-Dead-Code meldet nur `private` Typen und Funktionen sowie ungenutzte
Imports; jede nicht-private Deklaration gilt als verwendet. Jede Verwendung im
Code zählt: Typpositionen, `::foo`, Trailing-Lambda- und Infix-Aufrufe,
String-Templates und KDoc-Links; Imports von Operator-Konventionen
(`getValue`, `plus`, `component1`) werden nie gemeldet. Die Kotlin-Security
arbeitet lexikalisch (ohne Kotlin-Parser) mit den Java-Quellen und -Senken:
Spring-Handler-Parameter, `HttpServletRequest`, Ktor `call.parameters`,
`call.receive<T>()` und WebFlux `ServerRequest` als Eingaben; Command
Injection (SKY-D212, SKY-D203), SQL inklusive String-Templates (SKY-D211),
Path Traversal (SKY-D215), SSRF (SKY-D216), Open Redirect (SKY-D230), HTML-
Antworten (SKY-D226), `ObjectInputStream`/`XMLDecoder` (SKY-D204, SKY-D233),
XXE (SKY-D236), SpEL/JNDI (SKY-D237) sowie Android-WebView-JavaScript-Bridges
(SKY-D257) und Dateizugriff über `file://`-URLs (SKY-D258). Der Datenfluss wird
innerhalb einer Funktion oder Route-Lambda verfolgt. Die Secret-Prüfung deckt
`.kt`- und `.kts`-Dateien ab.

³ Dart-Prüfungen brauchen das optionale Extra `skylos[dart]`
(`pip install "skylos[dart]"`, benötigt einen C-Compiler). Ohne es meldet ein
Scan `.dart`-Dateien als nicht analysiert (`SKY-ANALYSIS-INCOMPLETE`).

⁴ Rust-Dead-Code ist experimentell: Trait-Methodenaufrufe, über Crates hinweg
genutzte `pub`-Elemente, Re-Exports und Makros werden nicht aufgelöst.

Inline-Unterdrückung funktioniert in jeder Sprache oben gleich:
`skylos: ignore[SKY-D211] Grund` (nur die genannten Regeln), `skylos: ignore`
(alle Regeln) oder ein Block `skylos: ignore-start` … `skylos: ignore-end` in
einem Kommentar auf der Zeile des Befunds (`#` in Python, Shell, PHP und Ruby; `//`
oder ein einzeiliges `/* */` in den anderen). Das gilt für Dead Code, Security,
Quality und Secrets; Text in einem String-Literal zählt nie, und Marker anderer
Tools (`#nosec`, `//nolint`, `NOSONAR`, `@SuppressWarnings`) blenden keine
Skylos-Befunde aus.

`--secrets` liest außerdem Shell-Skripte (auch solche ohne Endung, die mit einer
Shell-`#!`-Zeile beginnen), C- und C++-Quellen und -Header, Dockerfiles,
Terraform `.tf`/`.tfvars`/`.hcl`, `.properties`, XML, Gradle, `.npmrc` und
`.pypirc`.
Rust-Kandidaten haben höchstens Konfidenz 40, also unter dem Standard-Schwellenwert
60; sie erscheinen nur mit `--confidence 40`.

C#-Dead-Code-Funde sind konservativ: Bei einer vollständigen Analyse einer
ausführbaren oder Web-Anwendung gelten unreferenzierte öffentliche Typen und
Methoden als Kandidaten mit geringer Konfidenz. Bibliotheks-APIs, geschützte
Member sowie bekannte Framework- und konfigurierte Einstiegspunkte bleiben
extern erreichbar. Konstruktoren gelten nur dann als ungenutzte Funktionen,
wenn sie privat sind, Parameter haben und nichts sie aufruft (die Regel von
Roslyn IDE0051); Controller- und Dependency-Injection-Konstruktoren ruft das
Framework auf. Die Erreichbarkeit von C#-Quelldateien wird nicht analysiert.
Die Qualitätsprüfung erkennt Anweisungen nach einem unbedingten
`return`, `throw`, `break` oder `continue` im direkten Block, bietet aber keine
vollständige Kontrollflussanalyse. Die Sicherheitsprüfung (`--danger`) wertet
ASP.NET-Anfragedaten als Eingabe: Parameter von Controller-Actions,
Razor-Page-Handlern, Minimal APIs und `[From*]` sowie `Request.*`, nicht
Konstruktor- oder gewöhnliche Service-Parameter, und folgt ihnen in
Hilfsmethoden derselben Datei. Sie meldet SQL-Injection (ADO.NET, EF-Raw-SQL,
Dapper), Command Injection, Path Traversal, SSRF (`HttpClient`, `WebClient`,
`WebRequest`, RestSharp), Open Redirects (nicht bei `LocalRedirect` oder einer
`Url.IsLocalUrl`-Prüfung), unsichere Deserialisierung (`BinaryFormatter`-Familie,
Json.NET `TypeNameHandling`, `SimpleTypeResolver`) und XSS über
`HtmlString`/`Html.Raw`/`MarkupString` und HTML-Antworten, jeweils mit CWE.
Methoden, die nur den Namen einer Senke teilen (das `GetAsync` eines
Repositorys), zählen nur mit dem passenden Empfängertyp. Generische
Secret-Prüfungen decken `.cs`-Dateien mit `--secrets` oder `-a` ab.
`.cshtml`/`.razor`-Markup, dateiübergreifender Datenfluss und Ausdrücke in
interpolierten Raw-Strings werden von der C#-Taint-Analyse noch nicht verfolgt. SCA
inventarisiert direkte NuGet-`PackageReference`-Einträge in `.csproj`-Dateien.
Nur unbedingte, exakt festgelegte `Version`-Werte (`[version]`) ohne lokale
`Update`-/`Remove`-Änderungen werden gegen Advisories geprüft;
`VersionOverride` und zentral verwaltete Versionen nicht.
Gewöhnliche NuGet-Versionen sind Untergrenzen. Ohne aufgelöste Lockdatei
bleiben installierte Version und Schwachstellenstatus unbekannt. Mit
`packages.lock.json` (`RestorePackagesWithLockFile`) wird jedes aufgelöste
Paket je Ziel-Framework geprüft, auch transitive.

Regelfamilien und Scanner-Scope stehen in der
[Rules Reference](https://docs.skylos.dev/rules-reference).

## Abhängigkeitsdateien

Die Prüfung auf bekannte Schwachstellen in Abhängigkeiten (`--sca`, in `-a`
enthalten) liest diese Dateien als Daten und fragt OSV nach den darin
festgehaltenen exakten Versionen:

| Ökosystem | Lockdateien (alle erfassten Pakete) | Manifeste (nur exakte Versionen; Bereiche gelten als nicht aufgelöst) | Genannt, aber nicht gelesen |
|:---|:---|:---|:---|
| PyPI | `uv.lock`, `poetry.lock`, `Pipfile.lock` | `requirements.txt`, `pyproject.toml`, `setup.cfg`, `setup.py` | `Pipfile` ohne Lockdatei |
| npm | `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock` | `package.json` | `bun.lockb` |
| Go | | `go.mod` | `go.sum` vor Go 1.17 |
| Maven / Gradle | `gradle.lockfile` | `pom.xml` (Properties, lokale Parent-POMs und `<dependencyManagement>`) | `build.gradle(.kts)` ohne `gradle.lockfile` |
| crates.io | `Cargo.lock` | `Cargo.toml` (`=x.y.z`) | |
| Packagist | `composer.lock` | `composer.json` | |
| RubyGems | `Gemfile.lock` | | `Gemfile` ohne Lockdatei |
| Pub | `pubspec.lock` | `pubspec.yaml` | |
| NuGet | `packages.lock.json` | `*.csproj` (`[x.y.z]`) | |

Git-, Pfad-, SDK-, Private-Registry- und Branch-Einträge (`dev-*`) werden als
nicht geprüft aufgeführt und nie als öffentliche Pakete abgefragt. Details in
[Dependency scanning](../dependency-scanning.md).

Malware-Advisories (`MAL-*`, CWE-506, etwa die gekaperten Releases von
`chalk`, `debug` und `xrpl`) sind `CRITICAL` mit `metadata.malicious`, werden
nie als reine Dev-Abhängigkeit herabgestuft und sagen dir, das Paket zu
entfernen und alle Zugangsdaten zu rotieren, die eine Installation lesen
konnte. Derselbe Scan prüft über die ca9-Engine die Lieferkette: Dependency
Confusion für deine `internal_packages` (`SKY-SCA-SRC001`), Git-Abhängigkeiten
ohne festen Commit und URL-Abhängigkeiten ohne Hash (`SKY-SCA-SRC003`),
in Pull Requests ein Paket aus einer Quelle, die das Repository bisher nicht
verwendet hat (`SKY-SCA-SRC004`),
Lockfile-Einträge ohne Integritäts-Hash (`SKY-SCA-INT001`) und, wenn du
`min_release_age_hours` setzt, Versionen jünger als dieses Fenster
(`SKY-SCA-AGE001`). Das JSON enthält zusätzlich ein Paketinventar und eine
Lieferketten-Bewertung (Lockfile committet, eingefrorene CI-Installationen,
Install-Skripte deaktiviert, Mindestalter für Releases, gepinnte Actions, kein
`pull_request_target`-Checkout). Details in
[Supply-chain checks](../dependency-scanning.md#supply-chain-checks).

In Pull Requests (`--diff` oder `--diff-base`) lässt `--sca` das Gate auch
scheitern, wenn eine Änderung die Installationshärtung schwächt: eine
Wartezeit entfernt oder verkürzt, Install-Skripte wieder eingeschaltet,
Pakete in pnpm `allowBuilds` oder npm `allowScripts` aufgenommen, eine Action
von einem SHA auf ein Tag umgestellt (`SKY-SCA-HRD001`). Geprüfte Ausnahmen
pro Paket stehen im Basis-Branch. Mit `--review-upgrades` (in Workflows von
`skylos cicd init` eingeschaltet) wird jedes npm- oder PyPI-Upgrade alt und neu
heruntergeladen und als Daten verglichen: ein neuer Install-Hook, `.pth`- oder
`sitecustomize`-Code oder Dekodieren-und-Ausführen lässt das Gate scheitern
(`SKY-SCA-UPG001`); neue Netzwerkaufrufe beim Import oder Binärdateien werden
zur Prüfung gelistet (`SKY-SCA-UPG002`). `--danger` meldet committete Agent-
und Editor-Hooks (`SKY-D365`, `SKY-D366`: `SessionStart` in
`.claude/settings.json`, `folderOpen` in `.vscode/tasks.json`), ungepinnte,
versteckte oder imitierende MCP-Server (`SKY-D367`-`SKY-D369`), überschriebene
Agent-Basis-URLs (`SKY-D370`), Konfigurationen, deren doppelte Schlüssel verbergen, was ausgeführt wird (`SKY-D377`), und riskante Publish-Jobs (`SKY-D371`-`SKY-D376`).
Ein Scan des ganzen Repositorys listet sie; ein Pull Request, der einen Hook
hinzufügt oder ändert, scheitert. Details in
[Agent configuration and publish-job rules](../agent-config-and-publish-rules.md).

Die Agent-Hooks (`skylos agent install-hooks`) blockieren vor einer
Installation zusätzlich Versionen, die als Malware gemeldet sind, Releases,
die jünger als 48 Stunden sind (mit der älteren Version, die stattdessen
installiert werden soll), und npm-Releases ohne die Provenance ihrer
Vorgänger; Lockfile-Installationen wie `npm ci` oder `uv sync` bekommen die
Malware-Prüfung für jedes Paket. Die Wartezeit stellst du mit
`[tool.skylos.supply_chain] min_release_age_hours` ein (0 schaltet sie ab).

MCP-Server und Agent-Hooks: Der Agent-Hook blockiert ungepinnte oder bösartige
MCP-Server (`claude mcp add`, Änderungen an `.mcp.json`) und nennt den genauen
gepinnten Befehl, fragt vor neuen SessionStart- oder folderOpen-Hooks nach und
prüft konfigurierte Server in jeder Sitzung erneut. `skylos agent harden` gibt
für jeden Agenten die eigenen Einstellungen zum Sperren von Zugangsdaten und
für gepinnte MCP-Server aus (Richtlinie und Prüfung, keine Sandbox).

## Benchmark-Snapshot

Skylos enthält eingecheckte Regression-Suites für Dead Code, Security,
Quality, Agent Review und AI-Code-Fehler. Diese sind Regression-Gates, keine
unabhängigen Genauigkeitsbenchmarks. Die Fallzahlen ändern sich; die
jeweiligen Manifeste sind die aktuelle Quelle.

Methodik, datierte Ergebnisse, Vergleichszeilen und Grenzen stehen in
[BENCHMARK.md](../../BENCHMARK.md).

## Projektnachweise

Skylos-unterstützte Dead-Code-Cleanup-PRs wurden in
[Black](https://github.com/psf/black/pull/5041),
[NetworkX](https://github.com/networkx/networkx/pull/8572),
[Optuna](https://github.com/optuna/optuna/pull/6547),
[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136),
[pypdf](https://github.com/py-pdf/pypdf/pull/3685) und
[beets](https://github.com/beetbox/beets/pull/6473) gemerged. Das
sind akzeptierte Cleanup-PRs, keine Empfehlungen oder Endorsements dieser
Projekte. Siehe [Real-World Results](../../REAL_WORLD_RESULTS.md).

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

Der erzeugte Workflow lädt per GitHub OIDC zu Skylos Cloud hoch: Pushes auf den
Default-Branch und Pull Requests auf den Default-Branch. Ein Pull Request wird
als nicht vertrauenswürdige Daten in einem Job ohne Zugangsdaten gescannt und
von einem Job hochgeladen, der seine Dateien nie auscheckt. Monorepo-Subprojekte
gehen über `--scan-path`.

## Dokumentationskarte

| Bedarf | Dokument |
|:---|:---|
| Installation, Quellinstallation und Docker | [Installation](https://docs.skylos.dev/installation) |
| Erster Scan und Kernworkflows | [Quick Start](https://docs.skylos.dev/quick-start) |
| CLI-Befehle, Flags und Beispiele | [CLI Reference](https://docs.skylos.dev/cli-reference) |
| CLI-Ausgabemodi, Pretty Reports und TUI-Steuerung | [CLI Output Modes](../cli-output.md) |
| Optionales Ruff-Linting über die Skylos-CLI | [Python Linting](../python-linting.md) |
| CI-Setup, PR-Gates, Annotationen und Branch Protection | [CI/CD](https://docs.skylos.dev/ci-cd) |
| Dead-Code-Verhalten und Framework-Awareness | [Dead Code Detection](https://docs.skylos.dev/dead-code-detection) |
| Security-Scanning und Taint-Analyse | [Security Analysis](https://docs.skylos.dev/security-analysis) |
| Rule-ID-Präfixe und Produktterminologie | [Rule Dictionary](../../dictionary.md) |
| Agent Scan, Verifikation, Remediation und Modellsetup | [AI Features](https://docs.skylos.dev/ai-features) |
| AI-app-safety-Prüfungen und LLM-Guardrails | [AI app safety](https://docs.skylos.dev/ai-defense) |
| Was eine Änderung berührt und was zuerst zu lesen ist (`skylos done map`) | [Change map](../change-map.md) |
| Tutorial: `skylos setup`, `skylos open`, die Pipeline-Ansicht und die PR-Prüfung, aus einer echten Agenten-Sitzung | [Tutorial](../workflow.md) |
| Wer was aufruft, in einfachen Worten, und ob geänderte Logik gleich geblieben ist (`skylos graph`) | [Codebase graph](../graph.md) |
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

**Ersetzt Skylos Ruff?**

Nein. `skylos lint` ist ein optionaler Einstiegspunkt, der an Ruff delegiert.
Die Installation erfolgt mit `pip install "skylos[lint]"`; normale
Skylos-Scans führen Ruff nicht aus.

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
