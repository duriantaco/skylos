<div align="center">
    <img src="../../assets/DOG_1.png" alt="Skylos" width="160">
    <h1>Skylos</h1>
    <p><strong>Code-Prüfungen, die ihre Belege zeigen.</strong></p>

[![PyPI version](https://img.shields.io/pypi/v/skylos)](https://pypi.org/project/skylos/)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/skylos)
![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
[![codecov](https://codecov.io/gh/duriantaco/skylos/branch/main/graph/badge.svg)](https://codecov.io/gh/duriantaco/skylos)
![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/oha.skylos-vscode-extension)

[Docs](https://docs.skylos.dev) · [Schnellstart](#quick-start) · [Website](https://skylos.dev) · [VS Code](../../editors/vscode/README.md) · [Discord](https://discord.gg/Ftn9t9tErf)

[English](../../README.md) | **Deutsch** | [简体中文](./README.zh-CN.md)

</div>

## Was ist Skylos?

Skylos ist ein kostenloser Open-Source-Prüfer (Apache-2.0) für den Code, den du
und deine Coding-Agents schreiben. Er läuft auf deinem Rechner, in der Schleife
deines Agents und als Pull-Request-Gate. Kein Konto, kein API-Schlüssel und
kein LLM nötig.

Coding-Agents wie Claude Code, Codex und Cursor schreiben Code schneller, als
ihn jemand prüfen kann, und sie wiederholen dieselben Fehler. Sie melden
„fertig“, nachdem sie einen fehlschlagenden Test gelöscht oder übersprungen
haben. Sie installieren Pakete, die es nicht gibt, und importieren Funktionen,
die niemand geschrieben hat. Sie hinterlassen Injection-Lücken und hartkodierte
Schlüssel. Linter und Sicherheitsscanner fangen jeweils einen Teil davon ab,
im Nachhinein. Skylos prüft all das in einem Werkzeug, an den Stellen, an denen
es sich noch aufhalten lässt.

Gebaut für:

- **Entwickler, die Agents Code schreiben lassen** und den Agent prüfen wollen,
  während er arbeitet, nicht danach.
- **Maintainer**, die eine kostenlose Prüfung für jeden Pull Request wollen.
- **Bestehende Codebasen**, die Sicherheits-, Secret-, Abhängigkeits-,
  Qualitäts- und Totcode-Befunde aus einem Scan brauchen, in Python,
  TypeScript, Java, Go und [weiteren Sprachen](#language-support).

## So funktioniert es

Skylos greift an vier Stellen ein:

| Wann | Befehl | Was es stoppt |
|:---|:---|:---|
| Während der Agent arbeitet | `skylos agent install-hooks` | Erfundene Paketinstallationen, Lesen von Dateien mit Secrets, Umgehen von Git-Hooks; prüft jede Änderung |
| Wenn der Agent „fertig“ sagt | `skylos done --base main` | Gelöschte oder übersprungene Tests, gelockerte CI-Schritte, stummgeschaltete Lint- oder Typprüfungen, Sonderfälle nur für Tests; führt deine Tests aus |
| Bei jedem Pull Request | `skylos cicd init` | Kritische Sicherheitsprobleme, Secrets und kritische AI-Code-Fehler, plus alles über deinen Grenzwerten |
| Jederzeit, im ganzen Repository | `skylos . -a` | Sicherheitslücken, Secrets, verwundbare Abhängigkeiten, Qualitätsregressionen, AI-Code-Fehler, toter Code |

## Beispiel

Eine Flask-App mit 20 Zeilen, mit allen Prüfungen gescannt (Auszug):

```text
$ skylos . -a --format concise
app.py:15  SKY-D211  Possible SQL injection: tainted or string-built query.
app.py:5  SKY-L012  Import from local module 'billing' requests 'issue_refund', but that name is not defined or re-exported there.
app.py:8  SKY-S101  Potential stripe secret detected
requirements.txt:1  SKY-SCA-GHSA-68rp-wp8r-4726  flask@3.1.2: Flask session does not add `Vary: Cookie` header when accessed in some ways
billing.py:1  SKY-U001  unused function: charge_card
```

Jeder Befund nennt Datei, Zeile und Regel. Sicherheitsbefunde zeigen den Pfad
von der Quelle zur Senke, wenn einer erfasst wurde; `--format json` enthält
alle Belege.

<a id="quick-start"></a>

## Schnellstart

```bash
pip install skylos
skylos . -a               # alle Prüfungen in diesem Repository
skylos done --base main   # ist der Agent wirklich fertig? führt deine Tests aus, vergleicht mit main
skylos cicd init          # eine Skylos-Prüfung für jeden Pull Request einrichten
```

Arbeitest du mit einem Coding-Agent? Zwei Befehle:

```bash
skylos setup   # einmal pro Repository: verbindet Claude Code und Codex, installiert ihre Hooks, lässt Done deine Tests ausführen, schreibt die PR-Prüfung
skylos open    # jeden Tag: Diagramm deines Codes, was sich geändert hat, in Klartext, jede Prüfung
```

Das [Tutorial](../workflow.md) zeigt eine echte Sitzung: Der Agent ändert
Code, wird blockiert und behebt es anhand von Skylos' Fix-Anleitung.

`skylos .` allein führt den schnellen Totcode-Scan aus. `skylos cloud` lädt
Ergebnisse hoch, um jeden Branch in Skylos Cloud zu verfolgen; das ist optional.

## Jede Agent-Änderung prüfen

Installiere Hooks, damit der Agent geprüft wird, während er arbeitet:

```bash
skylos agent install-hooks            # Claude Code
skylos agent install-hooks --codex    # Codex
skylos agent install-hooks --cursor   # Cursor
```

- **Nach jeder Änderung:** prüft die geänderten Zeilen auf Sicherheitsprobleme,
  Secrets und AI-Code-Fehler und sagt dem Agent, was zu beheben ist.
- **Vor dem Lesen einer Datei:** blockiert Dateien mit hartkodierten Secrets.
- **Vor einer Paketinstallation** (`pip`, `uv`, `npm`, `pnpm`, `bun`, `go`, ...):
  blockiert erfundene oder per Typosquatting nachgeahmte Pakete und fragt vor
  Installationen nach, die es nicht prüfen kann.
- **Vor einem Git-Befehl:** blockiert `--no-verify` und andere Wege an deinen
  Git-Hooks vorbei.
- **Beim Stopp:** blockiert „fertig“, solange vom Agent eingeführte Probleme
  offen sind.

Wenn Skylos selbst einen Fehler hat, wird die Aktion erlaubt, und du und der
Agent erfahrt, dass sie ungeprüft blieb. Siehe [Agent-Hooks](../agent-hooks.md).

## Ist der Agent wirklich fertig?

```bash
skylos done --base main
```

`skylos done` vergleicht den Branch mit `main` und führt deine Tests aus. Es
meldet:

- gelöschte, übersprungene oder abgeschwächte Tests
- gelockerte Testeinstellungen und CI-Testschritte
- stummgeschaltete Lint- oder Typprüfungen
- Code mit Sonderfällen nur für die Tests
- Code, den der Branch ohne Aufrufer zurückgelassen hat (Hinweis, keine Blockade)

Schlägt ein Test fehl, führt es ihn auf `main` erneut aus und kennzeichnet den
Fehler als „eingeführt“ oder „schon vorher fehlgeschlagen“. Es schreibt einen
Beleg nach `.skylos/receipts/`. pytest läuft automatisch; andere Runner
brauchen eine Zeile:

```toml
[tool.skylos.done]
test_command = "npm test"
```

Es liest seine Einstellungen von `main`, damit ein Branch seine eigene Prüfung
nicht lockern kann. Exit-Codes: `0` bestanden, `1` blockiert, `2` konnte nicht
laufen. Siehe [Done-Gate](../done-gate.md) und was es
[übersieht](../done-gate-benchmark.md).

<a id="cicd"></a>

## Pull Requests absichern

Kein Konto und kein Token nötig:

```bash
git checkout -b add-skylos-gate
skylos cicd init --no-upload
git add .github/workflows/skylos.yml
git commit -m "Add Skylos pull request gate"
git push -u origin add-skylos-gate
```

Der Workflow prüft die geänderten Zeilen jedes Pull Requests und führt
`skylos done` aus, wenn er deine Tests findet. `skylos cicd init` richtet auch
GitLab CI, Jenkins, Bitbucket Pipelines, Azure Pipelines und CircleCI ein
([jede CI](../ci-platforms.md)).

Das Gate schlägt immer fehl bei einem kritischen Sicherheitsproblem, einem
Secret oder einem kritischen AI-Code-Problem, etwa dem Import eines Pakets, das
es nicht gibt. Alles andere schlägt nur über deinen Grenzwerten fehl:

```toml
[tool.skylos.gate]
max_high = 5          # erlaubte Sicherheitsprobleme mit hoher Schwere
max_quality = 10      # erlaubte Qualitätsprobleme
max_ai_defects = 10   # erlaubte AI-Code-Probleme
```

Die Richtlinie wird vom Basis-Branch gelesen, damit ein Pull Request sein
eigenes Gate nicht lockern kann. Jeder Lauf endet mit `Quality Gate: PASSED`,
`FAILED` (Exit 1) oder `INCOMPLETE` (Exit 2) und den Gründen. Anleitung:
[dein erster abgesicherter Pull Request](../first-gated-pr.md).

Soll ein Mensch riskante Änderungen freigeben? `skylos cicd init --risk-review`
fügt eine Prüfung hinzu, die auf eine menschliche Freigabe wartet, wenn ein
Pull Request Tests löscht, Auth-Prüfungen entfernt, Abhängigkeiten ändert oder
die CI schwächt. Siehe [Risk Review](../risk-review.md).

## Ein Repository scannen

```bash
skylos .                         # toter Code (schnell, Standard)
skylos . -a                      # alle Prüfungen
skylos . -a --diff origin/main   # nur Befunde in geänderten Zeilen
skylos . --format pretty         # gruppierter Bericht mit Code-Ausschnitten
skylos . --tui                   # Triage per Tastatur
skylos . -a --format json        # alle Belege für Skripte und Agents
skylos . --format sarif          # GitHub Code Scanning
skylos cleanup . --top 5         # priorisierte Liste zum Beheben
```

Toten Python-Code kann Skylos für dich entfernen: `skylos clean . --dry-run`
zeigt den Plan, `--apply` ändert die Dateien. Ausgabemodi und Exit-Codes:
[CLI-Ausgabe](../cli-output.md).

## Was Skylos findet

| Kategorie | Beispiele |
|:---|:---|
| AI-Code-Fehler | Importe nicht existierender Funktionen, erfundene Paket-APIs, nicht existierende Pakete, unmögliche Versionen, unfertige Stubs, deaktivierte Kontrollen |
| Sicherheitslücken | SQL-Injection, XSS, SSRF, Path Traversal, Command Injection, unsichere Deserialisierung, ReDoS |
| Secrets | API-Schlüssel, Tokens, private Zugangsdaten, Zeichenketten mit hoher Entropie |
| Abhängigkeiten | bekannte CVEs, bösartige Pakete, Lizenzrichtlinie, Offline-SBOM (CycloneDX, SPDX) |
| Qualität | Komplexität, tiefe Verschachtelung, doppelte Zweige, lange Funktionen, inkonsistente Rückgaben |
| Toter Code | ungenutzte Funktionen, Klassen, Importe, Dateien und Abhängigkeiten, framework-bewusst (FastAPI, Django, Flask, Next.js, React, Laravel, ...) |
| CI/CD und Deployment | riskante GitHub Actions und GitLab CI, Dockerfiles, Docker Compose, systemd, Kubernetes |
| LLM-Apps | unsichere Tool-Nutzung, Prompt-Injection-Angriffsfläche, fehlende Ausgabevalidierung |

Alle Regeln: [Rules Reference](https://docs.skylos.dev/rules-reference) und
[Regelverzeichnis](../../dictionary.md).

## Die AI-Apps prüfen, die du baust

Wenn dein Code ein LLM aufruft, prüft Skylos die Schutzmaßnahmen darum, ohne
Modell in der Schleife:

```bash
skylos discover .                    # LLM-Aufrufe, Agent-Tools und Prompt-Stellen auflisten
skylos defend .                      # die Schutzmaßnahmen darum bewerten
skylos defend . --fail-on critical   # CI-Gate
skylos defend . --format md -o evidence.md   # Nachweisbericht mit Abdeckung der OWASP LLM Top 10
```

Es deckt Python und TypeScript/JavaScript ab; `--owasp-framework agentic`
berichtet gegen die OWASP Agentic Top 10. Um einen laufenden Agent gegen
erwartete Antworten und Tool-Aufrufe zu testen, nutze `skylos agent test`.
Siehe [Agent-Verifikation](../agent-verification.md) und
[Agent-Verhaltenstests](../agent-behavior-testing.md).

<a id="language-support"></a>

## Sprachunterstützung

| Sprache | Toter Code | Sicherheit | Qualität |
|:---|:---:|:---:|:---:|
| Python | Ja | Ja | Ja |
| TypeScript / JavaScript | Ja | Ja | Ja |
| Java | Ja | Ja | Ja |
| Go | Ja | Teilweise | Teilweise |
| PHP | Ja | Ja | Nein |
| Rust | Experimentell | Teilweise | Teilweise |
| Ruby | Teilweise | Teilweise | Nein |
| Dart | Ja | Teilweise | Nein |
| C# | Teilweise | Teilweise | Teilweise |
| C++ | Teilweise | Nein | Nein |
| Kotlin | Teilweise | Teilweise | Nein |
| Swift | Teilweise | Nein | Nein |
| Shell | Nein | Teilweise | Nein |

- Python hat die tiefste Abdeckung.
- Go braucht die native Engine `skylos-go`. Sie ist in den PyPI-Wheels für
  Linux, macOS und Windows enthalten; anderswo gibt `skylos doctor` den
  Build-Befehl aus.
- Dart braucht `pip install "skylos[dart]"`.
- Toter Rust-Code ist standardmäßig ausgeblendet; `--confidence 40` zeigt ihn.

Vollständige Matrix und Grenzen je Sprache:
[Language support](https://docs.skylos.dev/language-support).

## Konfiguration

`skylos init` fügt eine Startkonfiguration in `pyproject.toml` ein. Projekte
ohne diese Datei können `skylos.toml` mit denselben Schlüsseln auf oberster
Ebene nutzen:

```toml
# skylos.toml
exclude = ["generated", "dist"]

[gate]
max_high = 5

[done]
test_command = "npm test"
```

In einem Monorepo kann jedes Paket eine eigene Datei haben; die nächstgelegene
gewinnt je Schlüssel. `skylos doctor` zeigt, welche Dateien verwendet werden.

Einen einzelnen Befund mit Begründung stummschalten:

```python
query = build_query(user_id)  # skylos: ignore[SKY-D211] user_id is an int from the router
```

Um bestehende Befunde zu akzeptieren und nur neue zu blockieren, führe
`skylos baseline .` aus und scanne mit `--baseline`. Mehr:
[Konfiguration](https://docs.skylos.dev/configuration).

## Integrationen

| Integration | Was sie macht |
|:---|:---|
| [GitHub Action](../../action.yml) | Pull-Request-Gate, optional Container-Image-Gate |
| [GitLab, Bitbucket, Azure, Jenkins, CircleCI](../ci-platforms.md) | Pull-Request-Gate für diese CI |
| [Agent-Hooks](../agent-hooks.md) | Claude Code, Codex und Cursor bei jeder Änderung geprüft |
| [MCP-Server](https://docs.skylos.dev/mcp-server) | Skylos-Scans als Tools für AI-Assistenten |
| [VS-Code-Erweiterung](../../editors/vscode/README.md) | Befunde im Editor |
| [Skylos Cloud](../skylos-cloud.md) | Optional: Befunde und das Gate je Branch, über die Zeit |

## Installationsoptionen

```bash
pip install skylos              # Kernprüfungen
pip install "skylos[llm]"       # Agent-Befehle, die ein LLM nutzen
pip install "skylos[all]"       # alle optionalen Extras
```

Oder das Container-Image ausführen:

```bash
docker run --rm -v "$PWD":/work -w /work ghcr.io/duriantaco/skylos:latest . -a
```

Weitere Extras (`lint`, `verdict`, `dart`), Image-Tags je Python-Version und
Installation aus dem Quellcode: [Installation](https://docs.skylos.dev/installation).

## Was deinen Rechner verlässt

Dein Code und deine Befunde erreichen Skylos Cloud nur, wenn du einen Befehl
ausführst, der ausdrücklich hochlädt, etwa `skylos cloud` oder `--upload`. Ein
gespeicherter Login allein lädt nie etwas hoch. Es gibt keine Analytics.

Abhängigkeits- und Paketprüfungen senden Paketnamen und Versionen an OSV und
die öffentlichen Registries, nie Quellcode. LLM-Befehle senden Code an den
Modellanbieter, den du konfigurierst. Jede Anfrage, ihr Auslöser und wie man
sie abschaltet: [Privacy and network](../privacy-and-network.md).

## Ergebnisse

10 mit Skylos unterstützte Aufräum-PRs für toten Code wurden in 9
Open-Source-Projekten gemergt, darunter
[Black](https://github.com/psf/black/pull/5041),
[NetworkX](https://github.com/networkx/networkx/pull/8572),
[Optuna](https://github.com/optuna/optuna/pull/6547),
[mitmproxy](https://github.com/mitmproxy/mitmproxy/pull/8136) und
[pypdf](https://github.com/py-pdf/pypdf/pull/3685).
[Real-World Results](../../REAL_WORLD_RESULTS.md) listet alle 26 erfassten PRs,
auch die geschlossenen oder zurückgenommenen. Das sind angenommene Aufräum-PRs,
keine Empfehlungen.

Methoden, datierte Ergebnisse und Vergleiche mit anderen Werkzeugen:
[BENCHMARK.md](../../BENCHMARK.md).

## FAQ

**Ersetzt Skylos Semgrep, CodeQL, Bandit oder Vulture?**
Nein. Es läuft daneben. Es ergänzt Agent-Prüfungen, framework-bewussten toten
Code und ein Gate für Sicherheit, Secrets, Abhängigkeiten und Qualität.

**Braucht es ein LLM?**
Nein. Die Kernprüfungen laufen lokal ohne Modell. LLM-Funktionen sind optional
(`skylos[llm]`).

**Ist es kostenlos?**
Die CLI ist kostenlos und Open Source. Skylos Cloud ist optional und hat einen
kostenlosen Plan; siehe [Preise](https://skylos.dev/pricing).

**Kann ich nur meine Änderungen prüfen?**
Ja: `skylos . -a --diff origin/main`. Eine entfernte Sicherheitsprüfung, etwa
ein gelöschter Auth-Decorator, wird trotzdem gemeldet.

**Was ist mit Code, der nur dynamisch aufgerufen wird?**
Nutze Inline-Ausnahmen, eine Baseline oder `--trace`, um aufzuzeichnen, was
wirklich läuft. Siehe [Smart Tracing](https://docs.skylos.dev/smart-tracing).

Mehr: [FAQ](https://docs.skylos.dev/faq).

## Dokumentation

| Bedarf | Lesen |
|:---|:---|
| Jeder Befehl und jede Option | [CLI-Referenz](https://docs.skylos.dev/cli-reference) |
| Installation, Extras, Docker | [Installation](https://docs.skylos.dev/installation) |
| Konfigurationsdateien, Ausnahmen, Baselines | [Konfiguration](https://docs.skylos.dev/configuration) |
| Ausgabeformate und Exit-Codes | [CLI-Ausgabe](../cli-output.md) |
| Agent-Hooks | [Agent-Hooks](../agent-hooks.md) |
| `skylos done` | [Done-Gate](../done-gate.md) |
| Pull-Request-Gates | [Erster abgesicherter PR](../first-gated-pr.md), [jede CI](../ci-platforms.md) |
| Sicherheit und Taint-Analyse | [Security](https://docs.skylos.dev/security-analysis) |
| Abhängigkeiten, SBOM, Lizenzen | [Dependency scanning](../dependency-scanning.md), [Lizenzen](../license-compliance.md) |
| AI-Code-Prüfungen | [AI code verification](../ai-code-verification.md) |
| Netzwerkanfragen | [Privacy and network](../privacy-and-network.md) |
| Regel-IDs | [Regelverzeichnis](../../dictionary.md) |

## Mitwirken

- Lies [CONTRIBUTING.md](../../CONTRIBUTING.md), bevor du einen Pull Request
  sendest.
- Melde einen Fehler mit `skylos feedback` (kein Konto nötig) oder eröffne ein
  Issue mit einem minimalen Beispiel.
- Melde Sicherheitsprobleme über [SECURITY.md](../../SECURITY.md).
- Analyzer-Änderungen werden mit
  [liveness_primer](https://github.com/mcdigman/liveness_primer) an echten
  Projekten getestet, gebaut von [Matthew Digman](https://github.com/mcdigman).
  Siehe die [Anleitung](../liveness-primer.md).
- Ideen zum Mitarbeiten: [ROADMAP.md](../../ROADMAP.md). Chat:
  [Discord](https://discord.gg/Ftn9t9tErf).

## Lizenz

Apache License 2.0. Siehe [LICENSE](../../LICENSE).
