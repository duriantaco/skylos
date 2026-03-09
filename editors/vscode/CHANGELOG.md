## Changelog

## [0.5.0] - 2026-03-10

### Added
- **Local AI support**: new `"local"` provider option with dedicated `skylos.localBaseUrl` and `skylos.localModel` settings. Works with Ollama, LM Studio, LocalAI, vLLM, Kimi, or any OpenAI-compatible server. No API key required
- **SARIF export**: `Skylos: Export Report` now offers SARIF v2.1.0 output for CI/code-scanning integrations (GitHub Code Scanning, GitLab SAST, Azure DevOps). Includes rule metadata with CWE, OWASP, and PCI-DSS tags
- **Sidebar filters**: filter findings by severity, category, source (CLI vs AI), or file name via the funnel icon in the sidebar title bar. Filters stack and can be cleared with the X button
- **Configurable delta base branch**: `skylos.diffBase` setting (default `origin/main`) replaces the hardcoded base ref for delta mode. Supports any git ref
- **Safer AI fix workflow**: `skylos.fixPreviewFirst` (default `true`) enforces diff preview before applying fixes. `skylos.postFixCommand` runs tests/linter after each fix with one-click undo on failure
- Clear warning when `"local"` provider is selected but no server URL is configured, with "Open Settings" action

### Changed
- AI provider dropdown now shows descriptive labels: "OpenAI (cloud)", "Anthropic (cloud)", "Local AI server"
- Error messages are provider-specific — local provider tells you to set `localBaseUrl`, not an API key

## [0.4.1] - 2026-02-24

### Changed
- Raised default confidence threshold from 60 to 80 (reduces noise out of the box)
- Unused parameters (`DEAD-PARAM`) now hidden by default (toggle with `skylos.showDeadParams`)
- Dead code decorations now show confidence percentage inline, e.g. `unused — myFunc (87%)`

### Added
- `skylos.enableDeadCode` setting — toggle all dead code findings on/off
- `skylos.showDeadParams` setting — show unused parameter findings (off by default)
- "Ignore" CodeLens button on all dead code findings (appends to `.skylosignore`)

## [0.4.0] - 2026-02-23

### Added
- Multi-language support: TypeScript, JavaScript, TSX, JSX, Go
- Sidebar tree view with findings grouped by category, file, and line
- Rich hover with rule descriptions, OWASP/CWE refs, and fix guidance
- 4 severity color levels (red, orange, yellow, blue) replacing single yellow highlight
- Quality findings now shown in diagnostics (was silently dropped)
- Quick fixes: remove import, remove function, add to whitelist, ignore file
- Language-aware ignore comments (`// skylos-ignore` for TS/Go)
- Status bar severity breakdown (`2E 3W 5I`)
- Scan on workspace open (`skylos.scanOnOpen`)
- Keyboard shortcut `Cmd+Alt+S` / `Ctrl+Alt+S`
- 70-rule metadata registry with OWASP, CWE, PCI DSS refs

### Changed
- Rewrote 966-line monolith into 13 focused modules with central FindingsStore
- Switched from `execFile` to `spawn` for scan cancellation support
- AI analysis now works for TypeScript/JS/Go (was Python-only)

## [0.3.0] - 2025-02-01

### Added
- Real-time analysis. Detects bugs as you type, no save required
- Choose between OpenAI and Anthropic
- CodeLens buttons. "Fix with AI" and "Dismiss" appear inline on error lines
- See fix progress in status bar as AI generates code
- Function caching. It only re-analyzes functions that changed
- Popup alerts for critical issues with configurable cooldown
- New settings: `aiProvider`, `openaiApiKey`, `anthropicApiKey`, `openaiModel`, `anthropicModel`, `idleMs`, `popupCooldownMs`


## [0.2.0] - 2025-11-16

### Added 
- Highlighting unused variables and dangerous/poor quality code. Warning messages will appear on the same line as the errors
- Added config toggles for `enableSecrets`, `enableDanger`, and `enableQuality` that control `--secrets`, `--danger`, `--quality` flags
- Wired quality issues into the extension output under a new `QUALITY` section

## [0.1.1] - 2025-10-14

### Added
- Output panel showing all findings grouped by category and severity
- Status bar item with clickable icon showing scan results
- File paths with line numbers for each finding
- Extension icon

### Changed
- Improved error reporting and feedback

### Fixed
- Issues not showing detailed location information

## [0.1.0] - 2025-09-22

### Added

- VS Code extension: inline diagnostics
- Popup + status bar after each scan
- Settings: `skylos.path`, `skylos.confidence`, `skylos.excludeFolders`, `skylos.runOnSave` (default true), `skylos.enableSecrets` (default true), `skylos.enableDanger` (default true), `skylos.showPopup` (default true)
- Workspace command: "Skylos: Scan Workspace"
