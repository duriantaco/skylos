## Changelog

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
