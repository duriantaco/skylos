# Skylos for VS Code

> Python dead code, security and secrets checks in VS Code, from the open-source [Skylos](https://github.com/duriantaco/skylos) CLI. TypeScript and JavaScript get narrower checks. Findings show the file, line and evidence. AI chat and fixes are optional; when you invoke them, your configured provider receives code context.

<img src="media/vsce.gif" alt="Skylos VS Code Extension — inline dead code detection, security scanning, and CodeLens actions" width="800" />

## Features

* **Skylos Review Queue**: A ranked sidebar queue puts CI-blocking, new, high-risk, evidence-backed, and fixable issues first
* **Source provenance and confirmation**: Findings are labeled as Static, Automation, AI Assist, or Confirmed by multiple sources
* **Decision-grade finding details**: Each finding explains why it was prioritized, what evidence Skylos has, likely CI impact, and the safest fix path
* **Optional Automation Activity**: Repo-level background triage fed by Skylos automation state when you explicitly use it
* **AI Security Copilot Chat**: Sidebar chat panel to ask questions about findings, get explanations, and apply fixes from code blocks
* **Auto-Remediation**: One-click "Fix All" with severity picker, progress tracking, and dry-run preview mode
* **Optional Edit-Time Verification**: Opt-in CLI verification of changed functions after you pause typing
* **Multi-Provider Support**: OpenAI, Anthropic, or any OpenAI-compatible local server (Ollama, LM Studio, LocalAI, vLLM)
* **CodeLens Buttons**: Contextual "Fix with AI Assist", "Preview Engine Fix", "Ignore", and "Dismiss" actions appear on relevant lines
* **Function Caching**: Reuses recent verification results for unchanged functions
* **Multi-Language**: Python (deepest), TypeScript, JavaScript, TSX and JSX. Go dead-code and security checks need the separately built `skylos-go` engine, which `pip install skylos` does not include
* **Engine-backed cleanup previews**: Safe cleanup actions are previewed from Skylos engine output when an engine patch is available
* **Framework-Aware Detection**: Handles Flask, Django, FastAPI routes and decorators
* **Secrets Scanning**: Detects API keys & secrets (GitHub, GitLab, Slack, Stripe, AWS, Google, SendGrid, Twilio, private key blocks)
* **Dangerous Patterns**: Flags risky uses of `eval/exec`, command execution, `pickle.load/loads`, `yaml.load` without SafeLoader, and weak hashes. See the [rules reference](https://docs.skylos.dev/rules-reference).

Analysis runs through your local Skylos CLI. AI chat and fixes are optional; when you invoke them, your configured provider receives code context. CLI network lookups and Cloud sync follow your CLI configuration.

## How it works

**Static Analysis (Skylos CLI)**
On save, the extension scans the current file by default. Full workspace scans are explicit:
```
skylos <workspace-folder> --json -c <confidence> [--secrets] [--danger] [--quality]
```

**Optional AI Assist**
Manual AI Assist commands and chat use your configured provider. Optional edit-time verification is off by default; when enabled, the extension waits for idle and runs `skylos verify --stdin` with the unsaved file and changed-function line range. That edit-time path uses the CLI verifier and does not call a model provider.

## Requirements

1. Python 3.10+
2. Skylos engine installed (`pip install skylos`) and available on `PATH`, or set an explicit path via `skylos.path`
3. (Optional) OpenAI or Anthropic API key for AI chat and fixes, or an OpenAI-compatible local server

## Installation

Install [Skylos](https://marketplace.visualstudio.com/items?itemName=oha.skylos-vscode-extension) (`oha.skylos-vscode-extension`) from the Visual Studio Marketplace.

An Open VSX listing has not been published yet. In editors that use Open VSX, install a Skylos `.vsix` package using **Extensions: Install from VSIX**. The contributing section below explains how to package one locally.

Make sure skylos runs in a terminal:
```bash
skylos --version
```

If not, run:
```bash
pip install skylos
```

Open your project in VS Code and save a file — diagnostics appear.

## Usage

### First Run

Open the VS Code walkthrough **Get Started with Skylos** or run:

1. `Skylos: Doctor` to verify the CLI path and version
2. `Skylos: Scan Workspace` to populate the Review Queue
3. `Skylos: Toggle New Issues Only` on legacy repos or PR branches

### Basic

- **Save a supported file** → Skylos CLI refreshes findings for that file
- **Type and pause** → optional edit-time verification runs only when `skylos.enableRealtimeAI` is enabled
- **Click "Fix with AI Assist"** on any error line to auto-fix
- **Command Palette** → `Skylos: Scan Workspace` for a full project scan

### Optional Edit-Time Verification

Edit-time verification is off by default. To enable it:

1. Set `skylos.enableRealtimeAI` to `true`
2. Make sure your Skylos CLI supports `skylos verify --stdin`

When enabled in a trusted workspace, typing in a supported file starts CLI verification after the idle delay. Findings appear in the Review Queue and editor diagnostics. No model provider or API key is needed for this path; CLI dependency checks may query package registries.

Keep `skylos.enableRealtimeAI` set to `false` to disable edit-time verification. You can still invoke AI chat and fixes manually.

### AI Security Copilot Chat

The chat panel lives in the Skylos sidebar:

1. Open the **Skylos** sidebar (shield icon in the activity bar)
2. The **Security Copilot** panel is below the Review Queue
3. Type a question about any security topic and get a streamed response

**Ask about a specific finding:**
- In the Review Queue, **right-click any finding** → **"Ask AI About Finding"**
- The chat panel opens with that finding's context (file, severity, surrounding code)
- Ask follow-up questions — the AI knows which finding you're looking at

**Apply fixes from chat:**
- Code blocks in AI responses have an **"Apply Fix"** button
- Click it to replace the enclosing function in your editor

**Clear history:** Click the clear button in the chat panel title bar, or run `Skylos: Clear Chat` from the command palette.

### Auto-Remediation (Fix All)

Fix multiple findings at once:

1. **`Cmd+Alt+F`** (Mac) / **`Ctrl+Alt+F`** (Windows/Linux), or Command Palette → `Skylos: Auto-Fix All with AI Assist`
2. Pick a severity level:
   - **Fix Errors Only** — CRITICAL + HIGH
   - **Fix Errors + Warnings** — + MEDIUM
   - **Fix All** — all severities
3. Confirm in the modal dialog
4. A progress notification shows each finding being fixed: `"Fixing 3/12: SKY-D203 in auth.py..."`
5. Each fix is a **separate undo step** — `Cmd+Z` to undo one fix at a time
6. After completion, Skylos re-scans to verify

**Dry Run** — preview fixes without editing:
1. Command Palette → `Skylos: Auto-Fix AI Assist Dry Run`
2. Pick severity level
3. A markdown report opens with before/after code for each finding
4. No files are modified

**Safety:**
- Fix All skips dead code findings; use the separate engine-backed cleanup preview for dead code
- Capped at 50 findings per run (change with `skylos.autoFixMaxFindings`)
- 200ms delay between API calls to avoid rate limits
- Cancellable via the progress notification

For individual **Fix Issue with AI Assist** actions, `skylos.fixPreviewFirst` shows a diff before applying and `skylos.postFixCommand` can run your tests or linter afterwards. Fix All does not use those settings; use Dry Run to review its proposed changes first.

### Local AI (Ollama, LM Studio, etc.)

You can use an OpenAI-compatible local server instead of a cloud API. No API key is needed for the extension's local provider. AI requests stay on your machine when the configured server runs there.

**Setup:**

1. Set `skylos.aiProvider` to `"local"`
2. Set `skylos.localBaseUrl` to your server's URL
3. Set `skylos.localModel` to the model name
4. No API key required

**Examples by server:**

| Server | Base URL | Model example |
|--------|----------|---------------|
| Ollama | `http://localhost:11434` | `llama3.1`, `codellama`, `deepseek-coder` |
| LM Studio | `http://localhost:1234` | `lmstudio-community/Meta-Llama-3.1-8B` |
| LocalAI | `http://localhost:8080` | `gpt-4` (or whatever you named it) |
| vLLM | `http://localhost:8000` | `meta-llama/Llama-3.1-8B-Instruct` |
| Kimi | `http://localhost:8080` | `kimi` |

**Example `settings.json`:**
```json
{
  "skylos.aiProvider": "local",
  "skylos.localBaseUrl": "http://localhost:11434",
  "skylos.localModel": "llama3.1"
}
```

AI chat and fixes use this server. Optional edit-time verification continues to use the Skylos CLI.

### Review Queue Filters

The Review Queue has a filter button (funnel icon) in the title bar:

1. Click the **filter icon** or Command Palette → `Skylos: Filter Findings`
2. Choose a filter dimension:
   - **By Severity** — show only CRITICAL, HIGH, MEDIUM, etc.
   - **By Category** — security, secrets, dead code, quality, or AI Assist
   - **By Source** — Static scan, Automation, AI Assist, or Confirmed findings
   - **By File Name** — substring match (e.g. `auth.py`, `src/utils`)
3. Filters stack — filter by severity, then by category to narrow further
4. An **X** button appears in the title bar when a filter is active — click to clear

Click any Review Queue item to jump to the code, or open **Show Finding Detail** for the decision view. The detail panel keeps the editor quiet while still showing why a finding matters: priority reasons, evidence or trace metadata when the CLI emits it, CI-blocking risk, and whether the safest next step is an engine patch, safe-fix guidance, AI assistance, or manual review.

If static analysis and Automation report the same rule at the same location, Skylos merges them into one confirmed finding labeled **Confirmed by Static + Automation**. Confirmed findings keep their severity color and rank higher because two analysis paths agree. Static-only findings remain first-class results; missing Automation or AI Assist state is not an error unless you explicitly invoke those optional modes.

### Automation Activity

The **Automation Activity** view is optional. It is separate from the primary Review Queue and uses Skylos automation state for repo-level background triage:

1. Click **Refresh Automation** in the Automation Activity title bar, or run `Skylos: Refresh Automation`
2. Skylos reads `.skylos/agent_state.json` and shows the top ranked actions first
3. Click an action to open the file at the flagged line
4. Right-click an action to:
   - open a richer detail panel
   - preview an engine-backed cleanup patch when available
   - snooze or dismiss the action
5. Use **Restore Triaged Actions** from the Automation Activity title bar to bring snoozed or dismissed items back

For continuous repo-level updates, run this in a terminal from your project root:

```bash
skylos agent watch .
```

When the automation state file changes, the Automation Activity view refreshes automatically. You can also enable:

- `skylos.commandCenterRefreshOnOpen`
- `skylos.commandCenterRefreshOnSave`
- `skylos.commandCenterLimit`
- `skylos.commandCenterStateFile`

### New Issues Mode

New Issues mode shows only **new issues since a base branch**, useful for PRs and legacy repos:

1. Click the **git-compare icon** in the sidebar title bar, or Command Palette → `Skylos: Toggle New Issues Only`
2. Configure the base branch via `skylos.diffBase` (default: `origin/main`)
3. Supports any git ref: `origin/develop`, `HEAD~5`, a commit SHA, etc.

### Export Formats

Command Palette → `Skylos: Export Report` offers three formats:

- **Markdown** — human-readable report with severity tables and findings
- **JSON** — machine-readable with scores, CWE/OWASP tags
- **SARIF** — standard format for CI/code-scanning (GitHub Code Scanning, GitLab SAST, Azure DevOps)

## Settings

Open Settings → Extensions → Skylos (or settings.json):

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `skylos.path` | string | `"skylos"` | Path to the Skylos executable |
| `skylos.confidence` | number | `80` | Confidence threshold (0-100) |
| `skylos.excludeFolders` | string[] | `["venv",".venv","build","dist",".git","__pycache__","node_modules",".next"]` | Exclude these folders |
| `skylos.runOnSave` | boolean | `true` | Run Skylos on save |
| `skylos.scanOnOpen` | boolean | `false` | Auto scan the first supported file opened in the session |
| `skylos.enableSecrets` | boolean | `true` | Include secrets scanning |
| `skylos.enableDanger` | boolean | `true` | Include dangerous-pattern checks |
| `skylos.enableDeadCode` | boolean | `true` | Show dead code findings (functions, imports, classes, variables) |
| `skylos.showDeadParams` | boolean | `false` | Show unused parameter findings (noisy with callbacks/interfaces) |
| `skylos.enableQuality` | boolean | `true` | Include code quality checks |
| `skylos.showPopup` | boolean | `true` | Show toast notification after scans |
| `skylos.editorSignalLevel` | string | `"quiet"` | Editor visual noise: `quiet`, `balanced`, or `verbose` |
| `skylos.codeLensMode` | string | `"highValue"` | CodeLens frequency: `off`, `activeLine`, `highValue`, or `all` |
| `skylos.enableRealtimeAI` | boolean | `false` | Run CLI verification after the edit idle delay |
| `skylos.aiProvider` | string | `"openai"` | AI Assist provider: `"openai"`, `"anthropic"`, or `"local"` |
| `skylos.openaiBaseUrl` | string | `"https://api.openai.com"` | Base URL for OpenAI API |
| `skylos.openaiApiKey` | string | `""` | OpenAI API key |
| `skylos.openaiModel` | string | `"gpt-4o"` | OpenAI model |
| `skylos.localBaseUrl` | string | `""` | URL of your local AI server (e.g. `http://localhost:11434`) |
| `skylos.localModel` | string | `""` | Model name on your local server (e.g. `llama3.1`) |
| `skylos.anthropicApiKey` | string | `""` | Anthropic API key |
| `skylos.anthropicModel` | string | `"claude-sonnet-4-20250514"` | Anthropic model for analysis |
| `skylos.idleMs` | number | `1000` | Milliseconds to wait before optional edit-time verification |
| `skylos.popupCooldownMs` | number | `8000` | Cooldown between AI popups (ms) |
| `skylos.autoFixMaxFindings` | number | `50` | Max findings to auto-fix per run (1-200) |
| `skylos.diffBase` | string | `"origin/main"` | Git ref for delta mode base |
| `skylos.fixPreviewFirst` | boolean | `true` | Show a diff before applying individual AI Assist fixes |
| `skylos.postFixCommand` | string | `""` | Shell command after an individual AI Assist fix (e.g. `npm test`, `pytest -x`) |

## Keyboard Shortcuts

| Shortcut | Command |
|----------|---------|
| `Cmd+Alt+S` / `Ctrl+Alt+S` | Scan Workspace |
| `Cmd+Alt+F` / `Ctrl+Alt+F` | Auto-Fix All with AI Assist |

## Commands

| Command | Description |
|---------|-------------|
| `Skylos: Scan Workspace` | Run skylos over the entire workspace |
| `Skylos: Doctor` | Check the configured Skylos CLI path and print setup details |
| `Skylos: Fix Issue with AI Assist` | Fix the issue at cursor with AI Assist |
| `Skylos: Preview Engine Fix` | Preview an engine-backed patch when one is available |
| `Skylos: Auto-Fix All with AI Assist` | Fix all findings with severity picker |
| `Skylos: Auto-Fix AI Assist Dry Run` | Preview fixes without editing files |
| `Skylos: Ask AI About Finding` | Open chat with finding context (right-click in sidebar) |
| `Skylos: Clear Chat` | Clear chat history and context |
| `Skylos: Refresh` | Re-run scan |
| `Skylos: Clear All Findings` | Clear all findings from the panel |
| `Skylos: Filter Findings` | Filter sidebar by severity, category, source, or file |
| `Skylos: Clear Filter` | Remove active sidebar filter |
| `Skylos: Export Report` | Export findings as Markdown, JSON, or SARIF |
| `Skylos: Toggle New Issues Only` | Toggle new issues only vs all findings |

## Privacy

- Analysis executes through your local Skylos CLI; registry lookups and Cloud uploads depend on CLI settings
- Manual AI fixes provide the finding and full enclosing function or nearby code to your configured provider; Dry Run uses the same AI requests
- Chat provides your messages, recent conversation history, and the selected finding's file path, details, and surrounding code to that provider
- **Preview Dead Code Removal** uses the CLI's AI-provider settings and may share repository code context
- Recent chat history is saved locally in VS Code workspace state; **Clear Chat** removes it
- The local-provider option connects to your local server; that server's own network and privacy settings still apply
- The extension does not add telemetry

## Contributing

PRs welcome!

- Extension code: `src/extension.ts` + modular files in `src/`

- Pack & test locally:
```bash
npm run compile
# Press F5 in VS Code to launch extension development host
```

- Package a VSIX:
```bash
npm run package
```

## License

Apache-2.0
