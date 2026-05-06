# Skylos for VS Code

> Bring dead code detection, security scanning, and AI-assisted remediation into VS Code for Python, TypeScript, JavaScript, and Go. Catch risky code, AI-generated defects, and unused code without leaving the editor.

<img src="media/vsce.gif" alt="Skylos VS Code Extension — inline dead code detection, security scanning, and CodeLens actions" width="800" />

## Features

* **Skylos Review Queue**: A ranked sidebar queue puts CI-blocking, new, high-risk, evidence-backed, and fixable issues first
* **Source provenance and confirmation**: Findings are labeled as Static, Automation, AI Assist, or Confirmed by multiple sources
* **Decision-grade finding details**: Each finding explains why it was prioritized, what evidence Skylos has, likely CI impact, and the safest fix path
* **Optional Automation Activity**: Repo-level background triage fed by Skylos automation state when you explicitly use it
* **AI Security Copilot Chat**: Sidebar chat panel to ask questions about findings, get explanations, and apply fixes from code blocks
* **Auto-Remediation**: One-click "Fix All" with severity picker, progress tracking, and dry-run preview mode
* **Optional Real-Time AI Assist**: Opt-in bug detection as you type using GPT, Claude, or a local model
* **Multi-Provider Support**: OpenAI, Anthropic, or any OpenAI-compatible local server (Ollama, LM Studio, LocalAI, vLLM)
* **CodeLens Buttons**: Contextual "Fix with AI Assist", "Preview Engine Fix", "Ignore", and "Dismiss" actions appear on relevant lines
* **Smart Caching**: Only re-analyzes functions that actually changed
* **Multi-Language**: Python, TypeScript, JavaScript, TSX, JSX, Go
* **Engine-backed cleanup previews**: Safe cleanup actions are previewed from Skylos engine output when an engine patch is available
* **Framework-Aware Detection**: Handles Flask, Django, FastAPI routes and decorators
* **Secrets Scanning**: Detects API keys & secrets (GitHub, GitLab, Slack, Stripe, AWS, Google, SendGrid, Twilio, private key blocks)
* **Dangerous Patterns**: Flags risky code such as `eval/exec`, `os.system`, `subprocess(shell=True)`, `pickle.load/loads`, `yaml.load` without SafeLoader, hashlib.md5/sha1. Refer to `DANGEROUS_CODE.md` for the whole list.

Static analysis runs locally on your machine. AI Assist features are optional; they only send code to a configured provider when you explicitly use AI Assist commands or enable real-time AI Assist.

## How it works

**Static Analysis (Skylos CLI)**
On save, the extension scans the current file by default. Full workspace scans are explicit:
```
skylos <workspace-folder> --json -c <confidence> [--secrets] [--danger] [--quality]
```

**Optional AI Assist**
Manual AI Assist commands and chat use your configured provider. Real-time AI Assist is off by default; when enabled, the extension waits for idle, extracts changed functions, and sends them to the configured AI provider.

## Requirements

1. Python 3.10+
2. Skylos engine installed (`pip install skylos`) and available on `PATH`, or set an explicit path via `skylos.path`
3. (Optional) OpenAI or Anthropic API key for cloud AI features, or a local AI server for fully offline analysis

## Installation

Install `Skylos` for VS Code from the marketplace.

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

- **Save any file** → Skylos CLI refreshes findings for that file
- **Type and pause** → nothing leaves your machine unless `skylos.enableRealtimeAI` is enabled
- **Click "Fix with AI Assist"** on any error line to auto-fix
- **Command Palette** → `Skylos: Scan Workspace` for a full project scan

### Optional Real-Time AI Assist

Real-time AI is off by default so normal static scans do not make network calls. To enable it:

1. Set `skylos.enableRealtimeAI` to `true`
2. Configure an AI Assist provider or local OpenAI-compatible server
3. Optionally set `skylos.streamingInline` to `true` for ghost-text streaming

When enabled, typing in a supported file starts analysis after the idle delay. If streaming inline is also enabled, `analyzing...` ghost text appears on function lines and streamed findings are rendered inline until normal diagnostics take over.

If you start typing again during analysis, the previous stream is cancelled and a new one starts.

To disable all automatic AI Assist, keep `skylos.enableRealtimeAI` set to `false`.

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
- Dead code findings are skipped unless Skylos provides an engine-backed cleanup patch
- Capped at 50 findings per run (change with `skylos.autoFixMaxFindings`)
- 200ms delay between API calls to avoid rate limits
- Cancellable via the progress notification
- Preview-first mode (`skylos.fixPreviewFirst`, on by default) — always shows a diff before applying
- Optional post-fix validation command (`skylos.postFixCommand`) — runs your tests/linter after each fix, with one-click undo if it fails

### Local AI (Ollama, LM Studio, etc.)

You can use any OpenAI-compatible local server instead of a cloud API. No API key needed — everything stays on your machine.

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

That's it — 3 lines. All AI features (inline analysis, chat, auto-fix) work with local models. No API key, no cloud, everything stays on your machine.

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
| `skylos.excludeFolders` | string[] | `["venv",".venv","build","dist",".git","__pycache__"]` | Exclude these folders |
| `skylos.runOnSave` | boolean | `true` | Run Skylos on save |
| `skylos.scanOnOpen` | boolean | `true` | Auto scan the first supported file opened in the session |
| `skylos.enableSecrets` | boolean | `true` | Include secrets scanning |
| `skylos.enableDanger` | boolean | `true` | Include dangerous-pattern checks |
| `skylos.enableDeadCode` | boolean | `true` | Show dead code findings (functions, imports, classes, variables) |
| `skylos.showDeadParams` | boolean | `false` | Show unused parameter findings (noisy with callbacks/interfaces) |
| `skylos.enableQuality` | boolean | `true` | Include code quality checks |
| `skylos.showPopup` | boolean | `true` | Show toast notification after scans |
| `skylos.editorSignalLevel` | string | `"quiet"` | Editor visual noise: `quiet`, `balanced`, or `verbose` |
| `skylos.codeLensMode` | string | `"highValue"` | CodeLens frequency: `off`, `activeLine`, `highValue`, or `all` |
| `skylos.enableRealtimeAI` | boolean | `false` | Automatically run AI Assist as you edit |
| `skylos.aiProvider` | string | `"openai"` | AI Assist provider: `"openai"`, `"anthropic"`, or `"local"` |
| `skylos.openaiBaseUrl` | string | `"https://api.openai.com"` | Base URL for OpenAI API |
| `skylos.openaiApiKey` | string | `""` | OpenAI API key |
| `skylos.openaiModel` | string | `"gpt-4o"` | OpenAI model |
| `skylos.localBaseUrl` | string | `""` | URL of your local AI server (e.g. `http://localhost:11434`) |
| `skylos.localModel` | string | `""` | Model name on your local server (e.g. `llama3.1`) |
| `skylos.anthropicApiKey` | string | `""` | Anthropic API key |
| `skylos.anthropicModel` | string | `"claude-sonnet-4-20250514"` | Anthropic model for analysis |
| `skylos.idleMs` | number | `1000` | Milliseconds to wait before optional real-time AI Assist |
| `skylos.popupCooldownMs` | number | `8000` | Cooldown between AI popups (ms) |
| `skylos.streamingInline` | boolean | `false` | Show streaming ghost text when real-time AI Assist is enabled |
| `skylos.autoFixMaxFindings` | number | `50` | Max findings to auto-fix per run (1-200) |
| `skylos.diffBase` | string | `"origin/main"` | Git ref for delta mode base |
| `skylos.fixPreviewFirst` | boolean | `true` | Always show diff preview before applying AI Assist fixes |
| `skylos.postFixCommand` | string | `""` | Shell command to run after AI Assist fix (e.g. `npm test`, `pytest -x`) |

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

- Static analysis runs entirely on your machine
- AI features send only changed function code to your configured provider (OpenAI/Anthropic/local server)
- Chat messages are sent to your configured provider — no third parties
- With a local AI server, all AI Assist analysis stays entirely on your machine
- No telemetry, no data collection

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
