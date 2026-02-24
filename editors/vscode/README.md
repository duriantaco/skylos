# Skylos for VS Code

> Dead code detection, security scanning, and AI-powered code analysis for Python, TypeScript, JavaScript, and Go. Faster and better results than many alternatives like Flake8 and Pylint, and finding more dead code than Vulture in our tests with comparable speed.

<img src="media/vsce.gif" alt="Skylos VS Code Extension — inline dead code detection, security scanning, and CodeLens actions" width="800" />

## Features

* **Streaming Inline Analysis**: Ghost text appears character-by-character as the AI streams findings — see issues the instant they're detected
* **AI Security Copilot Chat**: Sidebar chat panel to ask questions about findings, get explanations, and apply fixes from code blocks
* **Auto-Remediation**: One-click "Fix All" with severity picker, progress tracking, and dry-run preview mode
* **AI-Powered Analysis**: Real-time bug detection as you type using GPT-4 or Claude — no save required
* **Multi-Provider Support**: Choose between OpenAI and Anthropic for AI analysis
* **CodeLens Buttons**: "Fix with AI" and "Dismiss" buttons appear inline on error lines
* **Smart Caching**: Only re-analyzes functions that actually changed
* **Multi-Language**: Python, TypeScript, JavaScript, TSX, JSX, Go
* **CST-safe removals**: Uses LibCST to remove selected imports or functions (handles multiline imports, aliases, decorators, async etc..)
* **Framework-Aware Detection**: Handles Flask, Django, FastAPI routes and decorators
* **Secrets Scanning**: Detects API keys & secrets (GitHub, GitLab, Slack, Stripe, AWS, Google, SendGrid, Twilio, private key blocks)
* **Dangerous Patterns**: Flags risky code such as `eval/exec`, `os.system`, `subprocess(shell=True)`, `pickle.load/loads`, `yaml.load` without SafeLoader, hashlib.md5/sha1. Refer to `DANGEROUS_CODE.md` for the whole list.

All analysis runs locally on your machine. AI features require an API key.

## How it works

**Static Analysis (Skylos CLI)**
On save, the extension runs:
```
skylos <workspace-folder> --json -c <confidence> [--secrets] [--danger] [--quality]
```

**AI Analysis**
As you type, the extension waits for idle (default 1s), extracts changed functions, and sends them to the configured AI provider for bug detection.

## Requirements

1. Python 3.10+
2. Skylos engine installed (`pip install skylos`) and available on `PATH`, or set an explicit path via `skylos.path`
3. (Optional) OpenAI or Anthropic API key for AI features

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

### Basic

- **Save any file** → Skylos CLI scans the workspace
- **Type and pause** → AI analyzes changed functions
- **Click "Fix with AI"** on any error line to auto-fix
- **Command Palette** → `Skylos: Scan Workspace` for a full project scan

### Streaming Inline Analysis

When you have an API key set, streaming analysis activates automatically:

1. Type in any supported file (Python, TS, JS, Go)
2. After the idle delay (default 1s), `analyzing...` ghost text appears on function lines
3. As the AI streams its response, issues appear character-by-character as blue italic text
4. When the stream completes, normal decorations and diagnostics take over

If you start typing again during analysis, the previous stream is cancelled and a new one starts.

To disable: set `skylos.streamingInline` to `false` in settings.

### AI Security Copilot Chat

The chat panel lives in the Skylos sidebar:

1. Open the **Skylos** sidebar (shield icon in the activity bar)
2. The **Security Copilot** panel is below Findings
3. Type a question about any security topic and get a streamed response

**Ask about a specific finding:**
- In the Findings tree, **right-click any finding** → **"Ask AI About Finding"**
- The chat panel opens with that finding's context (file, severity, surrounding code)
- Ask follow-up questions — the AI knows which finding you're looking at

**Apply fixes from chat:**
- Code blocks in AI responses have an **"Apply Fix"** button
- Click it to replace the enclosing function in your editor

**Clear history:** Click the clear button in the chat panel title bar, or run `Skylos: Clear Chat` from the command palette.

### Auto-Remediation (Fix All)

Fix multiple findings at once:

1. **`Cmd+Alt+F`** (Mac) / **`Ctrl+Alt+F`** (Windows/Linux), or Command Palette → `Skylos: Auto-Fix All`
2. Pick a severity level:
   - **Fix Errors Only** — CRITICAL + HIGH
   - **Fix Errors + Warnings** — + MEDIUM
   - **Fix All** — all severities
3. Confirm in the modal dialog
4. A progress notification shows each finding being fixed: `"Fixing 3/12: SKY-D203 in auth.py..."`
5. Each fix is a **separate undo step** — `Cmd+Z` to undo one fix at a time
6. After completion, Skylos re-scans to verify

**Dry Run** — preview fixes without editing:
1. Command Palette → `Skylos: Auto-Fix Dry Run`
2. Pick severity level
3. A markdown report opens with before/after code for each finding
4. No files are modified

**Safety:**
- Dead code findings are skipped (use Remove Import/Function instead)
- Capped at 50 findings per run (change with `skylos.autoFixMaxFindings`)
- 200ms delay between API calls to avoid rate limits
- Cancellable via the progress notification

## Settings

Open Settings → Extensions → Skylos (or settings.json):

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `skylos.path` | string | `"skylos"` | Path to the Skylos executable |
| `skylos.confidence` | number | `80` | Confidence threshold (0-100) |
| `skylos.excludeFolders` | string[] | `["venv",".venv","build","dist",".git","__pycache__"]` | Exclude these folders |
| `skylos.runOnSave` | boolean | `true` | Run Skylos on save |
| `skylos.scanOnOpen` | boolean | `true` | Auto scan workspace on open |
| `skylos.enableSecrets` | boolean | `true` | Include secrets scanning |
| `skylos.enableDanger` | boolean | `true` | Include dangerous-pattern checks |
| `skylos.enableDeadCode` | boolean | `true` | Show dead code findings (functions, imports, classes, variables) |
| `skylos.showDeadParams` | boolean | `false` | Show unused parameter findings (noisy with callbacks/interfaces) |
| `skylos.enableQuality` | boolean | `true` | Include code quality checks |
| `skylos.showPopup` | boolean | `true` | Show toast notification after scans |
| `skylos.aiProvider` | string | `"openai"` | AI provider: `"openai"` or `"anthropic"` |
| `skylos.openaiApiKey` | string | `""` | OpenAI API key |
| `skylos.openaiModel` | string | `"gpt-4o"` | OpenAI model for analysis |
| `skylos.anthropicApiKey` | string | `""` | Anthropic API key |
| `skylos.anthropicModel` | string | `"claude-sonnet-4-20250514"` | Anthropic model for analysis |
| `skylos.idleMs` | number | `1000` | Milliseconds to wait before AI analysis |
| `skylos.popupCooldownMs` | number | `8000` | Cooldown between AI popups (ms) |
| `skylos.streamingInline` | boolean | `true` | Show streaming ghost text during AI analysis |
| `skylos.autoFixMaxFindings` | number | `50` | Max findings to auto-fix per run (1-200) |

## Keyboard Shortcuts

| Shortcut | Command |
|----------|---------|
| `Cmd+Alt+S` / `Ctrl+Alt+S` | Scan Workspace |
| `Cmd+Alt+F` / `Ctrl+Alt+F` | Auto-Fix All |

## Commands

| Command | Description |
|---------|-------------|
| `Skylos: Scan Workspace` | Run skylos over the entire workspace |
| `Skylos: Fix Issue with AI` | Fix the issue at cursor with AI |
| `Skylos: Auto-Fix All` | Fix all findings with severity picker |
| `Skylos: Auto-Fix Dry Run` | Preview fixes without editing files |
| `Skylos: Ask AI About Finding` | Open chat with finding context (right-click in sidebar) |
| `Skylos: Clear Chat` | Clear chat history and context |
| `Skylos: Refresh` | Re-run scan |
| `Skylos: Clear All Findings` | Clear all findings from the panel |

## Privacy

- Static analysis runs entirely on your machine
- AI features send only changed function code to your configured provider (OpenAI/Anthropic)
- Chat messages are sent to your configured provider — no third parties
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