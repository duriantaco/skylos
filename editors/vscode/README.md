# Skylos for VS Code

> A static analysis tool for Python codebases written in Python that detects unreachable functions and unused imports, aka dead code. Faster and better results than many alternatives like Flake8 and Pylint, and finding more dead code than Vulture in our tests with comparable speed.

<img src="screenshot1.png" alt="Skylos VS Code Extension showing AI-detected issue with Fix and Dismiss buttons" width="800" />

## Features

* **AI-Powered Analysis**: Real-time bug detection as you type using GPT-4 or Claude — no save required
* **Multi-Provider Support**: Choose between OpenAI and Anthropic for AI analysis
* **CodeLens Buttons**: "Fix with AI" and "Dismiss" buttons appear inline on error lines
* **Streaming Fixes**: See fix progress in real-time as the AI generates code
* **Smart Caching**: Only re-analyzes functions that actually changed
* **CST-safe removals**: Uses LibCST to remove selected imports or functions (handles multiline imports, aliases, decorators, async etc..)
* **Framework-Aware Detection**: Attempt at handling Flask, Django, FastAPI routes and decorators  
* **Test File Exclusion**: Auto excludes test files (you can include it back if you want)
* **Interactive Cleanup**: Select specific items to remove from CLI
* **Unused Functions & Methods**: Finds functions and methods that not called
* **Unused Classes**: Detects classes that are not instantiated or inherited
* **Unused Imports**: Identifies imports that are not used
* **Folder Management**: Inclusion/exclusion of directories 
* **Ignore Pragmas**: Skip lines tagged with `# pragma: no skylos`, `# pragma: no cover`, or `# noqa`
* **Secrets Scanning (PoC, opt-in)**: Detects API keys & secrets (GitHub, GitLab, Slack, Stripe, AWS, Google, SendGrid, Twilio, private key blocks)
* **Dangerous Patterns**: Flags risky code such as `eval/exec`, `os.system`, `subprocess(shell=True)`, `pickle.load/loads`, `yaml.load` without SafeLoader, hashlib.md5/sha1. Refer to `DANGEROUS_CODE.md` for the whole list.

All analysis runs locally on your machine. AI features require an API key.

## How it works

**Static Analysis (Skylos CLI)**  
On save of a Python file, the extension runs:
```
skylos <workspace-folder> --json -c <confidence> [--secrets] [--danger] [--quality]
```

**AI Analysis**  
As you type, the extension waits for idle (default 2s), extracts changed functions, and sends them to the configured AI provider for bug detection.

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

Open your Python project in VS Code and save a .py file — diagnostics appear.

## Usage

- Save any Python file → Skylos CLI scans the workspace
- Type and pause → AI analyzes changed functions
- Click "Fix with AI" on any error line to auto-fix
- Run full project scan: Command Palette → `Skylos: Scan Workspace`
- Ignore a single line: Quick Fix → `Skylos: ignore on this line`

## Settings

Open Settings → Extensions → Skylos (or settings.json):

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| `skylos.path` | string | `"skylos"` | Path to the Skylos executable |
| `skylos.confidence` | number | `60` | Confidence threshold (0-100) |
| `skylos.excludeFolders` | string[] | `["venv",".venv","build","dist",".git","__pycache__"]` | Exclude these folders |
| `skylos.runOnSave` | boolean | `true` | Run Skylos on save |
| `skylos.enableSecrets` | boolean | `true` | Include secrets scanning |
| `skylos.enableDanger` | boolean | `true` | Include dangerous-pattern checks |
| `skylos.enableQuality` | boolean | `true` | Include code quality checks |
| `skylos.aiProvider` | string | `"openai"` | AI provider: `"openai"` or `"anthropic"` |
| `skylos.openaiApiKey` | string | `""` | OpenAI API key |
| `skylos.openaiModel` | string | `"gpt-4o-mini"` | OpenAI model for analysis |
| `skylos.anthropicApiKey` | string | `""` | Anthropic API key |
| `skylos.anthropicModel` | string | `"claude-sonnet-4-20250514"` | Anthropic model for analysis |
| `skylos.idleMs` | number | `2000` | Milliseconds to wait before AI analysis |
| `skylos.popupCooldownMs` | number | `15000` | Cooldown between AI popups (ms) |

## Commands

| Command | Description |
|---------|-------------|
| `Skylos: Scan Workspace` | Run skylos over the entire workspace |
| `Skylos: Fix Issue` | Fix the issue at cursor with AI |

## Privacy

- Static analysis runs entirely on your machine
- AI features send only changed function code to your configured provider (OpenAI/Anthropic)
- No telemetry, no data collection

## Contributing

PRs welcome!

- Extension code: `src/extension.ts`

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