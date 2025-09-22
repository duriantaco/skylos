# Skylos for VS Code

> A static analysis tool for Python codebases written in Python that detects unreachable functions and unused imports, aka dead code. Faster and better results than many alternatives like Flake8 and Pylint, and finding more dead code than Vulture in our tests with comparable speed.

## Features

* **CST-safe removals:** Uses LibCST to remove selected imports or functions (handles multiline imports, aliases, decorators, async etc..)
* **Framework-Aware Detection**: Attempt at handling Flask, Django, FastAPI routes and decorators  
* **Test File Exclusion**: Auto excludes test files (you can include it back if you want)
* **Interactive Cleanup**: Select specific items to remove from CLI
* **Unused Functions & Methods**: Finds functions and methods that not called
* **Unused Classes**: Detects classes that are not instantiated or inherited
* **Unused Imports**: Identifies imports that are not used
* **Folder Management**: Inclusion/exclusion of directories 
* **Ignore Pragmas**: Skip lines tagged with `# pragma: no skylos`, `# pragma: no cover`, or `# noqa`
**NEW** **Secrets Scanning (PoC, opt-in)**: Detects API keys & secrets (GitHub, GitLab, Slack, Stripe, AWS, Google, SendGrid, Twilio, private key blocks)
**NEW** **Dangerous Patterns**: Flags risky code such as `eval/exec`, `os.system`, `subprocess(shell=True)`, `pickle.load/loads`, `yaml.load` without SafeLoader, hashlib.md5/sha1. Refer to `DANGEROUS_CODE.md` for the whole list.

All analysis runs locally on your machine.

## How it works

On save of a Python file, the extension runs:

`skylos <that-file> --json -c <confidence> [--secrets] [--danger]`

If your Skylos build does not support `--danger`, the extension skips it automatically.

## Requirements

1. Python 3.9

Skylos engine installed (`pip install skylos`) and available on `PATH`, or set an explicit path via setting skylos.path.

## Installation

Install `Skylos` for VS Code from the marketplace.

Make sure skylos runs in a terminal:

`skylos --version`

If not, run:

`pip install skylos`

Open your Python project in VS Code and save a .py file — diagnostics appear.

## Usage

- Save any Python file -> Skylos scans that file

- Run a full project scan: Command Palette -> `Skylos: Scan Workspace Now`

- Ignore a single line: Quick Fix -> `Skylos: ignore on this line` (adds # pragma: no skylos).

## Settings

Open Settings -> Extensions ->  Skylos (or settings.json):

| Setting | Type | Default | Description |
|---------|------|---------|-------------|
| skylos.path | string | skylos | Path to the Skylos executable|
| skylos.confidence | number | 60 | Confidence threshold |
| skylos.excludeFolders | string | ["venv",".venv","build","dist",".git","__pycache__"] | Exclude these folders for workspace scans |
| skylos.runOnSave | boolean | true | Run Skylos automatically when saving a Python file |
| skylos.enableSecrets | boolean | true | Include secrets scanning (--secrets) |
| skylos.enableDanger | boolean | true | Include dangerous-pattern checks (--danger)|
| skylos.showPopup | boolean | true | Show a toast after scans |


## Commands

`Skylos: Scan Workspace Now`. This will run `skylos --json` over the entire workspace

## Privacy

- Your code never leaves your machine.
- Results are read from Skylos' local JSON output only

## Contributing

PRs welcome!

- Extension code: `src/extension.ts`

- Pack & test locally:

```bash
npm run compile
# Press F5 or fn + F5 in VSC to launch the "extension development host"
```

- Package a VSIX:
```bash
npm run package
```

## License
Apache-2.0