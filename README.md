# Skylos 🔍

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![100% Local](https://img.shields.io/badge/privacy-100%25%20local-brightgreen)
![PyPI version](https://img.shields.io/pypi/v/skylos)
![Security Policy](https://img.shields.io/badge/security-policy-brightgreen)

<div align="center">
   <img src="assets/SKYLOS.png" alt="Skylos Logo" width="200">
</div>

> A static analysis tool for Python codebases written in Python that detects unreachable functions and unused imports, aka dead code. Faster and better results than many alternatives like Flake8 and Pylint, and finding more dead code than Vulture in our tests with comparable speed.

<div align="center">
   <img src="assets/FE_SS.png" alt="FE" width="800">
</div>


## Table of Contents

- [Features](#features)
- [Benchmark](#benchmark-you-can-find-this-benchmark-test-in-test-folder)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Web Interface](#web-interface)
- [Design](#design)
- [Test File Detection](#test-file-detection)
- [Folder Management](#folder-management)
- [Ignoring Pragmas](#ignoring-pragmas)
- [Including & Excluding Files](#including--excluding-files)
- [CLI Options](#cli-options)
- [Example Output](#example-output)
- [Interactive Mode](#interactive-mode)
- [Development](#development)
- [FAQ](#faq)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)
- [Contact](#contact)

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

## Benchmark (You can find this benchmark test in `test` folder)

The benchmark checks how well static analysis tools spot dead code in Python. Things such as unused functions, classes, imports, variables, that kinda stuff. To read more refer down below.

**The methodology and process for benchmarking can be found in `BENCHMARK.md`** 

| Tool | Time (s) | Items | TP | FP | FN | Precision | Recall | F1 Score |
|------|----------|-------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **0.013** | **34** | **22** | **12** | **7** | **0.6471** | **0.7586** | **0.6984** |
| Vulture (0%) | 0.054 | 32 | 11 | 20 | 18 | 0.3548 | 0.3793 | 0.3667 |
| Vulture (60%) | 0.044 | 32 | 11 | 20 | 18 | 0.3548 | 0.3793 | 0.3667 |
| Flake8 | 0.371 | 16 | 5 | 7 | 24 | 0.4167 | 0.1724 | 0.2439 |
| Pylint | 0.705 | 11 | 0 | 8 | 29 | 0.0000 | 0.0000 | 0.0000 |
| Ruff | 0.140 | 16 | 5 | 7 | 24 | 0.4167 | 0.1724 | 0.2439 |

To run the benchmark:
`python compare_tools.py /path/to/sample_repo`

**Note: More can be found in `BENCHMARK.md`**

## Installation

### Basic Installation

```bash
pip install skylos
```

### From Source

```bash
git clone https://github.com/duriantaco/skylos.git
cd skylos

pip install .
```

## Quick Start

```bash
skylos /path/to/your/project

# To launch the front end
skylos run

# Interactive mode - select items to remove
skylos --interactive /path/to/your/project 

# Dry run - see what would be removed
skylos --interactive --dry-run /path/to/your/project 

skylos --json /path/to/your/project 

# With confidence
skylos path/to/your/file --confidence 20 ## or whatever value u wanna set
```

## Web Interface

Skylos includes a modern web dashboard for interactive analysis:

```bash
skylos run

# Opens browser at http://localhost:5090
```

## Design

### Summary 

Framework endpoints are often invoked externally (eg, via HTTP, signals), so we use framework aware signals + confidence scores to try avoid false positives while still catching dead codes

Name resolution handles aliases and modules, but when things get ambiguous, we rather miss some dead code than accidentally mark live code as dead lmao

Tests are excluded by default because their call patterns are noisy. You can opt in when you really need to audit it

### Understanding Confidence Levels

Skylos uses a confidence-based system to try to handle Python's dynamic nature and web frameworks.

### How Confidence Works

- **Confidence 100**: 100% unused (default imports, obvious dead functions)
- **Confidence 60**: Default value - conservative detection 
- **Confidence 40**: Framework helpers, functions in web app files
- **Confidence 20**: Framework routes, decorated functions
- **Confidence 0**: Show everything

### Framework Detection

When Skylos detects web framework imports (Flask, Django, FastAPI), it applies different confidence levels:

```bash
# only obvious dead codes
skylos app.py --confidence 60  # THIS IS THE DEFAULT

# include unused helpers in framework files  
skylos app.py --confidence 30

# include potentially unused routes
skylos app.py --confidence 20

# everything.. shows how all potential dead code
skylos app.py --confidence 0
```

## Test File Detection

Skylos automatically excludes test files from analysis because test code patterns often appear as "dead code" but are actually called by test frameworks. Should you need to include them in your test, just refer to the [Folder Management](#folder-management)  

### What Gets Detected as Test Files

**File paths containing:**
- `/test/` or `/tests/` directories
- Files ending with `_test.py`

**Test imports:**
- `pytest`, `unittest`, `nose`, `mock`, `responses`

**Test decorators:**  
- `@pytest.fixture`, `@pytest.mark.*`
- `@patch`, `@mock.*`

### Test File Behavior

When Skylos detects a test file, it by default, will apply a confidence penalty of 100, which will essentially filter out all dead code detection

```bash
# This will show 0 dead code because its treated as test file
/project/tests/test_user.py
/project/test/helper.py  
/project/utils_test.py

# The files will be analyzed normally. Note that it doesn't end with _test.py
/project/user.py
/project/test_data.py 
```

## Ignoring Pragmas

To ignore any warning, indicate `# pragma: no skylos` **ON THE SAME LINE** as the function/class you want to ignore

Example

```python
    def with_logging(self, enabled: bool = True) -> "WebPath":     # pragma: no skylos
        new_path = WebPath(self._url)
        return new_path
```

## Including & Excluding Files

### Default Exclusions
By default, Skylos excludes common folders: `__pycache__`, `.git`, `.pytest_cache`, `.mypy_cache`, `.tox`, `htmlcov`, `.coverage`, `build`, `dist`, `*.egg-info`, `venv`, `.venv`

### Folder Options
```bash
skylos --list-default-excludes

# Exclude single folder (The example here will be venv)
skylos /path/to/your/project --exclude-folder venv 

# Exclude multiple folders
skylos /path/to/your/project --exclude-folder venv --exclude-folder build

# Force include normally excluded folders
skylos /path/to/your/project --include-folder venv 

# Scan everything (no exclusions)
skylos path/to/your/project --no-default-excludes 
```

## CLI Options
```
Usage: skylos [OPTIONS] PATH

Arguments:
  PATH  Path to the Python project to analyze

Options:
  -h, --help                   Show this help message and exit
  --json                       Output raw JSON instead of formatted text  
  -o, --output FILE            Write output to file instead of stdout
  -v, --verbose                Enable verbose output
  -i, --interactive            Interactively select items to remove
  --dry-run                    Show what would be removed without modifying files
  --exclude-folder FOLDER      Exclude a folder from analysis (can be used multiple times)
  --include-folder FOLDER      Force include a folder that would otherwise be excluded
  --no-default-excludes        Don't exclude default folders (__pycache__, .git, venv, etc.)
  --list-default-excludes      List the default excluded folders and
  -c, --confidence LEVEL       Confidence threshold (0-100). Lower values will show more items.
```

## Interactive Mode

The interactive mode lets you select specific functions and imports to remove:

1. **Select items**: Use arrow keys and `spacebar` to select/unselect
2. **Confirm changes**: Review selected items before applying
3. **Auto-cleanup**: Files are automatically updated

## Development

### Prerequisites

- `Python ≥3.9`
- `pytest`
- `inquirer`

### Setup

```bash
git clone https://github.com/duriantaco/skylos.git
cd skylos

python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Running Tests

```bash
python -m pytest tests/
```

## FAQ 

**Q: Why doesn't Skylos find 100% of dead code?**
A: Python's dynamic features (getattr, globals, etc.) can't be perfectly analyzed statically. No tool can achieve 100% accuracy. If they say they can, they're lying.

**Q: Why are the results different on my codebase?**
A: These benchmarks use specific test cases. Your code patterns (frameworks, legacy code, etc.) will give different results.

**Q: Are these benchmarks realistic?**
A: They test common scenarios but can't cover every edge case. Use them as a guide, not gospel.

**Q: Should I automatically delete everything flagged as unused?**
A: No. Always review results manually, especially for framework code, APIs, and test utilities.

**Q: Why did Ruff underperform?**
A: Like all other tools, Ruff is focused on detecting specific, surface-level issues. Tools like Vulture and Skylos are built SPECIFICALLY for dead code detection. It is NOT a specialized dead code detector. If your goal is dead code, then ruff is the wrong tool. It is a good tool but it's like using a wrench to hammer a nail. Good tool, wrong purpose. 

**Q: Why doesn't Skylos detect my unused Flask routes?**
A: Web framework routes are given low confidence (20) because they might be called by external HTTP requests. Use `--confidence 20` to see them. We acknowledge there are current limitations to this approach so use it sparingly.

**Q: What confidence level should I use?**
A: Start with 60 (default) for safe cleanup. Use 30 for framework applications. Use 20 for more comprehensive auditing.

## Limitations

- **Dynamic code**: `getattr()`, `globals()`, runtime imports are hard to detect
- **Frameworks**: Django models, Flask, FastAPI routes may appear unused but aren't
- **Test data**: Limited scenarios, your mileage may vary
- **False positives**: Always manually review before deleting code

## Troubleshooting

### Common Issues

1. **Permission Errors**
   ```
   Error: Permission denied when removing function
   ```
   Check file permissions before running in interactive mode.

2. **Missing Dependencies**
   ```
   Interactive mode requires 'inquirer' package
   ```
   Install with: `pip install skylos[interactive]`

## Contributing

We welcome contributions! Please read our [Contributing Guidelines](CONTRIBUTING.md) before submitting pull requests.

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Roadmap
- [x] Expand our test cases
- [ ] Configuration file support 
- [ ] Git hooks integration
- [ ] CI/CD integration examples
- [ ] Further optimization

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: oha
- **Email**: aaronoh2015@gmail.com
- **GitHub**: [@duriantaco](https://github.com/duriantaco)