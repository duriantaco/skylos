# Skylos 🔍

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![100% Local](https://img.shields.io/badge/privacy-100%25%20local-brightgreen)
![PyPI version](https://img.shields.io/pypi/v/skylos)
![100% Dead Code Free](https://img.shields.io/badge/Dead%20Code-100%25%20Free-brightgreen)

<div align="center">
   <img src="assets/SKYLOS.png" alt="Skylos Logo" width="200">
</div>

> A static analysis tool for Python codebases written in Rust that detects unreachable functions and unused imports, aka dead code. Faster and better results than many alternatives like Flake8 and Pylint, and finding more dead code than Vulture in our tests with comparable speed.

## Features

- **Unreachable Function Detection**: Find functions and methods that are never called aka dead code
- **Unused Import Detection**: Imports that are never used
- **High Performance**: Built with Rust
- **Nice Output**: Colorized CLI output
- **Interactive Mode**: Select and remove specific items interactively
- **Dry Run Support**: Preview changes before applying them
- **Auto-removal**: Auto clean up
- **Cross-module Analysis**: Tracks imports and calls across your entire project

## Benchmark (You can find this benchmark test in `test/sample_project`)

| Tool | Time (s) | Functions | Imports | Total |
|------|----------|-----------|---------|-------|
| Skylos | 0.039 | 48 | 8 | 56 |
| Vulture (100%) | 0.040 | 0 | 3 | 3 |
| Vulture (60%) | 0.041 | 28 | 3 | 31 |
| Vulture (0%) | 0.041 | 28 | 3 | 31 |
| Flake8 | 0.274 | 0 | 8 | 8 |
| Pylint | 0.285 | 0 | 6 | 6 |
| Dead | 0.035 | 0 | 0 | 0 |

## Installation

### Basic Installation

```bash
pip install skylos
```

### With Interactive Features

For the interactive selection mode, install with:

```bash
pip install skylos[interactive]
```

### From Source

```bash
# Clone the repository
git clone https://github.com/duriantaco/skylos.git
cd skylos

# Install maturin (if not already installed)
pip install maturin

# Build and install
maturin develop
```

## Quick Start

```bash
# Analyze a project
skylos /path/to/your/project

# Interactive mode - select items to remove
skylos /path/to/your/project --interactive

# Dry run - see what would be removed
skylos /path/to/your/project --interactive --dry-run

# Output to JSON
skylos /path/to/your/project --json
```

## CLI Options

```
Usage: skylos [OPTIONS] PATH

Arguments:
  PATH  Path to the Python project to analyze

Options:
  -h, --help              Show this help message and exit
  -j, --json             Output raw JSON instead of formatted text
  -o, --output FILE      Write output to file instead of stdout
  -v, --verbose          Enable verbose output
  -i, --interactive      Interactively select items to remove
  --dry-run              Show what would be removed without modifying files
```

## Example Output

```
🔍 Python Static Analysis Results
===================================

Summary:
  • Unreachable functions: 48
  • Unused imports: 8

📦 Unreachable Functions
========================
 1. module_13.test_function
    └─ /Users/oha/project/module_13.py:5
 2. module_13.unused_function
    └─ /Users/oha/project/module_13.py:13
...

📥 Unused Imports
=================
 1. os
    └─ /Users/oha/project/module_13.py:1
 2. json
    └─ /Users/oha/project/module_13.py:3
...

Next steps:
  • Use --interactive to select specific items to remove
  • Use --dry-run to preview changes before applying them
```

## Interactive Mode

The interactive mode lets you select specific functions and imports to remove:

![Interactive Demo](docs/interactive-demo.gif)

1. **Select items**: Use arrow keys and space to select/deselect
2. **Confirm changes**: Review selected items before applying
3. **Auto-cleanup**: Files are automatically updated

## Architecture

Skylos uses a hybrid architecture combining Rust and Python:

- **Rust Core**: Fast tree-sitter based parsing and analysis
- **Python CLI**: User-friendly interface and file manipulation
- **maturin**: Seamless Python-Rust integration

### Core Components

```
skylos/
├── src/lib.rs          # Main Rust analysis engine
├── src/queries.rs      # Tree-sitter query definitions
├── src/types.rs       # Data structures for results
├── src/utils.rs       # Helper functions
├── skylos/
│   └── cli.py         # Python CLI interface
└── pyproject.toml     # Project configuration
```

## Development

### Prerequisites

- Python ≥3.8
- Rust and Cargo
- maturin

### Setup

```bash
# Clone the repository
git clone https://github.com/duriantaco/skylos.git
cd skylos

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install maturin inquirer pytest

# Build in development mode
maturin develop
```

### Running Tests

```bash
# Run Rust tests
cd src
cargo test

# Run Python tests
python -m pytest tests/
```

### Adding New Features

1. **Rust Analysis**: Add new queries in `src/queries.rs`
2. **Python CLI**: Extend functionality in `skylos/cli.py`
3. **Documentation**: Update this README and add docstrings

## Configuration

Skylos supports configuration via `.skylos.toml` (coming soon):

```toml
[analysis]
# Exclude patterns
exclude = [
    "*/migrations/*",
    "*/tests/*",
    "__pycache__"
]

# Custom patterns for dead code detection
patterns = [
    "test_*",      # Test functions
    "_*_internal"  # Internal functions
]

[output]
# Default output format
format = "colored"  # Options: colored, plain, json

# Color scheme
colors = "default"  # Options: default, dark, light
```

## Limitations 

- Occassionally there will be false positives and false negatives especially for extreme edge cases 

- The library is currently available **ONLY** for python

## Troubleshooting

### Common Issues

1. **Tree-sitter Errors**
   ```
   Error: tree-sitter parse failed
   ```
   Ensure your Python files have valid syntax.

2. **Permission Errors**
   ```
   Error: Permission denied when removing function
   ```
   Check file permissions before running in interactive mode.

3. **Missing Dependencies**
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

- [ ] Configuration file support (White lists etc)
- [ ] Custom analysis rules
- [ ] Git hooks integration
- [ ] CI/CD integration examples
- [ ] Web interface
- [ ] Support for other languages
- [ ] Further optimization

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [tree-sitter](https://tree-sitter.github.io/) for the powerful parsing framework
- [maturin](https://github.com/PyO3/maturin) for seamless Rust-Python integration
- [inquirer](https://github.com/magmax/python-inquirer) for the interactive CLI

## Contact

- **Author**: oha
- **Email**: aaronoh2015@gmail.com
- **GitHub**: [@duriantaco](https://github.com/duriantaco)