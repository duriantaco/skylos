# Skylos 🔍

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![100% Local](https://img.shields.io/badge/privacy-100%25%20local-brightgreen)
![PyPI version](https://img.shields.io/pypi/v/skylos)

<div align="center">
   <img src="assets/SKYLOS.png" alt="Skylos Logo" width="200">
</div>

> A static analysis tool for Python codebases written in Python (formerly was written in Rust but we ditched that) that detects unreachable functions and unused imports, aka dead code. Faster and better results than many alternatives like Flake8 and Pylint, and finding more dead code than Vulture in our tests with comparable speed.

## Features

* Unused Functions & Methods: Finds functions and methods that are never called
* Unused Classes: Detects classes that are never instantiated or inherited
* Unused Imports: Identifies imports that serve no purpose
* Cross-Module Tracking: Analyzes usage patterns across your entire codebase

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
# Clone the repository
git clone https://github.com/duriantaco/skylos.git
cd skylos

## Install your dependencies 
pip install .
```

## Quick Start

```bash
# Analyze a project
skylos /path/to/your/project

# Interactive mode - select items to remove
skylos --interactive /path/to/your/project 

# Dry run - see what would be removed
skylos --interactive --dry-run /path/to/your/project 

# Output to JSON
skylos --json /path/to/your/project 
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

## Development

### Prerequisites

- `Python ≥3.9`
- `pytest`
- `inquirer`

### Setup

```bash
# Clone the repository
git clone https://github.com/duriantaco/skylos.git
cd skylos

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Running Tests

```bash
# Run Python tests
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

## Limitations

- **Dynamic code**: `getattr()`, `globals()`, runtime imports are hard to detect
- **Frameworks**: Django models, Flask routes may appear unused but aren't
- **Test data**: Limited scenarios, your mileage may vary
- **False positives**: Always manually review before deleting code

If we can detect 100% of all dead code in any structure, we wouldn't be sitting here. But we definitely tried our best

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

- [ ] Expand our test cases
- [ ] Configuration file support 
- [ ] Custom analysis rules
- [ ] Git hooks integration
- [ ] CI/CD integration examples
- [ ] Web interface
- [ ] Support for other languages
- [ ] Further optimization

## License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.

## Contact

- **Author**: oha
- **Email**: aaronoh2015@gmail.com
- **GitHub**: [@duriantaco](https://github.com/duriantaco)