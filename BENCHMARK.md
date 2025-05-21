# Technical Rationale for Benchmark Selection and Design

## 1. Overview

The benchmark suite used to evaluate Python static-analysis tools, specifically how accurate it can detect unused code (dead code). Given the complexity of Python’s dynamic features, a carefully designed benchmark is crucial for fair, objective, and comprehensive evaluation.

### 1.1 Definition 

This is the way we define dead code. 

1. Unused Definitions

* Functions/Methods: Defined but not explicitly or implicitly called anywhere within the analyzed codebase. This includes both global functions and class methods, excluding implicitly invoked special methods like __init__, __enter__, and __exit__ which Skylos considers automatically used due to Python’s built-in invocation mechanisms.

* Classes: Defined but not instantiated, inherited, or referenced explicitly within the analyzed codebase.

* Imports: Modules, classes, functions, or variables imported but never referenced in any execution path.

2. Explicit and Implicit Usage Detection: 

* A definition is considered as "used" if explicitly referenced by name (e.g., direct function calls, class instantiation).

3. Dynamic Code Consideration:

* Recognizes code accessed dynamically through Python’s introspective capabilities. However, Skylos marks dynamically accessed symbols with a lower confidence, acknowledging inherent uncertainty.

4. Export Handling:

* Definitions explicitly exported via Python’s `__all__` mechanism in `__init__.py` or module-level files are considered "used". The reason being is that they may be imported and utilized by external code not included in the current analysis scope.

## 2. Why This Benchmark was Chosen

### 2.1. Realistic Representation

The benchmark contains diverse scenarios that represent practical coding patterns in Python. It includes:

* **Basic cases** (unused functions, methods, and classes)
* **Imports** (unused imports, re-exports via `__init__.py`, cross-module imports)
* **Metaprogramming** (decorators, dynamically accessed methods via `getattr`, `globals()`)

These scenarios ensure that static-analysis tools are assessed against challenges typical in real-world codebases.

### 2.2. Ground Truth

Each test case has explicitly defined ground-truth in their respective JSON files. Ground truths include details such as line numbers, exact symbol names, and categories.

### 2.3. Quantitative and Objective Metrics

Metrics such as **Precision**, **Recall**, and **F1-score** provide clear, objective and quantifiable evaluation criteria:

* **Precision** measures correctness (few false positives).
* **Recall** measures completeness (few false negatives).
* **F1-score** balances precision and recall, critical for overall performance evaluation.

### 2.4. Multi-tool Comparative Approach

The benchmark evaluates multiple popular static-analysis tools (`Vulture`, `Skylos`, `Flake8`, `Pylint`, `Ruff`). The choice of tools was based on their prominence, distinct detection methodologies, and diverse detection capabilities.

## 3. Technical Justification for Test Categorization

Tests are intentionally split into categories (**functions, methods, classes, imports, variables**) due to the differences in how tools approach dead-code detection.

### 3.1. Functions and Methods

* **Static Detection**: Tools like `Vulture` and `Skylos` rely on AST (Abstract Syntax Tree) analysis. They identify unused definitions by checking explicit references in code.
* **Dynamic Considerations**: Methods invoked via Python's magic methods (`__init__`, `__enter__`, `__exit__`) or dynamically accessed (e.g., using `getattr`) must be handled specially, often through heuristics to avoid false positives.

### 3.2. Classes

* A class might appear unused explicitly but could be instantiated implicitly through reflection, metaprogramming, or factory patterns.

* The benchmark explicitly tests these edge cases. This is to ensure tools correctly balance static analysis and heuristic approaches.

### 3.3. Imports

* Unused import detection differs notably between tools. For instance, `Flake8` primarily detects unused imports explicitly listed but does not deeply analyze usage patterns. In contrast, `Vulture` and `Skylos` analyze deeper references within modules, including re-exported names via `__all__`.
* Therefore, explicit categorization of import tests is vital to highlight tool differences clearly.

### 3.4. Variables

* Tools such as `Pylint` and `Ruff` detect unused variables by analyzing assignment and usage within scopes. This requires precise AST-based scope analysis.
* Evaluating this separately ensures clearer insights into each tool's capability in variable scope handling.

## 4. How Each Tool’s Approach Differs

### 4.1. Vulture

* **Method**: Dual-pass AST analysis. First pass collects definitions; second pass tracks references across module boundaries. 

* **Special Handling**: Supports confidence levels, ignores dynamically accessed attributes based on configurable confidence thresholds. Proably one of the best ones out there. 

### 4.2. Skylos

* **Method**: Advanced AST traversal with heuristic handling for dynamic references, auto-called methods (`__init__`, etc.), and explicit support for `__all__` exports.

* **Differentiator**: Combines exact-scope matching with sophisticated heuristics to minimize false negatives arising from dynamic Python constructs.

### 4.3. Flake8

* **Method**: Primarily checks explicit static import statements (`F401`). Minimal dynamic handling.
* **Differentiator**: Simplicity and speed, but limited scope.

### 4.4. Pylint

* **Method**: Broader static analysis with custom rules. Good at detecting simple unused imports, variables, and arguments.

* **Differentiator**: Lots of rulesets but not as good in deep cross-module static analysis for dead-code.

### 4.5. Ruff

* **Method**: Extremely extremely fast, syntax-based rule-checking tool. Checks for unused imports, variables, and unreachable code (F401, F811, F841).

* **Differentiator**: Optimized for performance (I think ruff might be the fastest out there), suitable for rapid checks but shallow compared to dedicated AST-based tools.

## 5. Benchmark Limitations and Trade-offs

* **Dynamic Patterns**: Static analysis tools will inherently struggle with dynamic Python code. Benchmarks may thus unintentionally bias towards static-detection-friendly scenarios.

* **Ground Truth Accuracy**: Human error in ground-truth definitions could introduce inaccuracies.

* **Scope**: Certain highly complex patterns (deep metaprogramming or runtime-generated code) might be underrepresented.

## 6. Technical Choices Explained

* **Use of AST-based Detection**: AST parsing allows precise symbol resolution and scope analysis, critical for accurate dead-code detection.

* **Explicit JSON Ground Truth**: JSON provides structured, automated comparisons avoiding subjective judgments.

* **Separate Metrics per Code Type**: Separating metrics by category clearly identifies each tool’s strengths and weaknesses, guiding developers toward informed choices.

## 7. Conclusion

We tried our best LOL. 
