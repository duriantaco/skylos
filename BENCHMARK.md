# Technical Rationale for Benchmark Selection and Design

## 1. Overview

The benchmark suite used to evaluate Python static-analysis tools, specifically how accurate it can detect unused code (dead code). Given Python’s dynamic features, we tried to design a benchmark that is fair and objective.

### 1.1 Definition 

This is the way we define dead code. 

1. Unused Definitions

* Functions/Methods: Defined but not explicitly or implicitly called anywhere within the analyzed codebase. This includes both global functions and class methods, excluding implicitly invoked special methods like `__init__`, `__enter__`, and `__exit__` which Skylos considers automatically used due to Python’s built-in invocation mechanisms.

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

The benchmark contains relatively diverse scenarios that represent practical coding patterns in Python. It includes:

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


## Results

## Benchmark Results For test/sample_repo

### Overall Performance (All Dead Code Types Combined)

| Tool | Time (s) | Items | TP | FP | FN | Precision | Recall | F1 Score |
|------|----------|-------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **0.013** | **34** | **22** | **12** | **7** | **0.6471** | **0.7586** | **0.6984** |
| Vulture (0%) | 0.054 | 32 | 11 | 20 | 18 | 0.3548 | 0.3793 | 0.3667 |
| Vulture (60%) | 0.044 | 32 | 11 | 20 | 18 | 0.3548 | 0.3793 | 0.3667 |
| Flake8 | 0.371 | 16 | 5 | 7 | 24 | 0.4167 | 0.1724 | 0.2439 |
| Pylint | 0.705 | 11 | 0 | 8 | 29 | 0.0000 | 0.0000 | 0.0000 |
| Ruff | 0.140 | 16 | 5 | 7 | 24 | 0.4167 | 0.1724 | 0.2439 |

### Performance by Dead Code Type

#### Class Detection (Ground Truth: 4 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **4** | **1** | **0** | **0.8000** | **1.0000** | **0.8889** |
| Vulture (0%) | 4 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Vulture (60%) | 4 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

#### Function Detection (Ground Truth: 6 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **5** | **4** | **1** | **0.5556** | **0.8333** | **0.6667** |
| Vulture (0%) | 5 | 4 | 1 | 0.5556 | 0.8333 | 0.6667 |
| Vulture (60%) | 5 | 4 | 1 | 0.5556 | 0.8333 | 0.6667 |
| Ruff | 0 | 0 | 6 | 0.0000 | 0.0000 | 0.0000 |

#### Import Detection (Ground Truth: 9 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| Skylos (Local Dev) | 3 | 5 | 3 | 0.3750 | 0.5000 | 0.4286 |
| Vulture (0%) | 2 | 3 | 4 | 0.4000 | 0.3333 | 0.3636 |
| Vulture (60%) | 2 | 3 | 4 | 0.4000 | 0.3333 | 0.3636 |
| **Flake8** | **5** | **7** | **1** | **0.4167** | **0.8333** | **0.5556** |
| Pylint | 0 | 7 | 6 | 0.0000 | 0.0000 | 0.0000 |
| **Ruff** | **5** | **7** | **1** | **0.4167** | **0.8333** | **0.5556** |

#### Method Detection (Ground Truth: 13 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **10** | **2** | **3** | **0.8333** | **0.7692** | **0.8000** |
| Vulture (0%) | 0 | 12 | 13 | 0.0000 | 0.0000 | 0.0000 |
| Vulture (60%) | 0 | 12 | 13 | 0.0000 | 0.0000 | 0.0000 |

## Benchmark Results For `Test/Cases`

### Overall Performance (All Dead Code Types Combined)

| Tool | Time (s) | Items | TP | FP | FN | Precision | Recall | F1 Score |
|------|----------|-------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **0.020** | **24** | **18** | **3** | **5** | **0.8571** | **0.7826** | **0.8182** |
| Vulture (0%) | 0.057 | 30 | 17 | 7 | 6 | 0.7083 | 0.7391 | 0.7234 |
| Vulture (60%) | 0.043 | 30 | 17 | 7 | 6 | 0.7083 | 0.7391 | 0.7234 |
| Flake8 | 0.336 | 9 | 6 | 3 | 17 | 0.6667 | 0.2609 | 0.3750 |
| Pylint | 2.494 | 3 | 0 | 3 | 23 | 0.0000 | 0.0000 | 0.0000 |
| Ruff | 0.133 | 10 | 6 | 4 | 17 | 0.6000 | 0.2609 | 0.3636 |

### Performance by Dead Code Type

#### Class Detection (Ground Truth: 3 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **2** | **0** | **0** | **1.0000** | **1.0000** | **1.0000** |
| Vulture (0%) | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |
| Vulture (60%) | 2 | 0 | 0 | 1.0000 | 1.0000 | 1.0000 |

#### Function Detection (Ground Truth: 10 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| Skylos (Local Dev) | 6 | 2 | 2 | 0.7500 | 0.7500 | 0.7500 |
| **Vulture (0%)** | **8** | **3** | **0** | **0.7273** | **1.0000** | **0.8421** |
| **Vulture (60%)** | **8** | **3** | **0** | **0.7273** | **1.0000** | **0.8421** |
| Ruff | 0 | 0 | 8 | 0.0000 | 0.0000 | 0.0000 |

#### Import Detection (Ground Truth: 7 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| Skylos (Local Dev) | 6 | 1 | 1 | 0.8571 | 0.8571 | 0.8571 |
| **Vulture (0%)** | **7** | **0** | **0** | **1.0000** | **1.0000** | **1.0000** |
| **Vulture (60%)** | **7** | **0** | **0** | **1.0000** | **1.0000** | **1.0000** |
| Flake8 | 6 | 3 | 1 | 0.6667 | 0.8571 | 0.7500 |
| Pylint | 0 | 2 | 7 | 0.0000 | 0.0000 | 0.0000 |
| Ruff | 6 | 3 | 1 | 0.6667 | 0.8571 | 0.7500 |

#### Method Detection (Ground Truth: 7 items)

| Tool | TP | FP | FN | Precision | Recall | F1 Score |
|------|----|----|----|-----------|---------|---------| 
| **Skylos (Local Dev)** | **4** | **0** | **2** | **1.0000** | **0.6667** | **0.8000** |
| Vulture (0%) | 0 | 2 | 6 | 0.0000 | 0.0000 | 0.0000 |
| Vulture (60%) | 0 | 2 | 6 | 0.0000 | 0.0000 | 0.0000 |