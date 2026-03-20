# Coding Standards for Automated Cleanup

## 1. Constants & Magic Values

- Extract numeric literals (other than 0, 1, -1) used in logic to named constants.
- Extract repeated string literals (used 2+ times) to named constants.
- Constants should be UPPER_SNAKE_CASE and defined at module level or class level.
- Exception: loop bounds like `range(10)` in tests or throwaway scripts are acceptable.

## 2. Exception Handling

- No bare `except:` — always catch a specific exception type.
- No silent exception swallowing (`except SomeError: pass`) without a comment explaining why.
- Use the most specific exception type possible (e.g., `KeyError` not `Exception`).
- Re-raise or log exceptions rather than silently dropping them.
- Avoid `except Exception as e: return None` patterns that hide bugs.

## 3. Function Size & Complexity

- Functions should be ≤50 lines of logic (excluding docstrings, blank lines, comments).
- Cyclomatic complexity should be ≤10 per function.
- Maximum nesting depth: 3 levels (e.g., function → if → for is OK; function → if → for → if is too deep).
- Extract deeply nested blocks into helper functions with descriptive names.

## 4. Type Hints

- All public functions must have parameter type hints and return type annotations.
- Private/internal functions should have return type annotations at minimum.
- Use `X | None` instead of `Optional[X]` (Python 3.10+).
- Use built-in generics (`list[str]`, `dict[str, int]`) instead of `typing.List`, `typing.Dict`.

## 5. Input Validation

- Public API functions should validate inputs early (fail-fast).
- Check for None, empty strings, invalid ranges at function entry.
- Raise `ValueError` or `TypeError` with descriptive messages.
- Don't validate deeply inside private helper functions — validate at the boundary.

## 6. Naming Conventions

- Functions and variables: `snake_case`
- Classes: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`
- Private members: `_leading_underscore`
- Avoid single-letter variable names except in comprehensions and short lambdas.
- Boolean variables/parameters should read as predicates (e.g., `is_valid`, `has_items`).

## 7. Dead Patterns

- Remove commented-out code blocks (more than 2 consecutive commented lines of code).
- Remove unused imports.
- Remove unused variables that are assigned but never read.
- Remove empty functions/methods that only contain `pass` with no docstring.

## 8. Security Hygiene

- No hardcoded secrets, API keys, passwords, or tokens in source code.
- Use parameterized queries for database operations — never string concatenation/f-strings for SQL.
- Validate and sanitize external input before use.
- Don't log sensitive data (passwords, tokens, PII).
