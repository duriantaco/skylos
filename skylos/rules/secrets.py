from __future__ import annotations
import re, ast
from math import log2

__all__ = ["scan_ctx"]

ALLOWED_FILE_SUFFIXES = (".py", ".pyi", ".pyw")

PROVIDER_PATTERNS = [
    ("github", re.compile(r"(ghp|gho|ghu|ghs|ghr|gpat)_[A-Za-z0-9]{36,}")),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("slack", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,48}")),
    ("stripe", re.compile(r"sk_(live|test)_[A-Za-z0-9]{16,}")),
    (
        "aws_access_key_id",
        re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA)[0-9A-Z]{16}\b"),
    ),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("sendgrid", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("twilio", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    (
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----"),
    ),
]

GENERIC_VALUE = re.compile(r"""(?ix)
    (?:
      (token|api[_-]?key|secret|password|passwd|pwd|bearer|auth[_-]?token|access[_-]?token)
      \s*[:=]\s*(?P<q>['"])(?P<val>[^'"]{16,})(?P=q)
    )
    |
    (?P<bare>
      (?=[A-Za-z0-9_-]{32,}\b)
      (?=.*[A-Z])
      (?=.*[a-z])
      (?=.*\d)
      [A-Za-z0-9_-]+
    )
""")

SAFE_TEST_HINTS = {
    "example",
    "sample",
    "fake",
    "placeholder",
    "dummy",
    "test_",
    "_test",
    "test_test_",
    "changeme",
    "password",
    "secret",
    "not_a_real",
    "do_not_use",
}

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

IGNORE_DIRECTIVE = "skylos: ignore[SKY-S101]"
DEFAULT_MIN_ENTROPY = 3.9

IS_TEST_PATH = re.compile(r"(^|/)(tests?(/|$)|test_[^/]+\.py$)")


def _entropy(s):
    if len(s) == 0:
        return 0.0

    char_counts = {}
    for character in s:
        if character in char_counts:
            char_counts[character] += 1
        else:
            char_counts[character] = 1

    total_chars = len(s)
    entropy = 0.0

    for count in char_counts.values():
        probability = count / total_chars
        entropy -= probability * log2(probability)

    return entropy


def _mask(tok):
    token_length = len(tok)

    if token_length <= 8:
        return "*" * token_length

    else:
        first_part = tok[:4]
        last_part = tok[-4:]
        return first_part + "…" + last_part


def _looks_like_identifier(s):
    return bool(_IDENTIFIER.fullmatch(s))


def _docstring_lines(tree):
    if tree is None:
        return set()

    docstring_line_numbers = set()

    def find_docstring_lines(node):
        if not hasattr(node, "body") or not node.body:
            return

        first_statement = node.body[0]

        is_expression = isinstance(first_statement, ast.Expr)
        if not is_expression:
            return

        value = getattr(first_statement, "value", None)
        if not isinstance(value, ast.Constant):
            return

        if not isinstance(value.value, str):
            return

        start_line = getattr(first_statement, "lineno", None)
        end_line = getattr(first_statement, "end_lineno", start_line)

        if start_line is not None:
            if end_line is None:
                end_line = start_line

            for line_num in range(start_line, end_line + 1):
                docstring_line_numbers.add(line_num)

    if isinstance(tree, ast.Module):
        find_docstring_lines(tree)

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            find_docstring_lines(node)

    return docstring_line_numbers


def scan_ctx(
    ctx,
    *,
    min_entropy=DEFAULT_MIN_ENTROPY,
    scan_comments=True,
    scan_docstrings=True,
    allowlist_patterns=None,
    ignore_path_substrings=None,
    ignore_tests=True,
):
    rel_path = ctx.get("relpath", "")
    if not rel_path.endswith(ALLOWED_FILE_SUFFIXES):
        return []

    if ignore_tests and IS_TEST_PATH.search(rel_path.replace("\\", "/")):
        return []

    if ignore_path_substrings:
        for substring in ignore_path_substrings:
            if substring and substring in rel_path:
                return []

    file_lines = ctx.get("lines") or []
    syntax_tree = ctx.get("tree")

    allowlist_regexes = []
    if allowlist_patterns:
        for pattern in allowlist_patterns:
            compiled_regex = re.compile(pattern)
            allowlist_regexes.append(compiled_regex)

    if scan_docstrings:
        docstring_lines = set()
    else:
        docstring_lines = _docstring_lines(syntax_tree)

    findings = []

    for line_number, raw_line in enumerate(file_lines, start=1):
        line_content = raw_line.rstrip("\n")

        if IGNORE_DIRECTIVE in line_content:
            continue

        stripped_line = line_content.lstrip()
        if not scan_comments and stripped_line.startswith("#"):
            continue

        if not scan_docstrings and line_number in docstring_lines:
            continue

        should_skip_line = False
        for regex_pattern in allowlist_regexes:
            if regex_pattern.search(line_content):
                should_skip_line = True
                break

        if should_skip_line:
            continue

        for provider_name, pattern_regex in PROVIDER_PATTERNS:
            pattern_matches = pattern_regex.finditer(line_content)

            for regex_match in pattern_matches:
                potential_secret = regex_match.group(0)

                token_lowercase = potential_secret.lower()
                has_safe_hint = False

                for safe_hint in SAFE_TEST_HINTS:
                    if safe_hint in token_lowercase:
                        has_safe_hint = True
                        break

                if has_safe_hint:
                    continue

                col_pos = line_content.find(potential_secret)

                finding = {
                    "rule_id": "SKY-S101",
                    "severity": "CRITICAL",
                    "provider": provider_name,
                    "message": f"Potential {provider_name} secret detected",
                    "file": rel_path,
                    "line": line_number,
                    "col": max(0, col_pos),
                    "end_col": max(1, col_pos + len(potential_secret)),
                    "preview": _mask(potential_secret),
                }
                findings.append(finding)

        aws_key_indicators = ["AWS_SECRET_ACCESS_KEY", "aws_secret_access_key"]
        line_has_aws_key = False

        for indicator in aws_key_indicators:
            if indicator in line_content or indicator in line_content.lower():
                line_has_aws_key = True
                break

        if line_has_aws_key:
            aws_secret_pattern = r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"
            aws_match = re.search(aws_secret_pattern, line_content)

            if aws_match:
                aws_token = aws_match.group(1)
                tok_entropy = _entropy(aws_token)

                if tok_entropy >= min_entropy:
                    col_pos = line_content.find(aws_token)

                    aws_finding = {
                        "rule_id": "SKY-S101",
                        "severity": "CRITICAL",
                        "provider": "aws_secret_access_key",
                        "message": "Potential AWS secret access key detected",
                        "file": rel_path,
                        "line": line_number,
                        "col": max(0, col_pos),
                        "end_col": max(1, col_pos + len(aws_token)),
                        "preview": _mask(aws_token),
                        "entropy": round(tok_entropy, 2),
                    }
                    findings.append(aws_finding)

        in_tests = bool(IS_TEST_PATH.search(rel_path.replace("\\", "/")))

        if in_tests:
            generic_match = None
        else:
            generic_match = GENERIC_VALUE.search(line_content)

        if generic_match:
            val_group = generic_match.group("val")
            bare_group = generic_match.group("bare")

            is_bare = False
            if val_group:
                extracted_token = val_group
            elif bare_group:
                extracted_token = bare_group
                is_bare = True
            else:
                extracted_token = ""

            clean_token = extracted_token.strip()

            if clean_token:
                if is_bare and _looks_like_identifier(clean_token):
                    continue

                token_lowercase = clean_token.lower()
                has_safe_hint = False

                for safe_hint in SAFE_TEST_HINTS:
                    if safe_hint in token_lowercase:
                        has_safe_hint = True
                        break

                if not has_safe_hint:
                    tok_entropy = _entropy(clean_token)

                    if tok_entropy >= min_entropy and len(clean_token) >= 20:
                        col_pos = line_content.find(clean_token)

                        generic_finding = {
                            "rule_id": "SKY-S101",
                            "severity": "CRITICAL",
                            "provider": "generic",
                            "message": f"High-entropy value detected (entropy={tok_entropy:.2f})",
                            "file": rel_path,
                            "line": line_number,
                            "col": max(0, col_pos),
                            "end_col": max(1, col_pos + len(clean_token)),
                            "preview": _mask(clean_token),
                            "entropy": round(tok_entropy, 2),
                        }
                        findings.append(generic_finding)

    return findings
