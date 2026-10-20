"""Comprehensive test coverage for all quality/logic rules.

Each rule gets at least 1 positive (triggers) and 1 negative (clean) test.
Rules already covered in test_logic.py: L001, L002, L003.
"""

import ast
from difflib import SequenceMatcher

from skylos.core.linter import LinterVisitor
from skylos.rules.quality import clones as clones_mod
from skylos.rules.ai_defect import PhantomCallRule
from skylos.rules.quality.logic import (
    TryBlockPatternsRule,
    UnusedExceptVarRule,
    ReturnConsistencyRule,
    EmptyErrorHandlerRule,
    MissingResourceCleanupRule,
    DebugLeftoverRule,
    SecurityTodoRule,
    DisabledSecurityRule,
    InsecureRandomRule,
    HardcodedCredentialRule,
    MockPlaceholderDataRule,
    DuplicateStringLiteralRule,
    TooManyReturnsRule,
    BooleanTrapRule,
    ErrorDisclosureRule,
    BroadFilePermissionsRule,
)
from skylos.rules.quality.unreachable import UnreachableCodeRule
from skylos.rules.quality.performance import PerformanceRule


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(code)
    visitor = LinterVisitor([rule], filename)
    visitor.context.update({"mod": "test_module", "source": code})
    visitor.visit(tree)
    return visitor.findings


def test_clone_similarity_threshold_keeps_possible_matches(monkeypatch):
    monkeypatch.setattr(clones_mod, "_fast_similarity", None)
    a = "a" * 89
    b = ("a" * 89) + ("b" * 11)

    assert SequenceMatcher(a=a, b=b).ratio() >= 0.9
    assert clones_mod._similarity(a, b, threshold=0.9) >= 0.9


def test_clone_group_type_tie_uses_canonical_order():
    select_type = clones_mod._select_group_clone_type

    assert select_type([clones_mod.CloneType.TYPE2, clones_mod.CloneType.TYPE1]) == (
        clones_mod.CloneType.TYPE1
    )
    assert select_type([clones_mod.CloneType.TYPE3, clones_mod.CloneType.TYPE2]) == (
        clones_mod.CloneType.TYPE2
    )


def test_clone_group_type_prefers_most_common_type():
    assert (
        clones_mod._select_group_clone_type(
            [
                clones_mod.CloneType.TYPE3,
                clones_mod.CloneType.TYPE1,
                clones_mod.CloneType.TYPE3,
            ]
        )
        == clones_mod.CloneType.TYPE3
    )


def test_clone_group_type_empty_defaults_to_type3():
    assert clones_mod._select_group_clone_type([]) == clones_mod.CloneType.TYPE3


def test_group_pairs_uses_canonical_type_for_tied_edges():
    def fragment(name, line):
        return clones_mod.Fragment(
            file_path="sample.py",
            start_line=line,
            end_line=line + 10,
            name=name,
            kind="function",
            node_count=10,
            text_norm=name,
            ast_norm_type2=name,
            ast_norm_type3=name,
        )

    first = fragment("first", 1)
    second = fragment("second", 20)
    third = fragment("third", 40)
    pairs = [
        clones_mod.ClonePair(
            a=first,
            b=second,
            similarity=0.99,
            clone_type=clones_mod.CloneType.TYPE3,
        ),
        clones_mod.ClonePair(
            a=second,
            b=third,
            similarity=0.99,
            clone_type=clones_mod.CloneType.TYPE2,
        ),
    ]

    for ordered_pairs in (pairs, list(reversed(pairs))):
        groups = clones_mod.group_pairs(ordered_pairs, clones_mod.CloneConfig())
        assert len(groups) == 1
        assert groups[0].clone_type == clones_mod.CloneType.TYPE2


# --- SKY-L004: Try Block Patterns ---


class TestTryBlockPatterns:
    def test_oversized_try_block(self):
        # A try inside a conditional is not the whole-function exemption.
        lines = ["def f():", "    if ready:", "        try:"]
        for i in range(20):
            lines.append(f"            x{i} = {i}")
        lines.extend(
            [
                "            try:",
                "                work()",
                "            except ValueError:",
                "                recover()",
                "        except Exception:",
                "            pass",
            ]
        )
        code = "\n".join(lines)
        from skylos.analysis.file_processing import TRY_NODE_TYPES

        assert len(TRY_NODE_TYPES) == len(set(TRY_NODE_TYPES))
        rule = TryBlockPatternsRule(max_lines=15)
        rule.node_types = TRY_NODE_TYPES
        findings = check_code(rule, code)
        assert any(f["value"] == 24 for f in findings)
        # The one-call inner catch is already narrow; only the broad outer
        # scope is actionable.
        assert not any(f["value"] == "nested" for f in findings)

    def test_small_try_block_ok(self):
        # Cleanup scope must include all protected work. It catches no errors,
        # even when the body is large, branches, or contains an actual catch.
        lines = ["async def f():", '    "doc"', "    try:"]
        lines.extend(f"        x{i} = {i}" for i in range(16))
        lines.extend(f"        if condition{i}: pass" for i in range(4))
        lines.extend(
            [
                "        try:",
                "            work()",
                "        except ValueError:",
                "            recover()",
                "    finally:",
                "        cleanup()",
            ]
        )
        code = "\n".join(lines)
        rule = TryBlockPatternsRule(max_lines=15)
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L004" for f in findings)

    # 18 code lines and 4 ifs remain actionable; the one-call inner catch does
    # not create another problem merely by being nested.
    BIG_BODY = [
        "a1 = f(1)",
        *[f"if a{i}:\n    a{i + 1} = f({i + 1})" for i in range(1, 5)],
        "try:\n    a6 = f(6)\nexcept KeyError:\n    a6 = None",
        *[f"a{i} = f({i})" for i in range(7, 12)],
    ]

    @classmethod
    def _wrapped(cls, handlers, prefix=("total = 0",), header="def run(items):"):
        lines = [header, *[f"    {line}" for line in prefix], "    try:"]
        for stmt in cls.BIG_BODY:
            lines.extend(f"        {line}" for line in stmt.split("\n"))
        lines.extend(f"    {line}" for line in handlers)
        return "\n".join(lines)

    @staticmethod
    def _l004_values(code):
        findings = check_code(TryBlockPatternsRule(max_lines=15), code)
        return sorted(str(f["value"]) for f in findings if f["rule_id"] == "SKY-L004")

    def test_reraising_handlers_catch_nothing(self):
        bare = ["except Exception:", "    cleanup()", "    raise"]
        as_name = ["except ValueError as err:", "    raise err"]
        assert self._l004_values(self._wrapped(bare)) == []
        assert self._l004_values(self._wrapped(as_name)) == []

        translated = ["except ValueError as err:", "    raise RuntimeError() from err"]
        conditional = [
            "except ValueError:",
            "    if items:",
            "        return None",
            "    raise",
        ]
        assert self._l004_values(self._wrapped(translated)) == ["18", "4"]
        assert self._l004_values(self._wrapped(conditional)) == ["18", "4"]

    def test_finally_that_discards_the_exception_is_checked(self):
        cleanup = ["finally:", "    cleanup()"]
        returns = ["finally:", "    return total"]
        assert self._l004_values(self._wrapped(cleanup)) == []
        assert self._l004_values(self._wrapped(returns)) == ["18", "4"]

    def test_length_counts_code_lines_only(self):
        def body(code_lines):
            lines = ["def run():", "    total = 0", "    try:"]
            for i in range(code_lines):
                lines.append(f"        x{i} = {i}  # inline comment")
                lines.extend(["", "        # comment-only line"])
            lines.extend(
                ['        """String statement', '        used as a comment."""']
            )
            lines.extend(["    except ValueError:", "        return None"])
            return "\n".join(lines)

        assert self._l004_values(body(15)) == []
        assert self._l004_values(body(16)) == ["16"]

    def test_per_item_and_import_fallback_inner_tries_are_not_nested(self):
        per_item = """
def run(items):
    total = 0
    try:
        for item in items:
            try:
                use(item)
            except ValueError:
                skip(item)
    except OSError:
        return None
"""
        import_fallback = """
try:
    try:
        import json5 as jsonlib
    except (ImportError, ModuleNotFoundError):
        import json as jsonlib
except ImportError:
    jsonlib = None
"""
        direct = """
def run(items):
    total = 0
    try:
        if items:
            try:
                use(items)
            except ValueError:
                skip(items)
    except OSError:
        return None
"""
        assert self._l004_values(per_item) == []
        assert self._l004_values(import_fallback) == []
        assert self._l004_values(direct) == []

    def test_function_level_boundary_skips_size_and_branching(self):
        # Size and branching of a whole-function try are the function's own
        # metrics; a narrow nested catch is also already precise.
        prefix = (
            '"""Doc."""',
            "import os",
            "def helper(value):",
            "    return value",
            "if not items:",
            "    return []",
            "if items is None:",
            "    raise ValueError('items')",
        )
        handlers = ["except ValueError:", "    return None"]
        boundary = self._wrapped(handlers, prefix=prefix)
        assert self._l004_values(boundary) == []
        assert self._l004_values(self._wrapped(handlers, prefix=())) == []
        # 18 code lines and 9 ifs, no inner try.
        flat = ["def run(items):", "    try:"]
        flat += [f"        if items > {i}:\n            x{i} = {i}" for i in range(9)]
        flat += ["    except ValueError:", "        return None"]
        assert self._l004_values("\n".join(flat)) == []

        all_checks = ["18", "4"]
        guard_with_else = ("if not items:", "    return []", "else:", "    use(items)")
        assert (
            self._l004_values(self._wrapped(handlers, prefix=guard_with_else))
            == all_checks
        )
        assert self._l004_values(self._wrapped(handlers)) == all_checks


# --- SKY-L005: Unused Exception Variable ---


class TestUnusedExceptVar:
    def test_unused_exception(self):
        code = """
try:
    x = 1
except ValueError as e:
    pass
"""
        rule = UnusedExceptVarRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L005" for f in findings)

    def test_used_exception(self):
        code = """
try:
    x = 1
except ValueError as e:
    print(e)
"""
        rule = UnusedExceptVarRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L005" for f in findings)

    def test_underscore_prefix_flagged(self):
        code = """
try:
    x = 1
except ValueError as _e:
    pass
"""
        rule = UnusedExceptVarRule()
        findings = check_code(rule, code)
        # Rule flags underscore-prefixed vars as unused too
        assert any(f["rule_id"] == "SKY-L005" for f in findings)


# --- SKY-L006: Inconsistent Return ---


class TestReturnConsistency:
    def test_inconsistent_return(self):
        code = """
def f(x):
    if x:
        return x
    return
"""
        rule = ReturnConsistencyRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L006" for f in findings)

    def test_consistent_return(self):
        code = """
def f(x):
    if x:
        return x
    return x + 1
"""
        rule = ReturnConsistencyRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L006" for f in findings)


# --- SKY-L007: Empty Error Handler ---


class TestEmptyErrorHandler:
    def test_except_pass(self):
        code = """
try:
    x = 1
except:
    pass
"""
        rule = EmptyErrorHandlerRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_except_with_logging(self):
        code = """
try:
    x = 1
except Exception as e:
    logger.error(e)
"""
        rule = EmptyErrorHandlerRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_narrow_return_fallback_not_flagged(self):
        code = """
def parse(value):
    try:
        return int(value)
    except ValueError:
        return None
"""
        rule = EmptyErrorHandlerRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_narrow_pass_fallback_not_flagged(self):
        code = """
try:
    x = 1
except ValueError:
    pass
"""
        rule = EmptyErrorHandlerRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L007" for f in findings)


# --- SKY-L008: Missing Resource Cleanup ---


class TestMissingResourceCleanup:
    def test_open_without_with(self):
        code = """
def f():
    f = open("file.txt")
    data = f.read()
"""
        rule = MissingResourceCleanupRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L008" for f in findings)

    def test_open_with_context_manager(self):
        code = """
def f():
    with open("file.txt") as f:
        data = f.read()
"""
        rule = MissingResourceCleanupRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L008" for f in findings)


# --- SKY-L009: Debug Leftover ---


class TestDebugLeftover:
    def test_print_statement(self):
        code = """
def f():
    print("debug")
"""
        rule = DebugLeftoverRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L009" for f in findings)

    def test_breakpoint(self):
        code = """
def f():
    breakpoint()
"""
        rule = DebugLeftoverRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L009" for f in findings)

    def test_logger_call_ok(self):
        code = """
def f():
    logger.info("message")
"""
        rule = DebugLeftoverRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L009" for f in findings)


# --- SKY-L010: Security TODO ---


class TestSecurityTodo:
    def test_todo_in_string_literal(self, tmp_path):
        # Production supplies the parsed source; the filename is only a label.
        src = 'def f():\n    """# TODO: fix authentication bypass"""\n    pass\n'
        p = tmp_path / "test_todo.py"
        rule = SecurityTodoRule()
        tree = ast.parse(src)
        context = {"filename": str(p), "mod": "test_module", "source": src}
        findings = []
        for node in ast.walk(tree):
            res = rule.visit_node(node, context)
            if res:
                findings.extend(res)
        assert any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_no_todo(self, tmp_path):
        src = 'def f():\n    x = "# TODO: rotate access_token; auth"\n'
        p = tmp_path / "clean.py"
        rule = SecurityTodoRule()
        tree = ast.parse(src)
        context = {"filename": str(p), "mod": "test_module", "source": src}
        findings = []
        for node in ast.walk(tree):
            res = rule.visit_node(node, context)
            if res:
                findings.extend(res)
        assert not any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_security_terms_match_whole_words(self, tmp_path):
        lines = [
            "# XXX Move the prefix computation into a wrapper around tokenize.",
            "# TODO: ask the author about this branch",
            "# TODO: certainly slow, profile later",
            "# TODO: oracle connection pooling",
            "# TODO: configure SSLContext",
            "# TODO: prevent SQLi",
            "# HACK: verify=False until certs are rotated",
        ]
        src = "\n".join(lines) + "\n"
        rule = SecurityTodoRule()
        context = {"filename": str(tmp_path / "notes.py"), "source": src}
        findings = rule.visit_node(ast.parse(src), context) or []
        assert [f["line"] for f in findings] == [5, 6, 7]


# --- SKY-L011: Disabled Security ---


class TestDisabledSecurity:
    def test_verify_false(self):
        code = """
import requests
requests.get("https://example.com", verify=False)
"""
        rule = DisabledSecurityRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L011" for f in findings)

    def test_verify_true_ok(self):
        code = """
import requests
requests.get("https://example.com", verify=True)
"""
        rule = DisabledSecurityRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L011" for f in findings)


# --- SKY-L012: Phantom Function Call ---


class TestPhantomCall:
    def test_phantom_security_call(self):
        # PhantomCallRule only flags calls to security-related function names
        code = """
def handler(request):
    sanitize_input(request.data)
"""
        rule = PhantomCallRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L012" for f in findings)

    def test_defined_security_function_ok(self):
        code = """
def sanitize_input(data):
    return data.strip()

def handler(request):
    sanitize_input(request.data)
"""
        rule = PhantomCallRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L012" for f in findings)

    def test_non_security_call_ignored(self):
        code = """
def f():
    result = some_func()
"""
        rule = PhantomCallRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L012" for f in findings)


# --- SKY-L013: Insecure Random ---


class TestInsecureRandom:
    def test_random_for_security(self):
        code = """
import random
token = random.randint(0, 999999)
"""
        rule = InsecureRandomRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L013" for f in findings)

    def test_secrets_module_ok(self):
        code = """
import secrets
token = secrets.token_hex(32)
"""
        rule = InsecureRandomRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L013" for f in findings)


# --- SKY-L014: Hardcoded Credential ---


class TestHardcodedCredential:
    def test_hardcoded_password(self):
        code = """
password = "mysecretpassword123"
"""
        rule = HardcodedCredentialRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_env_var_ok(self):
        code = """
import os
password = os.environ["PASSWORD"]
"""
        rule = HardcodedCredentialRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_positional_only_default(self):
        code = """
def connect(api_password: str = "mysecretpassword123", /) -> None:
    return None
"""
        rule = HardcodedCredentialRule()
        findings = check_code(rule, code, filename="app.py")
        assert [finding["name"] for finding in findings] == ["api_password"]


# --- SKY-L032: Mock Or Placeholder Data ---


class TestMockPlaceholderData:
    def test_obvious_production_placeholders(self):
        code = """
SUPPORT_EMAIL = "test@example.com"
USER_ID = "00000000-0000-0000-0000-000000000000"
PLACEHOLDER_PHONE = "123-456-7890"
API_PASSWORD = "password123"
"""
        rule = MockPlaceholderDataRule()
        findings = check_code(rule, code, filename="app.py")
        types = {f["mock_data_type"] for f in findings}
        assert {
            "placeholder_email",
            "low_entropy_uuid",
            "placeholder_phone",
            "test_credential",
        } <= types

    def test_skips_test_files(self):
        code = """
SUPPORT_EMAIL = "test@example.com"
API_PASSWORD = "password123"
"""
        rule = MockPlaceholderDataRule()
        findings = check_code(rule, code, filename="test_app.py")
        assert not any(f["rule_id"] == "SKY-L032" for f in findings)

    def test_domain_requires_mock_context(self):
        code = """
BASE_URL = "https://example.com"
SAMPLE_URL = "https://example.com/users"
"""
        rule = MockPlaceholderDataRule()
        findings = check_code(rule, code, filename="app.py")
        assert [f["name"] for f in findings] == ["SAMPLE_URL"]
        assert findings[0]["mock_data_type"] == "placeholder_domain"

    def test_positional_only_placeholder_default(self):
        code = """
def notify(support_email: str = "test@example.com", /) -> None:
    return None
"""
        rule = MockPlaceholderDataRule()
        findings = check_code(rule, code, filename="app.py")
        assert [finding["name"] for finding in findings] == ["support_email"]
        assert findings[0]["mock_data_type"] == "placeholder_email"

    def test_mixed_positional_defaults_preserve_names(self):
        code = """
def notify(
    required: str,
    protocol_email: str = "test@example.com",
    /,
    implementation_email: str = "test@example.com",
) -> None:
    return None
"""
        rule = MockPlaceholderDataRule()
        findings = check_code(rule, code, filename="app.py")
        assert [finding["name"] for finding in findings] == [
            "protocol_email",
            "implementation_email",
        ]

    def test_protocol_and_implementation_defaults_flagged(self):
        code = """
from typing import Protocol

class Notifier(Protocol):
    def notify(
        self,
        protocol_email: str = "test@example.com",
        /,
    ) -> None:
        ...

class ConcreteNotifier(Notifier):
    def notify(
        self,
        implementation_email: str = "test@example.com",
        /,
    ) -> None:
        return None
"""
        rule = MockPlaceholderDataRule()
        findings = check_code(rule, code, filename="app.py")
        assert {finding["name"] for finding in findings} == {
            "protocol_email",
            "implementation_email",
        }


# --- SKY-UC001: Unreachable Code ---


class TestUnreachableCode:
    def test_code_after_return(self):
        code = """
def f():
    return 1
    x = 2
"""
        rule = UnreachableCodeRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-UC001" for f in findings)

    def test_no_unreachable(self):
        code = """
def f():
    x = 1
    return x
"""
        rule = UnreachableCodeRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-UC001" for f in findings)

    def test_code_after_raise(self):
        code = """
def f():
    raise ValueError("bad")
    x = 2
"""
        rule = UnreachableCodeRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-UC001" for f in findings)


# --- SKY-P401-P403: Performance Rules ---


class TestPerformanceRules:
    def test_file_read_without_iteration(self):
        code = """
f = open('data.txt')
content = f.read()
"""
        rule = PerformanceRule(ignore_list=[])
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-P401" for f in findings)

    def test_pandas_read_csv_no_chunksize(self):
        code = """
import pandas as pd
df = pd.read_csv('data.csv')
"""
        rule = PerformanceRule(ignore_list=[])
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-P402" for f in findings)

    def test_pandas_read_csv_with_chunksize_ok(self):
        code = """
import pandas as pd
df = pd.read_csv('data.csv', chunksize=1000)
"""
        rule = PerformanceRule(ignore_list=[])
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-P402" for f in findings)

    def test_nested_loop(self):
        code = """
for item in data:
    for other in data:
        if item == other:
            pass
"""
        rule = PerformanceRule(ignore_list=[])
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-P403" for f in findings)

    def test_single_loop_ok(self):
        code = """
for item in data:
    process(item)
"""
        rule = PerformanceRule(ignore_list=[])
        findings = check_code(rule, code)
        assert not any(f["rule_id"].startswith("SKY-P") for f in findings)


# --- SKY-L027: Duplicate String Literal ---


class TestDuplicateStringLiteral:
    def test_many_duplicates(self):
        code = """
def f():
    a = "repeated_magic_string"
    b = "repeated_magic_string"
    c = "repeated_magic_string"
    d = "repeated_magic_string"
"""
        rule = DuplicateStringLiteralRule()
        findings = check_code(rule, code)
        finding = next(f for f in findings if f["rule_id"] == "SKY-L027")
        assert finding["name"] == "repeated_magic_string"
        assert "repeated_magic_string" in finding["message"]

    def test_repeated_secret_like_string_is_redacted(self):
        secret = "ghp_" + "1234567890" + "abcdefABCDEF1234567890abcd"
        code = f'''
def f():
    a = "{secret}"
    b = "{secret}"
    c = "{secret}"
'''
        rule = DuplicateStringLiteralRule()
        findings = check_code(rule, code)
        finding = next(f for f in findings if f["rule_id"] == "SKY-L027")

        assert finding["name"] == "[REDACTED_SECRET]"
        assert finding["simple_name"] == "[REDACTED_SECRET]"
        assert secret not in finding["message"]
        assert secret not in repr(finding)

    def test_repeated_password_like_string_is_redacted(self):
        secret = "prod_password_value_2026"
        code = f'''
def f():
    a = "{secret}"
    b = "{secret}"
    c = "{secret}"
'''
        rule = DuplicateStringLiteralRule()
        findings = check_code(rule, code)
        finding = next(f for f in findings if f["rule_id"] == "SKY-L027")

        assert finding["name"] == "[REDACTED_SECRET]"
        assert secret not in finding["message"]

    def test_unique_strings_ok(self):
        code = """
def f():
    a = "one"
    b = "two"
    c = "three"
"""
        rule = DuplicateStringLiteralRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L027" for f in findings)

    def test_repeated_dict_key_access_ok(self):
        code = """
def f(event):
    total = event["amount"]
    total += event["amount"]
    total += event["amount"]
    total += event["amount"]
    return total
"""
        rule = DuplicateStringLiteralRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L027" for f in findings)


# --- SKY-L028: Too Many Returns ---


class TestTooManyReturns:
    def test_too_many_returns(self):
        code = """
def f(x):
    if x == 1:
        return 1
    if x == 2:
        return 2
    if x == 3:
        return 3
    if x == 4:
        return 4
    if x == 5:
        return 5
    if x == 6:
        return 6
    return 0
"""
        rule = TooManyReturnsRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L028" for f in findings)

    def test_few_returns_ok(self):
        code = """
def f(x):
    if x:
        return 1
    return 0
"""
        rule = TooManyReturnsRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L028" for f in findings)


# --- SKY-L029: Boolean Trap ---


class TestBooleanTrap:
    def test_bool_param_default(self):
        code = """
def process(data, flatten=True, strict=False):
    pass
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L029" for f in findings)

    def test_bool_annotated_param(self):
        code = """
def process(data, flag: bool):
    pass
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L029" for f in findings)

    def test_no_bool_params_ok(self):
        code = """
def process(data, count=5):
    pass
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L029" for f in findings)

    def test_positional_only_bool_params(self):
        code = """
def render_page(page: str, recurse: bool = True, /, name: str = "index") -> str:
    return page

def paginate(page: str, deep=True, /, name: str = "index") -> str:
    return page

def log_page(verbose: bool = True, /) -> None:
    return None
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)
        l029 = [finding for finding in findings if finding["rule_id"] == "SKY-L029"]

        assert [finding["simple_name"] for finding in l029] == [
            "recurse",
            "deep",
        ]

    def test_positional_only_bool_variants_preserve_default_alignment(self):
        code = """
async def refresh(active: "bool", /) -> None:
    return None

def configure(label="plain", /, enabled=False) -> None:
    return None
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)
        l029 = [finding for finding in findings if finding["rule_id"] == "SKY-L029"]

        assert [finding["simple_name"] for finding in l029] == [
            "active",
            "enabled",
        ]

    def test_property_setter_value_is_not_a_boolean_trap_with_custom_receiver(self):
        code = """
class Settings:
    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(instance, value: bool, /) -> None:
        instance._enabled = value
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)

        assert not any(finding["rule_id"] == "SKY-L029" for finding in findings)

    def test_qualified_property_setter_value_is_not_a_boolean_trap(self):
        code = """
class Base:
    @property
    def enabled(self) -> bool:
        return False

class Settings(Base):
    @Base.enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)

        assert not any(finding["rule_id"] == "SKY-L029" for finding in findings)

    def test_property_setter_only_exempts_value_parameter(self):
        code = """
class Settings:
    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool, announce: bool = False) -> None:
        self._enabled = value
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)
        l029 = [finding for finding in findings if finding["rule_id"] == "SKY-L029"]

        assert [finding["simple_name"] for finding in l029] == ["announce"]

    def test_setter_lookalikes_do_not_exempt_parameter(self):
        code = """
@setter
def configure(enabled: bool) -> None:
    return None

@registry.setter
def publish(active: bool) -> None:
    return None

@broken.setter
def broken(value: bool) -> None:
    return None
"""
        rule = BooleanTrapRule()
        findings = check_code(rule, code)
        l029 = [finding for finding in findings if finding["rule_id"] == "SKY-L029"]

        assert [finding["simple_name"] for finding in l029] == [
            "enabled",
            "active",
            "value",
        ]


# --- SKY-L017: Error Disclosure ---


class TestErrorDisclosure:
    def test_traceback_in_response(self):
        code = """
import traceback
def handler():
    try:
        pass
    except Exception as e:
        return traceback.format_exc()
"""
        rule = ErrorDisclosureRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L017" for f in findings)
        assert "returned from an exception handler" in findings[0]["message"]
        assert "If sent to a client" in findings[0]["message"]

    def test_unnamed_handler_traceback_in_response(self):
        code = """
import traceback
from aiohttp import web
async def handler():
    try:
        pass
    except Exception:
        return web.Response(status=500, text=traceback.format_exc())
"""
        findings = check_code(ErrorDisclosureRule(), code)
        assert [f["value"] for f in findings] == ["traceback_leaked"]
        assert "stack trace" in findings[0]["message"]
        assert "passed to 'web.Response()'" in findings[0]["message"]

    def test_exception_text_is_not_called_a_stack_trace(self):
        code = """
from aiohttp import web
async def handler():
    try:
        pass
    except ValueError as e:
        return web.Response(status=400, text=str(e))
"""
        findings = check_code(ErrorDisclosureRule(), code)
        assert [f["value"] for f in findings] == ["exception_leaked"]
        assert "stack trace" not in findings[0]["message"]
        assert "passed to 'web.Response()'" in findings[0]["message"]

    def test_unnamed_handler_returning_traceback_from_helper_is_not_reported(self):
        code = """
import traceback
def compile_source(src):
    try:
        return compile(src, "<x>", "exec")
    except SyntaxError:
        return traceback.format_exc()
"""
        assert check_code(ErrorDisclosureRule(), code) == []

    def test_logged_exception_ok(self):
        code = """
def handler():
    try:
        pass
    except Exception as e:
        logger.error(e)
        return {"error": "Internal server error"}
"""
        rule = ErrorDisclosureRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L017" for f in findings)


# --- SKY-L020: Broad File Permissions ---


class TestBroadFilePermissions:
    def test_chmod_777(self):
        code = """
import os
os.chmod("file.txt", 0o777)
"""
        rule = BroadFilePermissionsRule()
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L020" for f in findings)

    def test_chmod_644_ok(self):
        code = """
import os
os.chmod("file.txt", 0o644)
"""
        rule = BroadFilePermissionsRule()
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L020" for f in findings)
