"""Comprehensive test coverage for all quality/logic rules.

Each rule gets at least 1 positive (triggers) and 1 negative (clean) test.
Rules already covered in test_logic.py: L001, L002, L003.
"""

import ast

from skylos.rules.quality.logic import (
    TryBlockPatternsRule,
    UnusedExceptVarRule,
    ReturnConsistencyRule,
    EmptyErrorHandlerRule,
    MissingResourceCleanupRule,
    DebugLeftoverRule,
    SecurityTodoRule,
    DisabledSecurityRule,
    PhantomCallRule,
    InsecureRandomRule,
    HardcodedCredentialRule,
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
    findings = []
    context = {"filename": filename, "mod": "test_module"}
    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


# --- SKY-L004: Try Block Patterns ---


class TestTryBlockPatterns:
    def test_oversized_try_block(self):
        lines = ["try:"]
        for i in range(20):
            lines.append(f"    x{i} = {i}")
        lines.append("except Exception:\n    pass")
        code = "\n".join(lines)
        rule = TryBlockPatternsRule(max_lines=15)
        findings = check_code(rule, code)
        assert any(f["rule_id"] == "SKY-L004" for f in findings)

    def test_small_try_block_ok(self):
        code = """
try:
    x = 1
except Exception:
    pass
"""
        rule = TryBlockPatternsRule(max_lines=15)
        findings = check_code(rule, code)
        assert not any(f["rule_id"] == "SKY-L004" for f in findings)


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
        # SecurityTodoRule reads source from file, so we need a real file
        src = "# TODO: fix authentication bypass\ndef f():\n    pass\n"
        p = tmp_path / "test_todo.py"
        p.write_text(src)
        rule = SecurityTodoRule()
        tree = ast.parse(src)
        context = {"filename": str(p), "mod": "test_module"}
        findings = []
        for node in ast.walk(tree):
            res = rule.visit_node(node, context)
            if res:
                findings.extend(res)
        assert any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_no_todo(self, tmp_path):
        src = "def f():\n    x = 1\n"
        p = tmp_path / "clean.py"
        p.write_text(src)
        rule = SecurityTodoRule()
        tree = ast.parse(src)
        context = {"filename": str(p), "mod": "test_module"}
        findings = []
        for node in ast.walk(tree):
            res = rule.visit_node(node, context)
            if res:
                findings.extend(res)
        assert not any(f["rule_id"] == "SKY-L010" for f in findings)


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
        assert any(f["rule_id"] == "SKY-L027" for f in findings)

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
