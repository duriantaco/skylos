"""Advice needs a source-backed improvement, not merely a matching shape."""

import ast
from importlib.machinery import all_suffixes
import textwrap

import pytest

from test.fixture_paths import make_fixture_directory, write_fixture

from skylos.core.linter import LinterVisitor
from skylos.rules.quality.logic_foundation import TryBlockPatternsRule, UnusedExceptVarRule
from skylos.rules.quality.performance import PerformanceRule
from skylos.rules.quality.practices import TypeAnnotationPracticeRule


def analyze(rule, code, *, root=None, filename="app.py"):
    source = textwrap.dedent(code)
    visitor = LinterVisitor([rule], str(root / filename) if root else filename)
    visitor.context.update(source=source)
    if root is not None:
        visitor.context["project_root"] = root
    visitor.visit(ast.parse(source))
    return visitor.findings


def test_literal_exports_distinguish_internal_helpers_and_public_methods():
    findings = analyze(TypeAnnotationPracticeRule(coverage_advice=True), '''
        __all__ = ("Published", "published")
        def internal(value: str):
            return unknown(value)
        def published(value: str, missing):
            return unknown(value, missing)
        class Internal:
            def helper(self, value: str):
                return unknown(value)
        class Published:
            def hook(self, value: str, missing):
                return unknown(value, missing)
    ''')
    assert {(row["rule_id"], row["name"]) for row in findings} == {
        ("SKY-T101", "published"), ("SKY-T102", "published"),
        ("SKY-T101", "Published.hook"), ("SKY-T102", "Published.hook"),
    }


@pytest.mark.parametrize("exports", [
    '__all__ = discover_exports()',
    '__all__ = ["Published"]\n__all__.append("internal")',
    '__all__ = ["Published"]\nPublished = Internal',
    '__all__ = ["Published"]\nif enabled:\n    __all__ = ["internal"]',
    '__all__ = [*BASE_EXPORTS, "Published"]',
    '__all__ = ["Published"]\nexports_alias = __all__',
])
def test_uncertain_exports_do_not_establish_optional_api_boundaries(exports):
    code = exports + '\ndef internal(value: str):\n    return unknown(value)\n'
    assert analyze(TypeAnnotationPracticeRule(coverage_advice=True), code) == []


@pytest.mark.parametrize("import_statement", [
    "from application.public import *",
    "from .public import *",
])
def test_wildcard_import_cannot_prove_a_complete_literal_export_surface(import_statement):
    code = '''
        __all__ = ("published",)
        def internal(value: str):
            return unknown(value)
        def published(value: str):
            return unknown(value)
    '''
    baseline = analyze(TypeAnnotationPracticeRule(coverage_advice=True), code)
    assert [row["name"] for row in baseline] == ["published"]
    uncertain = analyze(TypeAnnotationPracticeRule(coverage_advice=True), textwrap.dedent(code) + "\n" + import_statement + "\n")
    assert uncertain == []


@pytest.mark.parametrize("body", [
    'print(value)',
    'if value:\n    return\nprint(value)',
    'if value:\n    return None\nprint(value)',
    'value.changed = True\nreturn None',
    'def nested():\n    return unknown()\nprint(value)',
    'class Nested:\n    def other(self):\n        yield 1\nprint(value)',
])
def test_obvious_none_procedure_does_not_require_redundant_return_advice(body):
    code = '__all__ = ["procedure"]\ndef procedure(value: str):\n' + textwrap.indent(body, '    ')
    assert analyze(TypeAnnotationPracticeRule(coverage_advice=True), code) == []


@pytest.mark.parametrize("body", [
    'return unknown(value)',
    'if value:\n    return unknown(value)',
    'yield value',
    'yield from value',
    'raise NotImplementedError',
    'pass',
    '...',
])
def test_unknown_value_generator_and_extension_contracts_remain_visible(body):
    code = '__all__ = ["public_hook"]\ndef public_hook(value: str):\n' + textwrap.indent(body, '    ')
    assert [row["rule_id"] for row in analyze(TypeAnnotationPracticeRule(coverage_advice=True), code)] == ["SKY-T102"]


def test_decorated_none_procedure_keeps_explicit_annotation_requirement(tmp_path):
    (tmp_path / "mypy.ini").write_text("[mypy]\nfiles = app.py\ndisallow_untyped_defs = True\n")
    assert [row["rule_id"] for row in analyze(TypeAnnotationPracticeRule(), '''
        @unknown_decorator
        def procedure(value: str):
            print(value)
    ''', root=tmp_path)] == ["SKY-T102"]


def test_explicit_annotation_policy_still_requires_none_annotation(tmp_path):
    (tmp_path / "mypy.ini").write_text("[mypy]\nfiles = app.py\ndisallow_untyped_defs = True\n")
    assert [row["rule_id"] for row in analyze(TypeAnnotationPracticeRule(), '''
        def procedure(value: str):
            print(value)
    ''', root=tmp_path)] == ["SKY-T102"]


def test_narrow_inner_try_is_precise_error_handling_not_a_nesting_problem():
    findings = analyze(TryBlockPatternsRule(), '''
        def run(callback):
            try:
                result = join()
                try:
                    callback.delay(result)
                except CallbackError:
                    recover_callback()
                finally:
                    cleanup_callback()
            except JoinError:
                recover_join()
    ''')
    assert findings == []


def test_broad_nested_catch_still_reports_its_unrelated_operations():
    lines = ["def run():", "    try:", "        try:"]
    lines += [f"            result{i} = operation{i}()" for i in range(16)]
    lines += ["        except ValueError:", "            recover()", "    except Exception:", "        recover_outer()"]
    findings = analyze(TryBlockPatternsRule(), "\n".join(lines))
    assert any(row["value"] == "nested" for row in findings)
    assert any(row["value"] == 16 for row in findings)


def test_multiline_call_does_not_become_a_broad_try_by_formatting():
    lines = ["def run():", "    if ready:", "        try:", "            render("]
    lines += [f"                option{i}=value{i}," for i in range(20)]
    lines += ["            )", "        except RenderError:", "            recover()"]
    assert analyze(TryBlockPatternsRule(), "\n".join(lines)) == []


def test_many_nested_argument_calls_still_form_a_broad_catch_scope():
    lines = ["def run():", "    if ready:", "        try:", "            render("]
    lines += [f"                option{i}=download{i}()," for i in range(20)]
    lines += ["            )", "        except RenderError:", "            recover()"]
    findings = analyze(TryBlockPatternsRule(), "\n".join(lines))
    assert len(findings) == 1
    assert isinstance(findings[0]["value"], int)


def test_many_distinct_protected_statements_still_report_size():
    lines = ["def run():", "    if ready:", "        try:"]
    lines += [f"            result{i} = operation{i}()" for i in range(16)]
    lines += ["        except ValueError:", "            recover()"]
    assert [row["value"] for row in analyze(TryBlockPatternsRule(), "\n".join(lines))] == [16]


def test_function_result_boundary_accepts_safe_local_setup_and_return_tuple():
    lines = ["def run():", "    result = error = None", "    started = 0", "    try:"]
    lines += [f"        result{i} = operation{i}()" for i in range(16)]
    lines += ["    except ValueError as exc:", "        error = exc", "    return result, error, started"]
    assert analyze(TryBlockPatternsRule(), "\n".join(lines)) == []


@pytest.mark.parametrize("prefix,suffix", [
    (["prepare()"], ["return result"]),
    (["self.state = None"], ["return result"]),
    (["global state", "state = None"], ["return result"]),
    (["result = None"], ["persist(result)", "return result"]),
    (["result = None"], ["return transform(calculate(result))"]),
    (["data = download(user_input)"], ["return data"]),
    (["result = None"], ["return persist(result)"]),
    (["started = clock()"], ["return result"]),
    (["result = None"], ["return Result(result)"]),
])
def test_try_with_separate_work_is_still_a_scoped_catch(prefix, suffix):
    lines = ["def run(self):", *["    " + statement for statement in prefix], "    try:"]
    lines += [f"        result{i} = operation{i}()" for i in range(16)]
    lines += ["    except ValueError:", "        recover()", *["    " + statement for statement in suffix]]
    assert [row["value"] for row in analyze(TryBlockPatternsRule(), "\n".join(lines))] == [16]


@pytest.mark.parametrize("module,symbol", [
    ("ast", "parse"), ("json", "loads"), ("tomllib", "loads"),
    ("pickle", "loads"), ("marshal", "loads"), ("gzip", "decompress"),
    ("zlib", "decompress"),
])
def test_buffer_api_requires_the_read_value_in_full(tmp_path, module, symbol):
    code = f'import {module} as parser\ndef load(stream):\n    return parser.{symbol}(stream.read())\n'
    assert analyze(PerformanceRule(), code, root=tmp_path) == []


def test_builtin_compile_requires_full_source(tmp_path):
    assert analyze(PerformanceRule(), '''
        def load(stream):
            return compile(stream.read(), "<source>", "exec")
    ''', root=tmp_path) == []


@pytest.mark.parametrize("source", [
    'def load(stream, parser):\n    return parser.loads(stream.read())',
    'def load(stream):\n    return unknown(stream.read())',
    'def load(stream):\n    return stream.read()',
    'def load(stream):\n    return stream.read().decode()',
    'import json\njson.loads = custom\ndef load(stream):\n    return json.loads(stream.read())',
    'def load(stream, compile):\n    return compile(stream.read(), "<source>", "exec")',
    'import ast\ndef load(stream):\n    return ast.parse(other, stream.read())',
    'import json\ndef load(stream):\n    return json.loads(stream.readlines())',
])
def test_unknown_modified_or_different_consumer_keeps_read_risk(tmp_path, source):
    assert [row["rule_id"] for row in analyze(PerformanceRule(), source, root=tmp_path)] == ["SKY-P401"]


def test_local_module_named_json_is_not_stdlib_proof(tmp_path):
    (tmp_path / "json.py").write_text("def loads(value): pass\n")
    assert [row["rule_id"] for row in analyze(PerformanceRule(), '''
        import json
        def load(stream):
            return json.loads(stream.read())
    ''', root=tmp_path)] == ["SKY-P401"]


def test_lambda_read_bound_does_not_crash_or_leak_outer_binding(tmp_path):
    findings = analyze(PerformanceRule(), '''
        count = 4
        load = lambda stream: stream.read(count)
        shadowed = lambda stream: (stream.read(count), (count := -1))
        unbounded = lambda stream: stream.read()
    ''', root=tmp_path)
    assert len(findings) == 1
    assert findings[0]["line"] == 5


@pytest.mark.parametrize("source", [
    'def load(parser):\n    return parser.read_csv("path")',
    'from application import csv\ncsv.read_csv("path")',
    'import pandas as pd\ndef load(pd):\n    return pd.read_csv("path")',
    'import pandas as pd\npd.read_csv("path", nrows=25)',
    'import pandas as pd\npd.read_csv("path", nrows=0)',
    'import pandas as pd\npd.read_csv("path", chunksize=1000)',
])
def test_pandas_advice_requires_the_actual_api_and_unbounded_rows(source):
    assert analyze(PerformanceRule(), source) == []


@pytest.mark.parametrize("source", [
    'import pandas as pd\npd.read_csv("path")',
    'from pandas import read_csv\nread_csv("path")',
    'from pandas import read_csv as load_csv\nload_csv("path", chunksize=None)',
    'import pandas as pd\npd.read_csv("path", nrows=None)',
])
def test_pandas_unbounded_and_none_limits_still_report(source):
    assert [row["rule_id"] for row in analyze(PerformanceRule(), source)] == ["SKY-P402"]


@pytest.mark.parametrize("provider", [
    "pandas.py", "pandas", "src/pandas.py", "src/pandas",
    *("pandas" + suffix for suffix in all_suffixes() if suffix != ".py"),
])
@pytest.mark.parametrize("source", [
    'import pandas as pd\npd.read_csv("path")',
    'from pandas import read_csv\nread_csv("path")',
])
def test_project_local_pandas_is_not_a_proven_pandas_api(tmp_path, provider, source):
    local = tmp_path / provider
    if local.suffix:
        write_fixture(tmp_path, provider, b"inert local provider fixture; never execute")
    else:
        make_fixture_directory(tmp_path, provider)
    assert analyze(PerformanceRule(), source, root=tmp_path) == []


def test_external_pandas_retains_unbounded_warning_and_cache_resets_per_file(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    local = tmp_path / "local"
    local.mkdir()
    (local / "pandas.py").write_text("def read_csv(path): return 0\n")
    source = 'import pandas as pd\npd.read_csv("first")\npd.read_csv("second")\n'
    rule = PerformanceRule()
    assert [row["rule_id"] for row in analyze(rule, source, root=external)] == [
        "SKY-P402", "SKY-P402",
    ]
    assert analyze(rule, source, root=local) == []


def test_historical_pandas_contract_does_not_use_head_provider_paths(tmp_path):
    (tmp_path / "pandas.py").write_text("# Current HEAD's local provider.\n")
    source = 'import pandas as pd\npd.read_csv("path")\n'
    visitor = LinterVisitor([PerformanceRule()], str(tmp_path / "app.py"))
    visitor.context.update(
        source=source, project_root=tmp_path, receiver_source_reader=lambda path: None
    )
    visitor.visit(ast.parse(source))
    assert [row["rule_id"] for row in visitor.findings] == ["SKY-P402"]


@pytest.mark.parametrize("predicate", ["re.search(pattern, value)", "re.match(pattern, value)", "re.fullmatch(pattern, value)"])
def test_required_regex_dispatch_is_not_an_indexable_join(tmp_path, predicate):
    code = f'''import re
def dispatch(values, patterns):
    for value in values:
        for pattern in patterns:
            if {predicate}:
                emit(value)
                break
'''
    assert analyze(PerformanceRule(), code, root=tmp_path) == []


def test_declared_compiled_regex_sequence_dispatch_is_not_an_indexable_join(tmp_path):
    assert analyze(PerformanceRule(), '''
        import re
        def dispatch(values, patterns: list[re.Pattern[str]]):
            for value in values:
                for pattern in patterns:
                    if pattern.search(value):
                        emit(value)
                        break
    ''', root=tmp_path) == []


def test_declared_regex_callback_pairs_preserve_ordered_dispatch(tmp_path):
    assert analyze(PerformanceRule(), '''
        import re
        class Dispatcher:
            def __init__(self, entries):
                self.entries: list[tuple[re.Pattern[str], object]] = entries
            def dispatch(self, values):
                for value in values:
                    for pattern, callback in self.entries:
                        if pattern.search(value):
                            callback(value)
                            break
    ''', root=tmp_path) == []


@pytest.mark.parametrize("predicate", ["matcher.search(value)", "matches(matcher, value)", "matcher.key == value.key"])
def test_unknown_matcher_and_equality_search_are_still_reviewed(tmp_path, predicate):
    code = f'''def dispatch(values, matchers):
    for value in values:
        for matcher in matchers:
            if {predicate}:
                emit(value)
                break
'''
    assert [row["rule_id"] for row in analyze(PerformanceRule(), code, root=tmp_path)] == ["SKY-P403"]


def test_shadowed_regex_module_keeps_unknown_predicate_visible(tmp_path):
    (tmp_path / "re.py").write_text("def search(left, right): pass\n")
    assert [row["rule_id"] for row in analyze(PerformanceRule(), '''
        import re
        def dispatch(values, patterns):
            for value in values:
                for pattern in patterns:
                    if re.search(pattern, value):
                        emit(value)
                        break
    ''', root=tmp_path)] == ["SKY-P403"]


@pytest.mark.parametrize("source", [
    'def load(stream) -> bytes:\n    return stream.read()',
    'def load(stream) -> str:\n    return stream.read().decode("utf-8")',
    'async def load(stream) -> bytes:\n    return await stream.read()',
    'async def load(stream) -> str:\n    return (await stream.read()).decode()',
    'def load(stream) -> bytes | None:\n    return stream.read()',
    'from typing import Optional as Maybe\ndef load(stream) -> Maybe[bytes]:\n    return stream.read()',
    'from typing import Union\ndef load(stream) -> Union[str, bytes, None]:\n    return stream.read()',
    'FileContent = str\ndef load(stream) -> FileContent:\n    return stream.read()',
    'Content = bytes | None\ndef load(stream) -> Content:\n    return stream.read()',
    'def load(stream) -> "bytes":\n    return stream.read()',
])
def test_declared_materialized_return_contract_cannot_be_replaced_by_chunks(tmp_path, source):
    # This establishes why chunking advice is inapplicable. It does not assert
    # that the source is size-bounded or exempt any security/resource rule.
    assert analyze(PerformanceRule(), source, root=tmp_path) == []


@pytest.mark.parametrize("source", [
    'def load(stream):\n    return stream.read()',
    'def load(stream) -> Unknown:\n    return stream.read()',
    'def load(stream) -> None:\n    return stream.read()',
    'def load(stream) -> str:\n    data = stream.read()\n    return process(data)',
    'str = Custom\ndef load(stream) -> str:\n    return stream.read()',
    'class Custom:\n    str = Other\n    def load(self, stream) -> str:\n        return stream.read()',
    'class Custom:\n    str = Other\n    def load(self, stream) -> "str":\n        return stream.read()',
    'Content = bytes\nContent = Unknown\ndef load(stream) -> Content:\n    return stream.read()',
    'Content = bytes\ndef load(stream) -> Content:\n    return stream.read()\nContent = Unknown',
    '@unknown_decorator\ndef load(stream) -> bytes:\n    return stream.read()',
    'def load(stream) -> bytes | Unknown:\n    return stream.read()',
    'from typing import Optional\nOptional = Other\ndef load(stream) -> Optional[bytes]:\n    return stream.read()',
    'def load(stream) -> bytes:\n    globals()[name] = replacement\n    return stream.read()',
])
def test_unknown_rebound_and_nonreturn_read_contracts_keep_advice(tmp_path, source):
    assert [row["rule_id"] for row in analyze(PerformanceRule(), source, root=tmp_path)] == ["SKY-P401"]


@pytest.mark.parametrize("lookup", ['locals()["error"]', 'vars()["error"]', 'locals().get("error")'])
def test_exception_capture_explicitly_consumed_through_builtin_namespace(lookup):
    code = f'try:\n    work()\nexcept ValueError as error:\n    emit({lookup})\n'
    assert analyze(UnusedExceptVarRule(), code) == []


def test_exception_namespace_proof_works_with_optimized_handler_only_dispatch():
    rule = UnusedExceptVarRule()
    rule.node_types = (ast.ExceptHandler,)
    assert analyze(rule, '''
        try:
            work()
        except ValueError as error:
            emit(locals()["error"])
    ''') == []


@pytest.mark.parametrize("source", [
    'try:\n    work()\nexcept ValueError as error:\n    recover()',
    'def run(locals):\n    try:\n        work()\n    except ValueError as error:\n        emit(locals()["error"])',
    'try:\n    work()\nexcept ValueError as error:\n    def nested():\n        return locals()["error"]\n    nested()',
    'try:\n    work()\nexcept ValueError as error:\n    emit([locals()["error"] for item in items])',
    'try:\n    work()\nexcept ValueError as error:\n    emit(locals()["different"])',
])
def test_unused_capture_and_uncertain_namespace_lookups_still_report(source):
    assert [row["rule_id"] for row in analyze(UnusedExceptVarRule(), source)] == ["SKY-L005"]
