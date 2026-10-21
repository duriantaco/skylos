"""Valid/invalid cases for the roundabout-Python checks SKY-L036..SKY-L039."""

import ast
import json
import sys
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.linter import LinterVisitor
from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.rules.catalog import get_rule_catalog
from skylos.rules.quality.slop import (
    BooleanLiteralConditionalRule,
    FormattedConversionCallRule,
    RepeatedFunctionImportRule,
    ReraiseOnlyHandlerRule,
)
from skylos.rules.quality.standards import CWE_MAP, STANDARD_REFS


def run_rule(rule_class, source, tmp_path, filename="app.py", files=None):
    for relative, content in (files or {}).items():
        extra = tmp_path / relative
        extra.parent.mkdir(parents=True, exist_ok=True)
        extra.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
            content,
            encoding="utf-8",
        )
    text = textwrap.dedent(source)
    path = tmp_path / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        text,
        encoding="utf-8",
    )
    rule = rule_class()
    rule.node_types = (ast.Module,)
    linter = LinterVisitor([rule], str(path))
    linter.context["source"] = text
    linter.context["project_root"] = str(tmp_path)
    linter.visit(ast.parse(text))
    return linter.findings


def reported_lines(rule_class, source, tmp_path, filename="app.py", files=None):
    return [
        finding["line"]
        for finding in run_rule(rule_class, source, tmp_path, filename, files)
    ]


def cases(table):
    return pytest.mark.parametrize(
        "source, expected",
        [(source, expected) for _label, source, expected in table],
        ids=[label for label, _source, _expected in table],
    )


L036_INVALID = [
    (
        "plain module repeated",
        """
        import os

        def path():
            import os
            return os.sep
        """,
        [5],
    ),
    (
        "submodule import already loads the package",
        """
        import os.path

        def path():
            import os
            return os.sep
        """,
        [5],
    ),
    (
        "same alias repeated",
        """
        import numpy as np

        def zeros():
            import numpy as np
            return np.zeros(3)
        """,
        [5],
    ),
    (
        "method and nested function",
        """
        import json

        class Store:
            def dump(self, value):
                def encode():
                    import json
                    return json.dumps(value)
                return encode()
        """,
        [7],
    ),
    (
        "import nested in a try inside the function",
        """
        import yaml

        def parse(text):
            try:
                import yaml
            except ImportError:
                return None
            return yaml.safe_load(text)
        """,
        [6],
    ),
]

L036_VALID = [
    (
        "function from a module can be patched there",
        """
        from json import loads

        def read(text):
            from json import loads
            return loads(text)
        """,
    ),
    (
        "relative function import",
        """
        from .helpers import tidy

        def clean(text):
            from .helpers import tidy
            return tidy(text)
        """,
    ),
    (
        "class import with an extra name",
        """
        from pkg.core import Tool

        def build():
            from pkg.core import Tool, Collection
            return Tool, Collection
        """,
    ),
    (
        "module import only under TYPE_CHECKING",
        """
        from typing import TYPE_CHECKING
        if TYPE_CHECKING:
            from pkg.models import User

        def load():
            from pkg.models import User
            return User
        """,
    ),
    (
        "optional dependency fallback",
        """
        try:
            import ujson as json
        except ImportError:
            import json

        def dump(value):
            import json
            return json.dumps(value)
        """,
    ),
    (
        "module import after the function",
        """
        def path():
            import os
            return os.sep

        import os
        """,
    ),
    (
        "module name rebound",
        """
        import os
        os = None

        def path():
            import os
            return os.sep
        """,
    ),
    (
        "module name written through global",
        """
        import json

        def install(module):
            global json
            json = module

        def dump(value):
            import json
            return json.dumps(value)
        """,
    ),
    (
        "local import loads a submodule",
        """
        import os

        def join(a, b):
            import os.path
            return os.path.join(a, b)
        """,
    ),
    (
        "different alias",
        """
        import numpy

        def zeros():
            import numpy as np
            return np.zeros(3)
        """,
    ),
    (
        "from import under another name",
        """
        from json import loads

        def read(text):
            from json import loads as parse
            return parse(text)
        """,
    ),
    (
        "function binds the name again",
        """
        import json

        def dump(value, custom):
            import json
            if custom:
                json = custom
            return json.dumps(value)
        """,
    ),
    (
        "parameter of the same name",
        """
        import json

        def dump(value, json=None):
            import json
            return json.dumps(value)
        """,
    ),
    (
        "enclosing function binds the name",
        """
        import json

        def outer():
            json = object()
            def inner():
                import json
                return json
            return inner, json
        """,
    ),
    (
        "source module attribute rebound in this file",
        """
        import settings
        from settings import level

        def configure():
            settings.level = 3

        def current():
            from settings import level
            return level
        """,
    ),
    (
        "source module reloaded",
        """
        import importlib
        import settings
        from settings import level

        def refresh():
            importlib.reload(settings)
            from settings import level
            return level
        """,
    ),
    (
        "dynamic module namespace",
        """
        import json

        def install(name, value):
            globals()[name] = value

        def dump(value):
            import json
            return json.dumps(value)
        """,
    ),
    (
        "star import",
        """
        import json
        from helpers import *

        def dump(value):
            import json
            return json.dumps(value)
        """,
    ),
    (
        "class body import",
        """
        import json

        class Codec:
            import json
        """,
    ),
]


@cases(L036_INVALID)
def test_l036_reports(tmp_path, source, expected):
    assert reported_lines(RepeatedFunctionImportRule, source, tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [source for _label, source in L036_VALID],
    ids=[label for label, _ in L036_VALID],
)
def test_l036_does_not_report(tmp_path, source):
    assert reported_lines(RepeatedFunctionImportRule, source, tmp_path) == []


def test_l036_skips_test_modules(tmp_path):
    source = """
    import json

    def test_dump():
        import json
        assert json.dumps(1) == "1"
    """
    assert (
        reported_lines(RepeatedFunctionImportRule, source, tmp_path, "test_dump.py")
        == []
    )


SUBMODULE = {"pkg/__init__.py": "", "pkg/sub.py": "VALUE = 1\n"}


def test_l036_reports_a_repeated_project_submodule_import(tmp_path):
    source = """
    from pkg import sub

    def read():
        from pkg import sub
        return sub.VALUE
    """
    assert reported_lines(
        RepeatedFunctionImportRule, source, tmp_path, files=SUBMODULE
    ) == [5]


def test_l036_reports_a_package_directory_submodule(tmp_path):
    files = {"pkg/__init__.py": "", "pkg/sub/__init__.py": ""}
    source = """
    from pkg import sub

    def read():
        from pkg import sub, other
        return sub, other
    """
    assert reported_lines(
        RepeatedFunctionImportRule, source, tmp_path, files=files
    ) == [5]


def test_l036_reports_a_relative_sibling_module(tmp_path):
    files = {"pkg/__init__.py": "", "pkg/sibling.py": ""}
    source = """
    from . import sibling

    def read():
        from . import sibling
        return sibling
    """
    assert reported_lines(
        RepeatedFunctionImportRule, source, tmp_path, "pkg/app.py", files
    ) == [5]


def test_l036_skips_members_that_tests_patch(tmp_path):
    files = {
        "pkg/__init__.py": "",
        "pkg/indexing.py": "def update_index():\n    return 1\n",
        "tests/test_tasks.py": (
            "from unittest import mock\n\n"
            "@mock.patch('pkg.indexing.update_index')\n"
            "def test_update(update_index):\n    pass\n"
        ),
    }
    source = """
    from pkg.indexing import update_index

    def run():
        from pkg.indexing import update_index
        return update_index()
    """
    assert (
        reported_lines(RepeatedFunctionImportRule, source, tmp_path, files=files) == []
    )


def test_l036_skips_a_submodule_file_outside_the_project(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (
        outside / "sub.py"
    ).write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        "",
        encoding="utf-8",
    )
    project = tmp_path / "project"
    (project / "pkg").mkdir(parents=True)
    try:
        (project / "pkg" / "sub.py").symlink_to(outside / "sub.py")
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable")
    source = """
    from pkg import sub

    def read():
        from pkg import sub
        return sub
    """
    assert reported_lines(RepeatedFunctionImportRule, source, project) == []


def test_l036_message_names_module_import_line(tmp_path):
    findings = run_rule(
        RepeatedFunctionImportRule,
        "import os\n\n\ndef path():\n    import os\n    return os.sep\n",
        tmp_path,
    )
    assert findings[0]["message"] == (
        "'import os' repeats the module-level import on line 1, which already "
        "binds 'os' for this function. Keep one import."
    )
    assert findings[0]["evidence"] == {
        "module_import_line": 1,
        "module_import": "import os",
    }


L037_INVALID = [
    ("true if else false", "flag = True if ready else False\n", [1]),
    ("false if else true", "flag = False if ready else True\n", [1]),
    ("parenthesized", "flag = (True) if (a == b) else (False)\n", [1]),
    (
        "if else returns",
        """
        def ready(job):
            if job.done:
                return True
            else:
                return False
        """,
        [3],
    ),
    (
        "if else assigns one name",
        """
        if step is last:
            corrector = False
        else:
            corrector = True
        """,
        [2],
    ),
]

L037_VALID = [
    ("other literal", "flag = True if ready else None\n"),
    ("same literal", "flag = True if ready else True\n"),
    ("integers", "flag = 1 if ready else 0\n"),
    (
        "different targets",
        """
        if ready:
            started = True
        else:
            stopped = False
        """,
    ),
    (
        "elif link of a longer chain",
        """
        if mode == "off":
            enabled = False
        elif mode == "on":
            enabled = True
        else:
            enabled = False
        """,
    ),
    (
        "extra work in a branch",
        """
        def ready(job):
            if job.done:
                return True
            else:
                job.log()
                return False
        """,
    ),
]


@cases(L037_INVALID)
def test_l037_reports(tmp_path, source, expected):
    assert reported_lines(BooleanLiteralConditionalRule, source, tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [source for _label, source in L037_VALID],
    ids=[label for label, _ in L037_VALID],
)
def test_l037_does_not_report(tmp_path, source):
    assert reported_lines(BooleanLiteralConditionalRule, source, tmp_path) == []


def test_l037_suggests_the_condition_when_it_is_always_bool(tmp_path):
    findings = run_rule(
        BooleanLiteralConditionalRule,
        "found = True if key in table else False\n",
        tmp_path,
    )
    assert findings[0]["value"] == "key in table"
    negated = run_rule(
        BooleanLiteralConditionalRule, "missing = False if ready else True\n", tmp_path
    )
    assert negated[0]["value"] == "not ready"
    general = run_rule(
        BooleanLiteralConditionalRule, "flag = True if count else False\n", tmp_path
    )
    assert general[0]["value"] == "bool(count)"


@pytest.mark.parametrize(
    "source, replacement",
    [
        ("flag = True if mode == 'on' else False\n", "bool(mode == 'on')"),
        ("flag = True if array == other else False\n", "bool(array == other)"),
        ("flag = False if key not in seen else True\n", "key in seen"),
        ("flag = False if not items else True\n", "bool(items)"),
    ],
)
def test_l037_replacement_keeps_comparison_meaning(tmp_path, source, replacement):
    findings = run_rule(BooleanLiteralConditionalRule, source, tmp_path)
    assert findings[0]["value"] == replacement


@pytest.mark.parametrize(
    "source",
    [
        "flag = False if step == last else True\n",
        "flag = False if step != last else True\n",
        "flag = False if size < limit else True\n",
        "if step == last:\n    use = False\nelse:\n    use = True\n",
    ],
)
def test_l037_skips_negated_overloadable_comparisons(tmp_path, source):
    assert reported_lines(BooleanLiteralConditionalRule, source, tmp_path) == []


def test_l037_describes_a_long_rewrite_instead_of_truncating_it(tmp_path):
    source = (
        "stopped = True if 'Agent stopped due to an iteration or time limit.' "
        "in result.output else False\n"
    )
    findings = run_rule(BooleanLiteralConditionalRule, source, tmp_path)
    assert findings[0]["value"] == (
        "'Agent stopped due to an iteration or time limit.' in result.output"
    )
    assert findings[0]["message"].endswith(
        "; write the condition itself (already a bool) instead."
    )


def test_l037_keeps_bool_for_overloadable_comparisons(tmp_path):
    findings = run_rule(
        BooleanLiteralConditionalRule,
        "flag = True if mode == 'on' else False\n",
        tmp_path,
    )
    assert findings[0]["message"] == (
        "This conditional expression only turns 'mode == 'on'' into True or "
        "False; write 'bool(mode == 'on')' instead."
    )


L038_INVALID = [
    ("str", 'message = f"failed: {str(error)}"\n', [1]),
    ("repr", 'message = f"got {repr(value)}"\n', [1]),
    ("ascii", 'message = f"got {ascii(value)}"\n', [1]),
    ("format spec", 'message = f"{str(value):>10}"\n', [1]),
    (
        "builtins module attribute",
        'import builtins\nmessage = f"{builtins.str(value)}"\n',
        [2],
    ),
]

L038_VALID = [
    ("explicit conversion", 'message = f"{str(value)!r}"\n'),
    ("shadowed str", 'def str(value):\n    return "x"\nmessage = f"{str(value)}"\n'),
    (
        "parameter named str",
        'def render(value, str):\n    return f"{str(value)}"\n',
    ),
    ("two arguments", "message = f\"{str(data, 'utf-8')}\"\n"),
    ("star argument", 'message = f"{str(*parts)}"\n'),
    ("not an f-string", 'message = "{}".format(str(value))\n'),
]


@cases(L038_INVALID)
def test_l038_reports(tmp_path, source, expected):
    assert reported_lines(FormattedConversionCallRule, source, tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [source for _label, source in L038_VALID],
    ids=[label for label, _ in L038_VALID],
)
def test_l038_does_not_report(tmp_path, source):
    assert reported_lines(FormattedConversionCallRule, source, tmp_path) == []


def test_l038_names_the_conversion_flag(tmp_path):
    findings = run_rule(
        FormattedConversionCallRule, 'text = f"{repr(item)}"\n', tmp_path
    )
    assert findings[0]["message"] == (
        "'{repr(item)}' calls repr() inside the f-string; the field "
        "'{item!r}' does the same."
    )


L039_INVALID = [
    (
        "only handler re-raises",
        """
        try:
            run()
        except Exception:
            raise
        """,
        [4],
    ),
    (
        "with finally",
        """
        try:
            run()
        except OSError:
            raise
        finally:
            close()
        """,
        [4],
    ),
    (
        "bare except after a real handler",
        """
        try:
            run()
        except ValueError:
            report()
        except:
            raise
        """,
        [6],
    ),
    (
        "named re-raise",
        """
        try:
            run()
        except Exception as error:
            raise error
        """,
        [4],
    ),
    (
        "two trailing re-raise clauses report once",
        """
        try:
            run()
        except ValueError:
            report()
        except KeyError:
            raise
        except Exception:
            raise
        """,
        [6],
    ),
]

L039_VALID = [
    (
        "re-raise that keeps a later handler away",
        """
        try:
            run()
        except ValueError:
            raise
        except Exception:
            report()
        """,
    ),
    (
        "chained re-raise",
        """
        try:
            run()
        except Exception as error:
            raise RuntimeError("failed") from error
        """,
    ),
    (
        "raise of another name",
        """
        try:
            run()
        except Exception as error:
            raise other
        """,
    ),
    (
        "logs before re-raise",
        """
        try:
            run()
        except Exception:
            log()
            raise
        """,
    ),
]


@cases(L039_INVALID)
def test_l039_reports(tmp_path, source, expected):
    assert reported_lines(ReraiseOnlyHandlerRule, source, tmp_path) == expected


@pytest.mark.parametrize(
    "source",
    [source for _label, source in L039_VALID],
    ids=[label for label, _ in L039_VALID],
)
def test_l039_does_not_report(tmp_path, source):
    assert reported_lines(ReraiseOnlyHandlerRule, source, tmp_path) == []


@pytest.mark.skipif(sys.version_info < (3, 11), reason="except* needs Python 3.11")
def test_l039_does_not_report_except_star(tmp_path):
    source = "try:\n    run()\nexcept* ValueError:\n    raise\n"
    assert reported_lines(ReraiseOnlyHandlerRule, source, tmp_path) == []


def test_l039_message_depends_on_what_remains(tmp_path):
    whole = run_rule(
        ReraiseOnlyHandlerRule,
        "try:\n    a()\nexcept Exception:\n    raise\n",
        tmp_path,
    )
    assert whole[0]["message"].endswith("changes nothing; remove it.")
    trailing = run_rule(
        ReraiseOnlyHandlerRule,
        "try:\n    a()\nexcept ValueError:\n    b()\nexcept Exception:\n    raise\n",
        tmp_path,
    )
    assert trailing[0]["message"].startswith("This except clause and any after it")


def test_deep_expressions_leave_builtins_unproven(tmp_path):
    terms = "+".join(["v"] * 700)
    source = (
        "import os\n"
        f"TOTAL = {terms}\n"
        "def show(value):\n"
        "    import os\n"
        '    return f"{str(value)}", os.sep\n'
    )
    assert reported_lines(FormattedConversionCallRule, source, tmp_path) == []
    assert reported_lines(RepeatedFunctionImportRule, source, tmp_path) == [4]


SHIPPED_SOURCE = """
import inspect
import json

def forward(payload):
    import json
    return json.dumps(payload)

REMOTE_CODE = inspect.getsource(forward)
"""


def test_l036_skips_files_that_ship_function_source(tmp_path):
    assert reported_lines(RepeatedFunctionImportRule, SHIPPED_SOURCE, tmp_path) == []


def test_l036_still_reports_without_a_source_reader(tmp_path):
    source = SHIPPED_SOURCE.replace("inspect.getsource(forward)", "forward")
    assert reported_lines(RepeatedFunctionImportRule, source, tmp_path) == [6]


def test_l039_comment_inside_the_clause_marks_a_placeholder(tmp_path):
    source = """
    try:
        run()
    except Cancelled:
        # release resources here, then re-raise
        raise
    """
    assert reported_lines(ReraiseOnlyHandlerRule, source, tmp_path) == []


def test_l039_comment_outside_the_clause_does_not_count(tmp_path):
    source = """
    # run the job
    try:
        run()
    except Cancelled:
        raise
    report()  # done
    """
    assert reported_lines(ReraiseOnlyHandlerRule, source, tmp_path) == [5]


def test_l039_needs_source_to_rule_out_a_comment(tmp_path):
    rule = ReraiseOnlyHandlerRule()
    rule.node_types = (ast.Module,)
    linter = LinterVisitor([rule], str(tmp_path / "app.py"))
    linter.context["project_root"] = str(tmp_path)
    linter.visit(ast.parse("try:\n    run()\nexcept Exception:\n    raise\n"))
    assert linter.findings == []


@pytest.mark.parametrize(
    "source, replacement",
    [
        ("ok = True if any(xs) else False\n", "any(xs)"),
        ("ok = True if hasattr(item, 'name') else False\n", "hasattr(item, 'name')"),
        ("ok = False if callable(item) else True\n", "not callable(item)"),
        (
            "def any(xs):\n    return 1\nok = True if any(xs) else False\n",
            "bool(any(xs))",
        ),
    ],
)
def test_l037_builtin_predicates_need_no_bool_wrapper(tmp_path, source, replacement):
    findings = run_rule(BooleanLiteralConditionalRule, source, tmp_path)
    assert findings[-1]["value"] == replacement


FIXTURE_CASE = """
try:
    run()
except Exception:
    raise
message = f"{str(value)}"

# output

try:
    run()
except Exception:
    raise
message = f"{str(value)}"
"""
FIXTURE_READER = (
    "from pathlib import Path\n\n"
    "def read_case(path):\n"
    "    text = Path(path).read_text()\n"
    "    for line in text.splitlines():\n"
    "        if line == '# output':\n"
    "            return text\n"
)


@pytest.mark.parametrize(
    "rule_class", [ReraiseOnlyHandlerRule, FormattedConversionCallRule]
)
def test_golden_fixture_data_is_not_code(tmp_path, rule_class):
    files = {"tests/__init__.py": "", "tests/util.py": FIXTURE_READER}
    assert (
        reported_lines(rule_class, FIXTURE_CASE, tmp_path, "tests/data/case.py", files)
        == []
    )


def test_fixture_shaped_file_without_a_reader_is_still_checked(tmp_path):
    assert reported_lines(
        ReraiseOnlyHandlerRule, FIXTURE_CASE, tmp_path, "tests/data/case.py"
    ) == [4, 12]


BOOL_TERNARY = "flag = True if ready else False\n"


@pytest.mark.parametrize(
    "config_name, config",
    [
        ("pyproject.toml", '[tool.ruff.lint]\nignore = ["SIM210"]\n'),
        ("pyproject.toml", '[tool.ruff]\nextend-ignore = ["SIM"]\n'),
        ("ruff.toml", '[lint]\nignore = ["SIM2"]\n'),
        (
            ".ruff.toml",
            '[lint.per-file-ignores]\n"app.py" = ["SIM210", "SIM211"]\n',
        ),
    ],
)
def test_project_ruff_ignore_of_the_same_rewrite_is_respected(
    tmp_path, config_name, config
):
    files = {config_name: config}
    assert (
        reported_lines(
            BooleanLiteralConditionalRule, BOOL_TERNARY, tmp_path, files=files
        )
        == []
    )


@pytest.mark.parametrize(
    "files",
    [
        {"pyproject.toml": '[tool.ruff.lint]\nignore = ["E501", "SIM3"]\n'},
        {"pyproject.toml": "[tool.black]\nline-length = 100\n"},
        {"pyproject.toml": '[tool.ruff.lint.per-file-ignores]\n"other.py" = ["SIM"]\n'},
        {
            "pyproject.toml": '[tool.ruff.lint]\nignore = ["SIM"]\n',
            "pkg/ruff.toml": "line-length = 100\n",
        },
    ],
    ids=["unrelated codes", "no ruff table", "other file", "nearer config wins"],
)
def test_ruff_configs_that_do_not_ignore_the_rewrite_keep_reporting(tmp_path, files):
    assert reported_lines(
        BooleanLiteralConditionalRule, BOOL_TERNARY, tmp_path, "pkg/app.py", files
    ) == [1]


def test_ruff_ignore_maps_each_check_to_its_own_rule(tmp_path):
    files = {"pyproject.toml": '[tool.ruff.lint]\nignore = ["RUF010"]\n'}
    source = 'flag = True if ready else False\nmessage = f"{str(value)}"\n'
    assert (
        reported_lines(FormattedConversionCallRule, source, tmp_path, files=files) == []
    )
    assert reported_lines(
        BooleanLiteralConditionalRule, source, tmp_path, files=files
    ) == [1]


SLOP_RULES = {
    "SKY-L036": ("Import repeated inside function", "advice", "LOW"),
    "SKY-L037": ("Conditional returning bool literals", "advice", "LOW"),
    "SKY-L038": ("Conversion call inside f-string", "advice", "LOW"),
    "SKY-L039": ("Except clause that only re-raises", "advice", "LOW"),
}


def test_catalog_standards_and_dictionary_describe_every_slop_rule():
    catalog = {entry["id"]: entry for entry in get_rule_catalog()}
    dictionary = (Path(__file__).resolve().parents[1] / "dictionary.md").read_text(
        encoding="utf-8"
    )
    for rule_id, (name, finding_type, severity) in SLOP_RULES.items():
        entry = catalog[rule_id]
        assert (entry["name"], entry["finding_type"], entry["severity"]) == (
            name,
            finding_type,
            severity,
        )
        assert entry["category"] == "quality"
        assert CWE_MAP[rule_id] and STANDARD_REFS[rule_id]
        assert f"| {rule_id.removeprefix('SKY-')} | {severity} | {name} |" in dictionary


@pytest.mark.parametrize(
    "rule_id, reason",
    [
        ("SKY-L038", "measurement"),
        ("SKY-L036", "measurement"),
        ("SKY-L037", "measurement"),
        ("SKY-L039", "measurement"),
    ],
)
def test_style_advice_is_optional_by_default(tmp_path, rule_id, reason):
    from skylos.reporting.advice_policy import optional_advice_reason

    finding = {"rule_id": rule_id, "file": str(tmp_path / "app.py"), "line": 1}
    assert optional_advice_reason(finding, "quality", project_root=tmp_path) == reason


def _analyze(tmp_path, source, *, ignore=()):
    assert write_text_no_symlink(
        tmp_path / "app.py",
        textwrap.dedent(source),
        encoding="utf-8",
    )
    if ignore:
        rendered = ", ".join(f'"{rule_id}"' for rule_id in ignore)
        assert write_text_no_symlink(
            tmp_path / "pyproject.toml",
            f"[tool.skylos]\nignore = [{rendered}]\n",
            encoding="utf-8",
        )
    return json.loads(
        analyze(str(tmp_path), conf=0, enable_quality=True, grep_verify=False)
    )


SAMPLE = """
import os


def load(flag):
    import os
    ready = True if flag else False
    try:
        names = os.listdir(".")
    except Exception as error:
        if isinstance(error, SystemExit):
            return None
        raise
    return f"{str(ready)} {names}"
"""


def test_slop_rules_reach_analyzer_quality_output(tmp_path):
    result = _analyze(tmp_path, SAMPLE)
    found = {
        finding["rule_id"]: finding["line"]
        for finding in result["quality"]
        if finding["rule_id"] in SLOP_RULES
    }
    assert found == {
        "SKY-L036": 6,
        "SKY-L037": 7,
        "SKY-L038": 14,
    }


def test_slop_rules_respect_project_ignore(tmp_path):
    result = _analyze(tmp_path, SAMPLE, ignore=("SKY-L036", "SKY-L038"))
    found = {finding["rule_id"] for finding in result["quality"]}
    assert "SKY-L036" not in found and "SKY-L038" not in found
    assert "SKY-L037" in found
