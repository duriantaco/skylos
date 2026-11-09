from __future__ import annotations

import difflib
from types import SimpleNamespace

import pytest

from skylos.typecheck.escapes import new_type_escapes


class _Comparison:
    def __init__(self, root, base, head):
        self.root, self.base, self.head = root, base, head
        self.changed = [
            SimpleNamespace(
                base_path=p if p in base else None, head_path=p if p in head else None
            )
            for p in sorted(set(base) | set(head))
            if base.get(p) != head.get(p)
        ]

    def base_text(self, path, sha=None):
        return self.base.get(path)

    def head_text(self, path):
        return self.head.get(path)

    def added_lines(self, changed):
        before = self.base.get(changed.base_path, "").splitlines()
        after = self.head.get(changed.head_path, "").splitlines()
        return {
            line
            for op, _, _, start, stop in difflib.SequenceMatcher(
                a=before, b=after, autojunk=False
            ).get_opcodes()
            if op in {"replace", "insert"}
            for line in range(start + 1, stop + 1)
        }


def _scan(tmp_path, base, head, checker="mypy"):
    return new_type_escapes(
        _Comparison(tmp_path, base, head), root=tmp_path, checker=checker
    )


def test_malformed_excluded_typescript_does_not_invalidate_production_guard(tmp_path):
    assert (
        _scan(
            tmp_path,
            {},
            {"app.test.ts": "const x = <", "generated/app.ts": "const x = <"},
            "tsc",
        )
        == []
    )


def test_other_project_typescript_is_not_parsed_by_selected_project_guard(tmp_path):
    comparison = _Comparison(
        tmp_path,
        {},
        {"other/app.ts": "const x = <", "selected/app.ts": "const x: number = 1;"},
    )
    assert new_type_escapes(comparison, root=tmp_path / "selected", checker="tsc") == []


def test_malformed_selected_production_typescript_remains_incomplete(tmp_path):
    with pytest.raises(ValueError, match="could not parse"):
        _scan(tmp_path, {}, {"app.ts": "const x = <"}, "tsc")


def test_unreadable_production_source_cannot_claim_no_new_suppressions(tmp_path):
    comparison = _Comparison(tmp_path, {}, {"app.py": "x = value # type: ignore\n"})
    comparison.head_text = lambda path: None
    with pytest.raises(ValueError, match="could not read production source"):
        new_type_escapes(comparison, root=tmp_path, checker="mypy")


def test_pyrefly_explanatory_comment_is_not_an_effective_pragma(tmp_path):
    assert (
        _scan(
            tmp_path,
            {},
            {"app.py": "# explanation of # pyrefly: ignore\nx = 1\n"},
            "pyrefly",
        )
        == []
    )


def test_new_production_type_ignore_is_an_introduced_error(tmp_path):
    findings = _scan(
        tmp_path,
        {"app.py": "x: int = 1\n"},
        {"app.py": 'x: int = "bad"  # type: ignore[assignment]\n'},
    )
    assert len(findings) == 1
    assert findings[0]["code"] == "type-suppression"
    assert findings[0]["origin"] == "introduced" and findings[0]["severity"] == "error"


@pytest.mark.parametrize(
    "path,source",
    [
        ("app.py", 'text = "# type: ignore"\n'),
        ("app.py", "import thing  # noqa\n"),
        ("tests/test_app.py", "x = wrong  # type: ignore\n"),
        ("generated/app.py", "x = wrong  # type: ignore\n"),
    ],
)
def test_strings_linters_tests_and_generated_are_not_compiler_escapes(
    tmp_path, path, source
):
    assert _scan(tmp_path, {}, {path: source}) == []


def test_preserved_or_moved_type_ignore_does_not_block(tmp_path):
    old = "x = value  # type: ignore\n"
    assert _scan(tmp_path, {"app.py": old}, {"app.py": "\n" + old}) == []
    assert _scan(tmp_path, {"old.py": old}, {"new.py": old}) == []


def test_added_suppression_count_is_not_hidden_by_an_existing_one(tmp_path):
    old = "x = value  # type: ignore\n"
    findings = _scan(
        tmp_path, {"app.py": old}, {"app.py": old + "y = value  # type: ignore\n"}
    )
    assert len(findings) == 1 and findings[0]["line"] == 2


@pytest.mark.parametrize(
    "checker,comment",
    [
        ("mypy", "# mypy: ignore-errors"),
        ("mypy", "# mypy: disable-error-code=assignment"),
        ("pyright", "# pyright: ignore"),
        ("pyright", "# pyright: basic"),
        ("pyrefly", "# pyrefly: ignore"),
        ("pyrefly", "# pyrefly: ignore-errors"),
    ],
)
def test_checker_specific_comments_are_detected(tmp_path, checker, comment):
    assert len(_scan(tmp_path, {}, {"app.py": comment + "\nx = wrong\n"}, checker)) == 1


def test_unrelated_checker_directives_are_not_enforced(tmp_path):
    assert (
        _scan(tmp_path, {}, {"app.py": "# pyright: ignore\nx = wrong\n"}, "mypy") == []
    )


def test_pyrefly_string_and_inert_file_pragma_are_not_suppressions(tmp_path):
    assert (
        _scan(
            tmp_path,
            {},
            {"app.py": 'text = "# pyrefly: ignore"\n# pyrefly: ignore-errors\n'},
            "pyrefly",
        )
        == []
    )


def test_moved_pyrefly_pragma_is_not_new(tmp_path):
    text = "# pyrefly: ignore-errors\nx = wrong\n"
    assert _scan(tmp_path, {"old.py": text}, {"new.py": text}, "pyrefly") == []


def test_new_ts_as_any_is_found_by_the_existing_ast_parser(tmp_path):
    findings = _scan(
        tmp_path, {}, {"src/app.ts": "const value = input as (any);\n"}, "tsc"
    )
    assert len(findings) == 1
    assert findings[0]["code"] == "type-escape" and findings[0]["file"] == "src/app.ts"


def test_ts_strings_and_comments_are_not_escapes(tmp_path):
    assert (
        _scan(
            tmp_path,
            {},
            {"app.ts": 'const text = "input as any: any";\n// input as any: any\n'},
            "tsc",
        )
        == []
    )


@pytest.mark.parametrize(
    "line",
    [
        "let value: any;\n",
        "function f(a: any) {}\n",
        "function f(): any {}\n",
        "const v: any[] = [];\n",
        "const v: Record<string, any> = {};\n",
        "function f(...args: any[]) {}\n",
        "try {} catch (e: any) {}\n",
    ],
)
def test_new_explicit_any_is_an_escape(tmp_path, line):
    result = _scan(
        tmp_path,
        {"app.ts": "const a = 1;\n"},
        {"app.ts": "const a = 1;\n" + line},
        "tsc",
    )
    assert _found(result) == [(2, "type-escape")]
    assert "explicit any" in result[0]["message"]
    assert result[0]["severity"] == "error"


def test_as_any_is_reported_once_not_as_explicit_any_too(tmp_path):
    result = _scan(
        tmp_path,
        {"app.ts": "const a = 1;\n"},
        {"app.ts": "const a = 1;\nconst v = x as any;\n"},
        "tsc",
    )
    assert [d["message"] for d in result] == [
        "New TypeScript assertion to any bypasses type checking"
    ]


@pytest.mark.parametrize(
    "line",
    ["let value: unknown;\n", "const any = 1;\n", "let value: AnyThing;\n"],
)
def test_explicit_any_controls(tmp_path, line):
    assert (
        _scan(
            tmp_path,
            {"app.ts": "const a = 1;\n"},
            {"app.ts": "const a = 1;\n" + line},
            "tsc",
        )
        == []
    )


def test_existing_explicit_any_declaration_files_and_tests_do_not_block(tmp_path):
    line = "let value: any;\n"
    assert (
        _scan(tmp_path, {"app.ts": line}, {"app.ts": "const a = 1;\n" + line}, "tsc")
        == []
    )
    assert _scan(tmp_path, {}, {"types.d.ts": line}, "tsc") == []
    assert _scan(tmp_path, {}, {"app.test.ts": line}, "tsc") == []


@pytest.mark.parametrize("checker", ["mypy", "pyright", "pyrefly"])
@pytest.mark.parametrize(
    "source, line",
    [
        ("from typing import Any\nv: Any = 1\n", 2),
        ("from typing import Any\ndef f(a: Any):\n    return a\n", 2),
        ("from typing import Any\ndef f() -> Any:\n    return 1\n", 2),
        ("import typing\nv: typing.Any = 1\n", 2),
        ("from typing import Any as A\nv: A = 1\n", 2),
    ],
)
def test_new_bare_any_warns_and_never_blocks(tmp_path, checker, source, line):
    result = _scan(tmp_path, {"app.py": "a = 1\n"}, {"app.py": source}, checker)
    assert [(d["line"], d["code"], d["severity"]) for d in result] == [
        (line, "type-widening", "warning")
    ]


@pytest.mark.parametrize(
    "source",
    [
        "from typing import Any\nv: dict[str, Any] = {}\n",
        "from mylib import Any\nv: Any = 1\n",
        "from typing import Any\nv = Any\n",
        "v: int = 1\n",
    ],
)
def test_nested_any_and_unrelated_names_do_not_warn(tmp_path, source):
    assert _scan(tmp_path, {"app.py": "a = 1\n"}, {"app.py": source}) == []


def test_ts_cast_count_preserves_old_moves_and_reports_new_occurrences(tmp_path):
    text = "const x = input as any;\n"
    assert _scan(tmp_path, {"old.ts": text}, {"new.ts": text}, "tsc") == []
    findings = _scan(
        tmp_path,
        {"app.ts": text},
        {"app.ts": text + "const y = other as any;\n"},
        "tsc",
    )
    assert len(findings) == 1 and findings[0]["line"] == 2


@pytest.mark.parametrize("directive", ["@ts-ignore", "@ts-expect-error", "@ts-nocheck"])
def test_new_production_ts_directives_block_only_in_opt_in_guard(tmp_path, directive):
    assert (
        len(
            _scan(
                tmp_path, {}, {"app.ts": f"// {directive}\nconst x = input;\n"}, "tsc"
            )
        )
        == 1
    )


def test_generated_and_test_ts_casts_do_not_block(tmp_path):
    assert (
        _scan(
            tmp_path,
            {},
            {
                "app.test.ts": "const x = input as any;\n",
                "generated/app.ts": "const x = input as any;\n",
            },
            "tsc",
        )
        == []
    )


def _found(result):
    return [(d["line"], d["code"]) for d in result]


@pytest.mark.parametrize(
    "line",
    [
        "const v: string = input as unknown as string;\n",
        "const v: string = input as never as string;\n",
        "const v: string = input as object as string;\n",
        "const v: string = <string><unknown>input;\n",
    ],
)
def test_new_double_assertion_is_an_escape(tmp_path, line):
    result = _scan(
        tmp_path,
        {"app.ts": "const a = 1;\n"},
        {"app.ts": "const a = 1;\n" + line},
        "tsc",
    )
    assert _found(result) == [(2, "type-escape")]
    assert "double assertion" in result[0]["message"]


@pytest.mark.parametrize(
    "line",
    [
        "const v = input as string;\n",
        "const v = input as unknown;\n",
        "const v = (input as Foo) as Bar;\n",
        "const v = 'x as unknown as y';\n",
    ],
)
def test_single_assertions_and_strings_are_not_double_assertions(tmp_path, line):
    assert (
        _scan(
            tmp_path,
            {"app.ts": "const a = 1;\n"},
            {"app.ts": "const a = 1;\n" + line},
            "tsc",
        )
        == []
    )


def test_existing_double_assertion_is_not_new(tmp_path):
    line = "const v = input as unknown as string;\n"
    assert (
        _scan(tmp_path, {"app.ts": line}, {"app.ts": "const a = 1;\n" + line}, "tsc")
        == []
    )


@pytest.mark.parametrize("checker", ["mypy", "pyright", "pyrefly"])
@pytest.mark.parametrize(
    "source, line",
    [
        ("from typing import cast\nv = cast(str, x)\n", 2),
        ("import typing\nv = typing.cast(str, x)\n", 2),
        ("import typing as t\nv = t.cast(str, x)\n", 2),
        ("from typing import cast as c\nv = c(str, x)\n", 2),
        ("from typing_extensions import cast\nv = cast(str, x)\n", 2),
    ],
)
def test_new_typing_cast_is_an_escape(tmp_path, checker, source, line):
    result = _scan(tmp_path, {"app.py": "a = 1\n"}, {"app.py": source}, checker)
    assert _found(result) == [(line, "type-escape")]
    assert "typing.cast" in result[0]["message"]


@pytest.mark.parametrize(
    "source",
    [
        "v = cast(str, x)\n",
        "from mylib import cast\nv = cast(str, x)\n",
        "import numpy\nv = numpy.cast(str, x)\n",
        "text = 'typing.cast(str, x)'\n",
    ],
)
def test_unrelated_cast_is_not_an_escape(tmp_path, source):
    assert _scan(tmp_path, {"app.py": "a = 1\n"}, {"app.py": source}) == []


def test_existing_typing_cast_is_not_new(tmp_path):
    source = "from typing import cast\nv = cast(str, x)\n"
    assert _scan(tmp_path, {"app.py": source}, {"app.py": source + "w = 1\n"}) == []


def test_typing_cast_in_a_test_file_does_not_block(tmp_path):
    source = "from typing import cast\nv = cast(str, x)\n"
    assert _scan(tmp_path, {}, {"tests/test_app.py": source}) == []


@pytest.mark.parametrize(
    "before, after, named",
    [
        (
            "def add(a: int, b: int) -> int:\n    return a\n",
            "def add(a, b):\n    return a\n",
            "add",
        ),
        (
            "def add(a: int) -> int:\n    return a\n",
            "def add(a) -> int:\n    return a\n",
            "add",
        ),
        (
            "def add(a: int) -> int:\n    return a\n",
            "def add(a: int):\n    return a\n",
            "add",
        ),
        (
            "class C:\n    def m(self, a: int) -> int:\n        return a\n",
            "class C:\n    def m(self, a) -> int:\n        return a\n",
            "C.m",
        ),
        (
            "async def f(a: int) -> int:\n    return a\n",
            "async def f(a) -> int:\n    return a\n",
            "f",
        ),
    ],
)
def test_removing_an_existing_annotation_is_an_escape(tmp_path, before, after, named):
    result = _scan(tmp_path, {"app.py": before}, {"app.py": after})
    assert [d["code"] for d in result] == ["type-escape"]
    assert named in result[0]["message"]


@pytest.mark.parametrize(
    "before, after",
    [
        ("def add(a, b):\n    return a\n", "def add(a, b):\n    return b\n"),
        (
            "def add(a: int) -> int:\n    return a\n",
            "def add(a: str) -> str:\n    return a\n",
        ),
        ("def add(a: int) -> int:\n    return a\n", "def renamed(a):\n    return a\n"),
        (
            "def add(a: int, b: int) -> int:\n    return a\n",
            "def add(a: int) -> int:\n    return a\n",
        ),
        (
            "def add(a: int) -> int:\n    return a\n",
            "def add(a: int, b) -> int:\n    return a\n",
        ),
    ],
)
def test_annotation_controls_that_are_not_escapes(tmp_path, before, after):
    assert _scan(tmp_path, {"app.py": before}, {"app.py": after}) == []


def test_removed_annotation_in_a_test_file_does_not_block(tmp_path):
    before = "def add(a: int) -> int:\n    return a\n"
    after = "def add(a):\n    return a\n"
    assert (
        _scan(tmp_path, {"tests/test_a.py": before}, {"tests/test_a.py": after}) == []
    )


def _allowing(tmp_path, base, head, config, checker="mypy"):
    comparison = _Comparison(
        tmp_path, {**base, "pyproject.toml": config}, {**head, "pyproject.toml": config}
    )
    comparison.config_sha = "base"
    return new_type_escapes(comparison, root=tmp_path, checker=checker)


ALLOW = (
    "[tool.skylos.done]\n"
    "[[tool.skylos.done.type_escape_allow]]\n"
    'file = "app.py"\n'
    'line = "v = call()  # type: ignore[attr-defined]"\n'
    'reason = "vendor stubs lag behind 3.2"\n'
)


def test_a_reviewed_entry_in_the_base_commit_accepts_that_exact_line(tmp_path):
    result = _allowing(
        tmp_path,
        {"app.py": "a = 1\n"},
        {"app.py": "a = 1\nv = call()  # type: ignore[attr-defined]\n"},
        ALLOW,
    )
    assert [d["severity"] for d in result] == ["info"]
    assert "vendor stubs lag behind 3.2" in result[0]["message"]


@pytest.mark.parametrize(
    "path, line",
    [
        ("app.py", "v = call()  # type: ignore"),
        ("app.py", "w = call()  # type: ignore[attr-defined]"),
        ("other.py", "v = call()  # type: ignore[attr-defined]"),
    ],
)
def test_an_entry_never_accepts_another_line_or_file(tmp_path, path, line):
    result = _allowing(tmp_path, {path: "a = 1\n"}, {path: f"a = 1\n{line}\n"}, ALLOW)
    assert [d["severity"] for d in result] == ["error"]


def test_an_entry_added_by_the_session_itself_accepts_nothing(tmp_path):
    head = {
        "app.py": "a = 1\nv = call()  # type: ignore[attr-defined]\n",
        "pyproject.toml": ALLOW,
    }
    comparison = _Comparison(
        tmp_path, {"app.py": "a = 1\n", "pyproject.toml": "[tool.skylos.done]\n"}, head
    )
    comparison.config_sha = "base"
    result = new_type_escapes(comparison, root=tmp_path, checker="mypy")
    assert [d["severity"] for d in result] == ["error"]


def test_an_entry_without_a_reason_accepts_nothing(tmp_path):
    config = ALLOW.replace('reason = "vendor stubs lag behind 3.2"\n', "")
    result = _allowing(
        tmp_path,
        {"app.py": "a = 1\n"},
        {"app.py": "a = 1\nv = call()  # type: ignore[attr-defined]\n"},
        config,
    )
    assert [d["severity"] for d in result] == ["error"]
