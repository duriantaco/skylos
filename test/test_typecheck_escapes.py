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

    def base_text(self, path):
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


def test_ts_strings_comments_and_explicit_any_annotation_are_not_assertions(tmp_path):
    assert (
        _scan(
            tmp_path,
            {},
            {
                "app.ts": 'const text = "input as any";\n// input as any\nlet value: any;\n'
            },
            "tsc",
        )
        == []
    )


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
