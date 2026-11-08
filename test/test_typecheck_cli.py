from __future__ import annotations

import argparse
from types import SimpleNamespace

import pytest

from skylos.typecheck.cli import (
    add_type_check_args,
    attach_type_check,
    render_type_check,
    scan_type_check_exit,
    validate_type_check_args,
)


def _parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stdin", action="store_true")
    add_type_check_args(parser)
    return parser


@pytest.mark.parametrize(
    "argv",
    [
        [],
        ["--type-check"],
        ["--type-check", "--type-checker", "tsc", "--type-check-timeout", "4.5"],
    ],
)
def test_type_check_flags_are_opt_in(argv):
    parser = _parser()
    args = parser.parse_args(argv)
    validate_type_check_args(parser, args)
    assert args.type_check == bool(argv)
    if not argv:
        assert args.type_check_timeout == 120 and args.type_checker is None


@pytest.mark.parametrize(
    "argv",
    [
        ["--type-checker", "auto"],
        ["--type-check-timeout", "120"],
        ["--stdin", "--type-check"],
        ["--type-check", "--type-check-timeout", "0"],
        ["--type-check", "--type-check-timeout", "nan"],
        ["--type-check", "--type-check-timeout", "inf"],
        ["--type-check", "--type-check-timeout", "3601"],
    ],
)
def test_invalid_type_check_flags_are_setup_errors(argv):
    parser = _parser()
    with pytest.raises(SystemExit) as exc:
        args = parser.parse_args(argv)
        validate_type_check_args(parser, args)
    assert exc.value.code == 2


@pytest.mark.parametrize(
    ("status", "expected"),
    [("pass", 0), ("fail", 1), ("incomplete", 2), ("not_configured", 2)],
)
def test_report_is_attached_with_project_scope_and_exit(
    tmp_path, monkeypatch, status, expected
):
    import skylos.typecheck

    calls = []
    report = {"status": status}

    def run(path, **kwargs):
        calls.append((path, kwargs))
        return report

    monkeypatch.setattr(skylos.typecheck, "run_type_check", run)
    args = _parser().parse_args(["--type-check", "--type-checker", "mypy"])
    payload = {}
    assert (
        attach_type_check(
            payload, args, path=tmp_path, base_ref="main", target_files=["app.py"]
        )
        is report
    )
    assert payload["type_check"] is report
    assert args._type_check_exit == expected
    assert calls == [
        (
            tmp_path,
            {
                "checker": "mypy",
                "base_ref": "main",
                "timeout_seconds": 120,
                "target_files": ["app.py"],
            },
        )
    ]


def test_static_default_does_not_run_the_checker(monkeypatch):
    import skylos.typecheck

    monkeypatch.setattr(
        skylos.typecheck,
        "run_type_check",
        lambda *a, **k: pytest.fail("checker ran without opt-in"),
    )
    payload = {"status": "pass"}
    assert attach_type_check(payload, _parser().parse_args([]), path=".") is None
    assert payload == {"status": "pass"}


def test_plain_render_includes_origin_location_and_comparison():
    text = render_type_check(
        {
            "checker": "tsc",
            "status": "fail",
            "summary": "1 introduced type error",
            "comparison": {"status": "complete"},
            "diagnostics": [
                {
                    "file": "src/app.ts",
                    "line": 4,
                    "column": 7,
                    "code": "TS2322",
                    "severity": "error",
                    "origin": "introduced",
                    "message": "Expected number, got string",
                }
            ],
        }
    )
    assert "src/app.ts:4:7" in text and "introduced" in text and "TS2322" in text
    assert "Type-check comparison: complete" in text
    assert "\x1b" not in text


@pytest.mark.parametrize(
    ("base", "type_exit", "force", "expected"),
    [
        (0, 0, False, 0),
        (0, 1, False, 1),
        (1, 0, False, 1),
        (0, 2, True, 2),
        (1, 2, False, 2),
        (0, 1, True, 0),
        (1, 1, True, 1),
        (2, 0, True, 2),
        (64, 1, True, 64),
    ],
)
def test_scan_exit_combines_type_and_scan_failures(base, type_exit, force, expected):
    @scan_type_check_exit
    def run(*, args):
        raise SystemExit(base)

    args = SimpleNamespace(type_check=True, _type_check_exit=type_exit, force=force)
    with pytest.raises(SystemExit) as exc:
        run(args=args)
    assert exc.value.code == expected


def test_scan_normal_return_is_upgraded_only_when_enabled():
    @scan_type_check_exit
    def run(*, args):
        return "original result"

    args = SimpleNamespace(type_check=True, _type_check_exit=1)
    with pytest.raises(SystemExit) as exc:
        run(args=args)
    assert exc.value.code == 1
    args.type_check = False
    assert run(args=args) == "original result"


def test_scan_preserves_unrelated_exceptions():
    @scan_type_check_exit
    def run(*, args):
        raise RuntimeError("original")

    with pytest.raises(RuntimeError, match="original"):
        run(args=SimpleNamespace(type_check=True, _type_check_exit=2))


def test_static_default_force_keeps_the_existing_scanner_exit():
    @scan_type_check_exit
    def run(*, args):
        raise SystemExit(1)

    with pytest.raises(SystemExit) as exc:
        run(args=SimpleNamespace(type_check=False, force=True))
    assert exc.value.code == 1


def test_file_report_exposes_project_errors_and_dependency_impact():
    text = render_type_check(
        {
            "status": "fail",
            "checker": "tsc",
            "project_error_count": 4,
            "out_of_scope_count": 2,
            "diagnostics": [
                {
                    "file": "consumer.ts",
                    "line": 2,
                    "column": 3,
                    "origin": "introduced",
                    "scope": "dependency_impact",
                    "message": "Provider signature changed",
                }
            ],
        }
    )
    assert "Project errors: 4" in text
    assert "outside selected files: 2" in text
    assert "dependency impact" in text
