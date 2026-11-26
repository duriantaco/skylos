import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from skylos.integrations.cargo_diagnostics import load_cargo_report


def diagnostic(rule, spans=None):
    return {
        "reason": "compiler-message",
        "package_id": "example",
        "message": {
            "code": {"code": rule},
            "level": "warning",
            "message": rule,
            "spans": spans
            if spans is not None
            else [
                {
                    "is_primary": True,
                    "file_name": "src/lib.rs",
                    "line_start": 3,
                    "line_end": 4,
                },
                {
                    "is_primary": False,
                    "file_name": "src/lib.rs",
                    "line_start": 2,
                    "line_end": 2,
                },
            ],
        },
    }


def write_events(path, events):
    path.write_text("".join(json.dumps(e) + "\n" for e in events), encoding="utf-8")
    return path


def test_cargo_comparison_keeps_compiler_provenance_and_deduplicates_targets(tmp_path):
    warning = diagnostic("example_lints::permissions_set_readonly_false")
    report = load_cargo_report(
        write_events(
            tmp_path / "cargo.jsonl",
            [
                {"reason": "compiler-artifact"},
                warning,
                warning,
                diagnostic("example_lints::len_zero"),
                diagnostic("dead_code"),
                diagnostic("unused_mut"),
                diagnostic("example_lints::multiple_crate_versions", []),
                diagnostic("E0123"),
                {"reason": "build-finished", "success": True},
            ],
        )
    )
    assert report["input_complete"] is True
    assert report["execution_successful"] is True
    assert report["scope"]["complete_repository"] is None
    assert [
        (
            row["rule_id"],
            row["source_tool"],
            row["category"],
            row["line_number"],
            row["end_line"],
        )
        for row in report["findings"]
    ] == [
        (
            "example_lints::permissions_set_readonly_false",
            "example_lints",
            "SECURITY",
            3,
            4,
        ),
        ("example_lints::len_zero", "example_lints", "QUALITY", 3, 4),
        ("dead_code", "rustc", "DEAD_CODE", 3, 4),
        ("unused_mut", "rustc", "QUALITY", 3, 4),
        ("example_lints::multiple_crate_versions", "example_lints", "QUALITY", 0, 0),
    ]


@pytest.mark.parametrize(
    "trailer", [[], [{"reason": "build-finished", "success": False}]]
)
def test_failed_or_truncated_export_is_incomplete(tmp_path, trailer):
    report = load_cargo_report(
        write_events(
            tmp_path / "cargo.jsonl", [diagnostic("example_lints::len_zero"), *trailer]
        )
    )
    assert report["input_complete"] is False
    assert report["execution_successful"] is (False if trailer else None)
    assert len(report["findings"]) == 1


@pytest.mark.parametrize(
    "payload",
    [
        "",
        "not JSON",
        '{"reason":[]}',
        '{"reason":"build-finished","success":1}',
        '{"reason":"build-finished","success":true}\n{"reason":"compiler-message"}',
        json.dumps(diagnostic("example_lints::len_zero", [{"is_primary": True}])),
    ],
)
def test_malformed_stream_is_not_a_clean_build(tmp_path, payload):
    path = tmp_path / "cargo.jsonl"
    path.write_text(payload)
    with pytest.raises(ValueError):
        load_cargo_report(path)


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"level": None},
        {"level": "future"},
        {"code": []},
        {"code": {"code": 0}},
        {"spans": "absent"},
        {"level": "error"},
    ],
)
def test_invalid_diagnostic_cannot_claim_a_successful_build(tmp_path, bad):
    event = diagnostic("example_lints::len_zero")
    if bad:
        event["message"].update(bad)
    else:
        event["message"] = {}
    with pytest.raises(ValueError):
        load_cargo_report(
            write_events(
                tmp_path / "cargo.jsonl",
                [
                    event,
                    {"reason": "build-finished", "success": True},
                ],
            )
        )


def test_no_code_compiler_note_is_not_a_finding(tmp_path):
    event = diagnostic("dead_code")
    event["message"].update(code=None, level="note")
    result = load_cargo_report(
        write_events(
            tmp_path / "cargo.jsonl",
            [
                event,
                {"reason": "build-finished", "success": True},
            ],
        )
    )
    assert result["input_complete"] and not result["findings"]


def test_real_compare_cli_accepts_a_successful_clean_cargo_run(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    (app / "lib.rs").write_text("pub fn entry() {}\n")
    source = write_events(
        tmp_path / "cargo.jsonl", [{"reason": "build-finished", "success": True}]
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "skylos.cli",
            "compare",
            str(app),
            "--against",
            str(source),
            "--against-format",
            "cargo",
            "--format",
            "json",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        check=True,
        timeout=60,
    )
    output = json.loads(result.stdout)
    assert output["mode"] == "shadow"
    assert output["external"]["format"] == "cargo"


@pytest.mark.skipif(not shutil.which("cargo"), reason="optional Cargo toolchain")
def test_real_cargo_check_imports_compiler_dead_code(tmp_path):
    app = tmp_path / "sample"
    (app / "src").mkdir(parents=True)
    (app / "Cargo.toml").write_text(
        '[package]\nname="controls"\nversion="0.1.0"\nedition="2021"\n'
    )
    (app / "src/lib.rs").write_text(
        "pub fn entry() { live(); }\nfn live() {}\nfn unused_helper() {}\n"
    )
    # Cargo type-checks this dependency-free fixture without running it.
    run = subprocess.run(
        ["cargo", "check", "--offline", "--message-format=json"],
        cwd=app,
        capture_output=True,
        check=True,
        timeout=90,
    )
    source = tmp_path / "cargo.jsonl"
    source.write_bytes(run.stdout)
    cargo = load_cargo_report(source)
    assert cargo["input_complete"]
    assert cargo["execution_successful"]
    assert [
        (row["source_tool"], row["category"], row["rule_id"], row["line_number"])
        for row in cargo["findings"]
    ] == [("rustc", "DEAD_CODE", "dead_code", 3)]
    finding = cargo["findings"][0]
    assert finding["file_path"] == "src/lib.rs"
    assert "unused_helper" in finding["message"]
