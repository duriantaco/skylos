import copy
from pathlib import Path

import pytest

from skylos.benchmarks import security as benchmark


def location(file="app.py", start=10, end=10):
    return {"rule_id": "SKY-D211", "file": file, "start_line": start, "end_line": end}


def case():
    return {
        "id": "locations",
        "expect": {
            "present": {"danger": [location()]},
            "absent": {"danger": [location(start=20, end=20)]},
        },
    }


@pytest.mark.parametrize(
    "file,line,expected",
    [
        ("app.py", 10, (1, 0, 0, 1)),
        ("app.py", 20, (0, 1, 1, 0)),
        ("other/app.py", 10, (0, 0, 1, 1)),
        ("app.py", 30, (0, 0, 1, 1)),
        ("app.py", "10", (0, 0, 1, 1)),
    ],
)
def test_location_must_match_same_finding(file, line, expected):
    _, *counts = benchmark._evaluate_expectations(
        case(), {"danger": [{"rule_id": "SKY-D211", "file": file, "line": line}]}
    )
    assert tuple(counts) == expected


def test_fields_cannot_be_combined_from_different_findings():
    assert benchmark._evaluate_expectations(
        case(),
        {
            "danger": [
                {"rule_id": "SKY-D211", "file": "other.py", "line": 10},
                {"rule_id": "SKY-D216", "file": "app.py", "line": 10},
            ]
        },
    )[1:] == (0, 0, 1, 1)


def test_zero_tp_with_fp_and_fn_has_zero_f1():
    result = benchmark._score_counts(
        true_positives=0,
        false_positives=1,
        false_negatives=8,
        true_negatives=7,
        elapsed_seconds=0.1,
        max_seconds=None,
    )
    assert result["f1"] == 0.0


@pytest.mark.parametrize("invalid", [None, [], "invalid", 12])
def test_path_normalization_preserves_invalid_reports_for_completeness(
    invalid, tmp_path
):
    benchmark._relative_finding_paths(invalid, tmp_path)


@pytest.mark.parametrize(
    "override",
    [
        {"file": "../app.py"},
        {"file": "/tmp/app.py"},
        {"start_line": True},
        {"start_line": 0},
        {"end_line": 9},
        {"rule_id": ""},
        {"unexpected": 1},
    ],
)
def test_invalid_locations_rejected(override):
    path = Path(__file__).resolve().parents[1] / "benchmarks/security/manifest.json"
    manifest = copy.deepcopy(benchmark.load_manifest(path))
    label = location()
    label.update(override)
    manifest["cases"][0]["expect"] = {"present": {"danger": [label]}}
    with pytest.raises(ValueError, match="invalid location expectation"):
        benchmark.validate_manifest(manifest, path)


def test_isolated_scan_matches_relative_path_after_cleanup(tmp_path):
    source = tmp_path / "nested"
    source.mkdir()
    (source / "app.py").write_text(
        "import yaml\n\ndef load(data):\n    return yaml.load(data, Loader=yaml.Loader)\n"
    )
    result = benchmark._scan_case(tmp_path)
    warning = next(f for f in result.get("danger", []) if f["rule_id"] == "SKY-D206")
    assert warning["file"] == "nested/app.py"
    assert warning["line"] == 4


@pytest.mark.parametrize("file,line", [("missing.py", 1), ("app.py", 2)])
def test_location_must_identify_existing_source_lines(tmp_path, file, line):
    path = Path(__file__).resolve().parents[1] / "benchmarks/security/manifest.json"
    item = copy.deepcopy(benchmark.load_manifest(path)["cases"][0])
    (tmp_path / "app.py").write_text("pass\n")
    item["path"] = "app.py"
    item["expect"] = {"absent": {"danger": [location(file, line, line)]}}
    with pytest.raises(ValueError, match="does not identify source lines"):
        benchmark.validate_manifest(
            {"version": 1, "cases": [item]}, tmp_path / "manifest.json"
        )
