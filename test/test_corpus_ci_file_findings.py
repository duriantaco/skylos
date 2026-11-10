"""Native unused-file findings have path identities, rather than symbol names."""

import pytest

from skylos.benchmarks import corpus_ci


def _case(tmp_path, *, mode="present"):
    root = tmp_path / "fixture"
    root.mkdir()
    (root / "orphan.ts").write_text("export {};\n")
    (root / "live.ts").write_text("export {};\n")
    return {
        "id": "file-identities",
        "path": "fixture",
        "source": {
            "repo": "https://github.com/duriantaco/skylos",
            "license": "Apache-2.0",
        },
        "expect": {
            mode: {
                "unused_files": [
                    {
                        "rule_id": "SKY-E003",
                        "file": "orphan.ts",
                        "start_line": 1,
                        "end_line": 1,
                    }
                ]
            }
        },
    }


def _report(rows):
    return {
        "analysis_errors": [],
        "analysis_summary": {"total_files": 2, "languages": {"TypeScript": 2}},
        "unused_files": rows,
    }


@pytest.mark.parametrize("absolute", [False, True])
def test_native_path_identity_scores_and_matches_the_exact_file(
    tmp_path, monkeypatch, absolute
):
    case = _case(tmp_path)

    def scan(path, **kwargs):
        file = str(path / "orphan.ts") if absolute else "orphan.ts"
        return _report([{"rule_id": "SKY-E003", "file": file, "line": 1}])

    monkeypatch.setattr(corpus_ci, "_scan_case", scan)
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert result["scored"] is True
    assert result["checked_expectation_count"] == 1
    assert result["failures"] == []
    case["expect"]["absent"] = case["expect"].pop("present")
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert result["scored"] is True
    assert len(result["failures"]) == 1
    assert result["failures"][0]["mode"] == "absent"


def test_same_rule_on_a_different_file_does_not_satisfy_presence(tmp_path, monkeypatch):
    case = _case(tmp_path)
    monkeypatch.setattr(
        corpus_ci,
        "_scan_case",
        lambda *a, **kw: _report(
            [
                {"rule_id": "SKY-E003", "file": "live.ts", "line": 1},
            ]
        ),
    )
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert result["scored"] is True
    assert len(result["failures"]) == 1
    assert result["failures"][0]["mode"] == "present"


@pytest.mark.parametrize(
    "invalid",
    [
        {"file": None},
        {"file": " "},
        {"file": "../outside.ts"},
        {"line": 0},
        {"line": True},
        {"rule_id": None},
    ],
)
def test_malformed_file_rows_cannot_pass_absence(tmp_path, monkeypatch, invalid):
    case = _case(tmp_path, mode="absent")
    row = {"rule_id": "SKY-E003", "file": "orphan.ts", "line": 1, **invalid}
    monkeypatch.setattr(corpus_ci, "_scan_case", lambda *a, **kw: _report([row]))
    result = corpus_ci.run_case(case, tmp_path / "manifest.json")
    assert result["scored"] is False
    assert result["analysis_status"] == "incomplete"
    assert result["checked_expectation_count"] == 0
