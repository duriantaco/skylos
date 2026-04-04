import json
from pathlib import Path

from skylos.corpus_ci import (
    format_summary,
    run_manifest,
    validate_manifest,
    load_manifest,
)


MANIFEST_PATH = Path(__file__).resolve().parent.parent / "corpus" / "manifest.json"


def test_checked_in_manifest_validates():
    manifest = load_manifest(MANIFEST_PATH)
    cases = validate_manifest(manifest, MANIFEST_PATH)

    assert len(cases) >= 40
    assert {case["id"] for case in cases} >= {
        "flask-route-handler",
        "fastapi-depends-route",
        "pytest-plugin-hooks",
        "django-class-based-view",
        "sqlalchemy-model",
        "python-pyproject-entrypoint",
    }


def test_checked_in_corpus_passes():
    summary = run_manifest(MANIFEST_PATH)

    assert summary["case_count"] >= 40
    assert summary["failure_count"] == 0, format_summary(summary)


def test_manifest_runner_reports_absent_violation(tmp_path):
    case_dir = tmp_path / "bad_case"
    case_dir.mkdir()
    (case_dir / "demo.py").write_text(
        "def definitely_dead():\n    return 1\n", encoding="utf-8"
    )

    manifest = {
        "version": 1,
        "cases": [
            {
                "id": "bad-case",
                "path": "bad_case",
                "description": "Synthetic failure case.",
                "source": {
                    "repo": "https://github.com/example/project",
                    "license": "MIT",
                    "notes": "Test-only fixture.",
                },
                "expect": {
                    "absent": {"unused_functions": ["definitely_dead"]},
                    "present": {},
                },
            }
        ],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    summary = run_manifest(manifest_path)

    assert summary["failure_count"] == 1
    failure = summary["cases"][0]["failures"][0]
    assert failure["case_id"] == "bad-case"
    assert failure["category"] == "unused_functions"
    assert failure["expected"] == "definitely_dead"
