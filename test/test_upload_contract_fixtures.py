"""Golden upload fixtures shared with Skylos Cloud.

Each case builds a small synthetic repository, runs the real CLI payload
builder (``skylos.api._prepare_report_upload``) on it and compares the result
with ``test/fixtures/upload_contract/<case>.payload.json``. The matching
``<case>.expected.json`` says what the server must store for every finding,
per ``skylos/api/upload_contract/v1.json``.

The same files are copied to the server repository as
``contracts/upload/fixtures/cli-<case>.payload.json`` so both sides test
against identical bytes. To regenerate after an intended change::

    SKYLOS_UPDATE_UPLOAD_FIXTURES=1 \\
    SKYLOS_CLOUD_UPLOAD_FIXTURES_DIR=../skylos-cloud/skylos-cloud/contracts/upload/fixtures \\
    PYTHONPATH=. python -m pytest test/test_upload_contract_fixtures.py -q
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

import pytest

import skylos.api as api
from skylos.api._upload_contract import repository_scope_rule_ids
from skylos.api._upload_paths import (
    REASON_MISSING,
    file_path_problem,
    normalize_contract_file_path,
)
from skylos.cloud.project_context import project_context_for_upload
from skylos.rules.quality.policy import analyze_repo_policy
from skylos.rules.quality.unused_deps import scan_unused_dependencies

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "upload_contract"
UPDATE_ENV = "SKYLOS_UPDATE_UPLOAD_FIXTURES"
CLOUD_DIR_ENV = "SKYLOS_CLOUD_UPLOAD_FIXTURES_DIR"

LONG_MESSAGE = (
    "Command injection: the value flows from request.args into subprocess.run "
    "with shell=True and no validation. "
) * 60


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path or explicit fixture regeneration path
        text, encoding="utf-8"
    )
    return path


def _finding(path: Path, line: int, **fields):
    return {"file": str(path), "line": line, **fields}


def _dead_function(path: Path, line: int, name: str):
    return _finding(
        path,
        line,
        name=name,
        simple_name=name,
        full_name=name,
        type="function",
        basename=path.name,
        confidence=90,
    )


def case_repo_policy_root(tmp: Path):
    root = tmp / "repo"
    _write(root / "app.py", "def main():\n    return 1\n")
    return root, root, {"quality": analyze_repo_policy(root)}


def case_repo_policy_subproject(tmp: Path):
    root = tmp / "repo"
    project = root / "apps" / "web"
    app = _write(project / "app.py", "def main():\n    return 1\n")
    _write(project / "pyproject.toml", '[project]\nname = "web"\n')
    _write(project / ".pre-commit-config.yaml", "repos: []\n")
    return (
        root,
        project,
        {
            "quality": analyze_repo_policy(project),
            "unused_functions": [_dead_function(app, 1, "main")],
        },
    )


def case_unused_dependency(tmp: Path):
    root = tmp / "repo"
    _write(root / "requirements.txt", "# runtime deps\nrequests>=2\npyserial==3.5\n")
    app = _write(
        root / "app.py", "import requests\n\nrequests.get('https://example.com')\n"
    )
    return root, root, {"quality": scan_unused_dependencies(root, [app])}


def case_path_spaces_unicode(tmp: Path):
    root = tmp / "repo"
    source = _write(
        root / "src" / "my module" / "caf\u00e9 \u00fc.py",
        "def unused_helper():\n    return 42\n",
    )
    return (
        root,
        root,
        {"unused_functions": [_dead_function(source, 1, "unused_helper")]},
    )


def case_deleted_or_moved_file(tmp: Path):
    root = tmp / "repo"
    _write(root / "app.py", "print('kept')\n")
    moved = _write(tmp / "outside" / "moved.py", "def moved():\n    pass\n")
    return (
        root,
        root,
        {
            "danger": [
                _finding(
                    root / "src" / "removed.py",
                    10,
                    rule_id="SKY-D211",
                    severity="HIGH",
                    message="Possible SQL injection: tainted input reaches cursor.execute.",
                )
            ],
            "quality": [
                _finding(
                    moved,
                    7,
                    rule_id="SKY-Q301",
                    severity="MEDIUM",
                    message="Function is too complex (McCabe=14).",
                )
            ],
        },
    )


def case_symlinked_file(tmp: Path):
    root = tmp / "repo"
    _write(
        root / "lib" / "real.py",
        "def compute(x):\n    if x:\n        return 1\n    return 0\n",
    )
    (root / "link.py").symlink_to(Path("lib") / "real.py")
    outside = _write(
        tmp / "outside" / "private.py", "TOKEN_NOTE = 'outside the repo'\n"
    )
    (root / "external.py").symlink_to(outside)
    return (
        root,
        root,
        {
            "quality": [
                _finding(
                    root / "link.py",
                    1,
                    rule_id="SKY-Q301",
                    severity="MEDIUM",
                    message="Function is too complex (McCabe=11).",
                ),
                _finding(
                    root / "external.py",
                    1,
                    rule_id="SKY-Q302",
                    severity="LOW",
                    message="Deeply nested block.",
                ),
            ]
        },
    )


def case_zero_line(tmp: Path):
    root = tmp / "repo"
    module = _write(root / "pkg" / "__init__.py", "")
    return (
        root,
        root,
        {
            "quality": [
                _finding(
                    module,
                    0,
                    rule_id="SKY-Q401",
                    severity="LOW",
                    message="Module has no docstring.",
                )
            ]
        },
    )


def case_long_message(tmp: Path):
    root = tmp / "repo"
    app = _write(
        root / "app.py",
        "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n",
    )
    return (
        root,
        root,
        {
            "danger": [
                _finding(
                    app,
                    4,
                    rule_id="SKY-D212",
                    severity="CRITICAL",
                    message=LONG_MESSAGE,
                )
            ]
        },
    )


def case_missing_and_placeholder_paths(tmp: Path):
    root = tmp / "repo"
    app = _write(root / "src" / "app.py", "def f():\n    return 1\n")
    return (
        root,
        root,
        {
            "danger": [
                {
                    "rule_id": "SKY-D211",
                    "severity": "HIGH",
                    "line": 3,
                    "message": "Finding reported without a file.",
                }
            ],
            "quality": [
                _finding(
                    Path("<unknown>"),
                    5,
                    rule_id="SKY-Q301",
                    severity="MEDIUM",
                    message="Imported finding with a placeholder path.",
                ),
                _finding(app, 1, rule_id="SKY-Q302", severity="LOW", message="Nested."),
            ],
        },
    )


def case_percent_in_path(tmp: Path):
    root = tmp / "repo"
    literal = _write(root / "src" / "100%.py", "def f():\n    return 1\n")
    escaped = _write(root / "src" / "a%20b.py", "def g():\n    return 2\n")
    return (
        root,
        root,
        {
            "unused_functions": [
                _dead_function(literal, 1, "f"),
                _dead_function(escaped, 1, "g"),
            ]
        },
    )


def case_no_git_root(tmp: Path):
    project = tmp / "project"
    app = _write(project / "src" / "app.py", "def unused():\n    return 1\n")
    outside = _write(tmp / "elsewhere" / "lib.py", "def other():\n    return 2\n")
    return (
        None,
        project,
        {
            "unused_functions": [
                _dead_function(app, 1, "unused"),
                _dead_function(outside, 1, "other"),
            ]
        },
    )


def case_unused_dependency_parent_manifest(tmp: Path):
    root = tmp / "repo"
    _write(root / "requirements.txt", "requests>=2\npyserial==3.5\n")
    project = root / "apps" / "web"
    app = _write(project / "app.py", "import requests\n")
    return (
        root,
        project,
        {"quality": scan_unused_dependencies(project, [app], location_root=project)},
    )


def _stored(index, file_path, line_number, rule_id, category, severity):
    return {
        "index": index,
        "file_path": file_path,
        "line_number": line_number,
        "rule_id": rule_id,
        "category": category,
        "severity": severity,
    }


# What the server must store for each finding, written out by hand so the
# fixtures document the contract instead of echoing the CLI's own output.
CASES = {
    "repo-policy-root": (
        case_repo_policy_root,
        {
            "stored": [
                _stored(0, ".", 1, "SKY-R101", "QUALITY", "MEDIUM"),
                _stored(1, ".", 1, "SKY-R102", "QUALITY", "LOW"),
                _stored(2, ".", 1, "SKY-R103", "QUALITY", "LOW"),
                _stored(3, ".", 1, "SKY-R104", "QUALITY", "LOW"),
            ],
            "warnings": [],
        },
    ),
    "repo-policy-subproject": (
        case_repo_policy_subproject,
        {
            "stored": [
                _stored(0, ".", 1, "SKY-R101", "QUALITY", "MEDIUM"),
                _stored(1, ".", 1, "SKY-R102", "QUALITY", "LOW"),
                _stored(2, ".", 1, "SKY-R103", "QUALITY", "LOW"),
                _stored(3, "app.py", 1, "SKY-U001", "DEAD_CODE", "LOW"),
            ],
            "warnings": [],
        },
    ),
    "unused-dependency": (
        case_unused_dependency,
        {
            "stored": [
                _stored(0, "requirements.txt", 3, "SKY-U005", "QUALITY", "MEDIUM"),
            ],
            "warnings": [],
        },
    ),
    "path-spaces-unicode": (
        case_path_spaces_unicode,
        {
            "stored": [
                _stored(
                    0,
                    "src/my module/caf\u00e9 \u00fc.py",
                    1,
                    "SKY-U001",
                    "DEAD_CODE",
                    "LOW",
                ),
            ],
            "warnings": [],
        },
    ),
    "deleted-or-moved-file": (
        case_deleted_or_moved_file,
        {
            "stored": [
                _stored(0, "src/removed.py", 10, "SKY-D211", "SECURITY", "HIGH"),
                # Outside the repository: sent with an empty path, never '..'.
                _stored(1, "", 7, "SKY-Q301", "QUALITY", "MEDIUM"),
            ],
            "warnings": [
                {"index": 1, "field": "file_path", "reason": REASON_MISSING},
            ],
        },
    ),
    "symlinked-file": (
        case_symlinked_file,
        {
            "stored": [
                _stored(0, "link.py", 1, "SKY-Q301", "QUALITY", "MEDIUM"),
                _stored(1, "external.py", 1, "SKY-Q302", "QUALITY", "LOW"),
            ],
            "warnings": [],
        },
    ),
    "zero-line": (
        case_zero_line,
        {
            "stored": [
                _stored(0, "pkg/__init__.py", 1, "SKY-Q401", "QUALITY", "LOW"),
            ],
            "warnings": [],
        },
    ),
    "missing-and-placeholder-paths": (
        case_missing_and_placeholder_paths,
        {
            "stored": [
                _stored(0, "", 3, "SKY-D211", "SECURITY", "HIGH"),
                _stored(1, "", 5, "SKY-Q301", "QUALITY", "MEDIUM"),
                _stored(2, "src/app.py", 1, "SKY-Q302", "QUALITY", "LOW"),
            ],
            "warnings": [
                {"index": 0, "field": "file_path", "reason": REASON_MISSING},
                {"index": 1, "field": "file_path", "reason": REASON_MISSING},
            ],
        },
    ),
    "percent-in-path": (
        case_percent_in_path,
        {
            # '%' is sent as '%25' so the server's single decode is lossless.
            "stored": [
                _stored(0, "src/100%.py", 1, "SKY-U001", "DEAD_CODE", "LOW"),
                _stored(1, "src/a%20b.py", 1, "SKY-U001", "DEAD_CODE", "LOW"),
            ],
            "warnings": [],
        },
    ),
    "no-git-root": (
        case_no_git_root,
        {
            # Relative to the working directory; a file outside it has no
            # location instead of an absolute machine path.
            "stored": [
                _stored(0, "src/app.py", 1, "SKY-U001", "DEAD_CODE", "LOW"),
                _stored(1, "", 1, "SKY-U001", "DEAD_CODE", "LOW"),
            ],
            "warnings": [
                {"index": 1, "field": "file_path", "reason": REASON_MISSING},
            ],
        },
    ),
    "unused-dependency-parent-manifest": (
        case_unused_dependency_parent_manifest,
        {
            # The manifest is above the uploaded project: no location.
            "stored": [
                _stored(0, "", 1, "SKY-U005", "QUALITY", "MEDIUM"),
            ],
            "warnings": [
                {"index": 0, "field": "file_path", "reason": REASON_MISSING},
            ],
        },
    ),
    "long-message": (
        case_long_message,
        {
            "stored": [
                _stored(0, "app.py", 4, "SKY-D212", "SECURITY", "CRITICAL"),
            ],
            # Messages over 1000 characters are truncated; that is not a
            # problem with the finding, so it is not a warning.
            "warnings": [],
        },
    ),
}


def build_case_payload(name: str, tmp: Path, monkeypatch):
    """Run the real payload builder on a case's synthetic repository."""
    build = CASES[name][0]
    git_root, project_dir, result = build(tmp)
    git_root = git_root.resolve() if git_root is not None else None
    project_dir = project_dir.resolve()
    result = dict(result)
    result["provenance"] = None
    context = project_context_for_upload(
        project_dir, str(git_root) if git_root is not None else None
    )
    result["project_root"] = context["project_root"]
    result.setdefault("analysis_summary", {})["project_root"] = context["project_root"]

    monkeypatch.chdir(project_dir)
    monkeypatch.setenv("SKYLOS_UPLOAD_SESSION_ID", "cli-fixture")
    with (
        mock.patch.object(
            api, "get_git_info", return_value=("0" * 40, "main", "fixture", None)
        ),
        mock.patch.object(
            api,
            "get_git_root",
            return_value=str(git_root) if git_root is not None else None,
        ),
        mock.patch.object(api, "detect_ai_code", return_value={"detected": False}),
        mock.patch.object(api, "_cli_version", return_value="fixture"),
    ):
        prepared = api._prepare_report_upload(result, analyzer_owned=True)
    return prepared


def _payload_text(payload) -> str:
    return json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _expected_text(expected) -> str:
    return json.dumps(expected, indent=2, ensure_ascii=False) + "\n"


_SARIF_CATEGORIES = {"SECURITY", "QUALITY", "DEAD_CODE", "SECRET", "DEPENDENCY"}


def _server_severity(level, security_severity):
    """Mirror of how the server reads severity from a Skylos SARIF result."""
    if security_severity is not None:
        score = float(security_severity)
        if score >= 9:
            return "CRITICAL"
        if score >= 7:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"
    return {"error": "HIGH", "warning": "MEDIUM"}.get(level, "LOW")


def reference_storage(payload) -> dict:
    """The contract, applied to a SARIF upload, as the server must apply it."""
    project_root = normalize_contract_file_path(payload.get("project_root") or "") or ""
    project_root = project_root.strip("/")
    scope_ids = repository_scope_rule_ids()
    stored, warnings = [], []
    run = payload["runs"][0]
    rules = {rule["id"]: rule for rule in run["tool"]["driver"]["rules"]}
    for index, result in enumerate(run["results"]):
        location = result["locations"][0]["physicalLocation"]
        uri = location["artifactLocation"]["uri"]
        line = location["region"]["startLine"]
        props = result.get("properties") or {}
        rule_id = result["ruleId"]
        if (
            rule_id in scope_ids
            and props.get("kind") == "repo_policy"
            and line == 1
            and uri == (project_root or ".")
        ):
            path = "."
        elif file_path_problem(uri):
            # Stored without a location; the reported line is kept.
            warnings.append(
                {"index": index, "field": "file_path", "reason": file_path_problem(uri)}
            )
            path = ""
        else:
            path = normalize_contract_file_path(uri)
            if project_root and path.startswith(project_root + "/"):
                path = path[len(project_root) + 1 :]
        category = str(props.get("category") or "QUALITY").upper()
        assert category in _SARIF_CATEGORIES
        severity = _server_severity(
            result.get("level"),
            (rules.get(rule_id, {}).get("properties") or {}).get("security-severity"),
        )
        stored.append(_stored(index, path, line, rule_id, category, severity))
    return {"stored": stored, "warnings": warnings}


def _contract_view(payload) -> dict:
    """The parts of a payload the contract governs; other fields may evolve."""
    results = payload["runs"][0]["results"]
    return {
        "project_root": payload.get("project_root"),
        "results": [
            {
                "ruleId": r["ruleId"],
                "uri": r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
                "startLine": r["locations"][0]["physicalLocation"]["region"][
                    "startLine"
                ],
                "level": r["level"],
                "category": (r.get("properties") or {}).get("category"),
                "kind": (r.get("properties") or {}).get("kind"),
            }
            for r in results
        ],
    }


@pytest.mark.parametrize("name", sorted(CASES))
def test_upload_contract_fixture(name, tmp_path, monkeypatch):
    prepared = build_case_payload(name, tmp_path, monkeypatch)
    payload = prepared.legacy_payload
    text = _payload_text(payload)
    expected = CASES[name][1]

    # Deterministic: no temp directory or absolute checkout path leaks in.
    assert str(tmp_path) not in text
    assert str(tmp_path.resolve()) not in text
    # The expectation follows from the contract applied to this payload.
    assert reference_storage(payload) == expected

    payload_path = FIXTURE_DIR / f"{name}.payload.json"
    expected_path = FIXTURE_DIR / f"{name}.expected.json"
    if os.getenv(UPDATE_ENV) == "1":
        _write(payload_path, text)
        _write(expected_path, _expected_text(expected))
        cloud_dir = os.getenv(CLOUD_DIR_ENV, "").strip()
        if cloud_dir:
            _write(Path(cloud_dir) / f"cli-{name}.payload.json", text)
            _write(
                Path(cloud_dir) / f"cli-{name}.expected.json", _expected_text(expected)
            )

    committed = json.loads(payload_path.read_text(encoding="utf-8"))
    assert _contract_view(committed) == _contract_view(payload)
    assert json.loads(expected_path.read_text(encoding="utf-8")) == expected
    assert reference_storage(committed) == expected


def test_symlink_outside_repository_is_not_read_into_the_payload(tmp_path, monkeypatch):
    prepared = build_case_payload("symlinked-file", tmp_path, monkeypatch)
    assert "outside the repo" not in _payload_text(prepared.legacy_payload)


def test_long_message_is_bounded_in_the_payload(tmp_path, monkeypatch):
    prepared = build_case_payload("long-message", tmp_path, monkeypatch)
    [result] = prepared.legacy_payload["runs"][0]["results"]
    assert len(LONG_MESSAGE) > 4000
    assert len(result["message"]["text"]) <= 4000


def test_moved_file_is_counted_once_as_missing_location(tmp_path, monkeypatch):
    prepared = build_case_payload("deleted-or-moved-file", tmp_path, monkeypatch)
    assert prepared.preflight.no_location == 1
    assert (
        prepared.preflight.no_location_message()
        == "1 finding has no file location; uploading it anyway."
    )


def test_fixture_folder_has_one_expected_file_per_payload():
    payloads = {
        p.name[: -len(".payload.json")] for p in FIXTURE_DIR.glob("*.payload.json")
    }
    expected = {
        p.name[: -len(".expected.json")] for p in FIXTURE_DIR.glob("*.expected.json")
    }
    assert payloads == expected == set(CASES)
