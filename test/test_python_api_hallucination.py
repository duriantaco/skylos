from skylos.rules.ai_defect.python_api_hallucination import (
    scan_python_local_api_hallucinations,
)
from skylos.verify_change import verify_change_path


def _scan(tmp_path, files, targets=None):
    paths = []
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
        paths.append(path)
    target_paths = [tmp_path / name for name in (targets or files)]
    return scan_python_local_api_hallucinations(
        tmp_path,
        paths,
        target_files=target_paths,
    )


def test_python_local_api_check_passes_existing_member(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "def verify_token(value):\n    return bool(value)\n",
            "app.py": "import security\nsecurity.verify_token('ok')\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 2


def test_python_local_api_check_fails_missing_member(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "def verify_token(value):\n    return bool(value)\n",
            "app.py": "import security\nsecurity.verify_session('ok')\n",
        },
        targets=["app.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["verify_session"]
    assert check["outcome"] == "fail"
    assert check["finding_count"] == 1


def test_python_local_api_check_is_incomplete_for_dynamic_surface(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "plugins.py": "def __getattr__(name):\n    return lambda: name\n",
            "app.py": "import plugins\nplugins.generated_helper()\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "dynamic_module_surface", "count": 1}]


def test_python_local_api_check_is_incomplete_for_target_parse_error(tmp_path):
    findings, check = _scan(
        tmp_path,
        {"app.py": "def broken(:\n    pass\n"},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "parse_error", "count": 1}]


def test_python_local_api_check_ignores_external_package_surface(tmp_path):
    findings, check = _scan(
        tmp_path,
        {"app.py": "import requests\nrequests.get('https://example.test')\n"},
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 0


def test_python_local_api_check_passes_existing_direct_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "from security import VERIFY_TOKEN as token\nprint(token)\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_python_local_api_check_fails_missing_direct_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "from security import VERIFY_SESSION\n",
        },
        targets=["app.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["VERIFY_SESSION"]
    assert findings[0]["metadata"]["reference_kind"] == "from_import"
    assert check["outcome"] == "fail"


def test_python_local_api_check_fails_missing_attribute_value(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "import security\nvalue = security.VERIFY_SESSION\n",
        },
        targets=["app.py"],
    )

    assert [finding["simple_name"] for finding in findings] == ["VERIFY_SESSION"]
    assert findings[0]["metadata"]["reference_kind"] == "module_member"
    assert check["outcome"] == "fail"


def test_python_local_api_check_uses_stub_only_api_surface(tmp_path):
    findings, check = _scan(
        tmp_path,
        {
            "security.pyi": "def verify_token(value: str) -> bool: ...\n",
            "app.py": "import security\nsecurity.verify_token('ok')\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 2


def test_python_local_submodule_import_is_incomplete_when_ownership_is_uncertain(
    tmp_path,
):
    findings, check = _scan(
        tmp_path,
        {
            "security.py": "VERIFY_TOKEN = 'ok'\n",
            "app.py": "import security.missing\n",
        },
        targets=["app.py"],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "local_import_ownership_uncertain", "count": 1}
    ]


def test_verify_change_discovers_python_stub_files(tmp_path):
    (tmp_path / "security.pyi").write_text(
        "def verify_token(value: str) -> bool: ...\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import security\nsecurity.verify_token('ok')\n",
        encoding="utf-8",
    )

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "pass"
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "python_local_api_reference"
    )
    assert check["applicable_files"] == 2


def test_verify_change_python_surface_respects_excluded_folders(tmp_path):
    (tmp_path / "security.py").write_text(
        "def verify_token(value):\n    return bool(value)\n",
        encoding="utf-8",
    )
    (tmp_path / "app.py").write_text(
        "import security\nsecurity.verify_session('ok')\n",
        encoding="utf-8",
    )
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "security.py").write_text(
        "def verify_session(value):\n    return bool(value)\n",
        encoding="utf-8",
    )

    payload = verify_change_path(tmp_path, exclude_folders=["generated"])

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["member_name"] == "verify_session"


def test_verify_change_keeps_nested_python_surface_inside_requested_scan(tmp_path):
    (tmp_path / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    case_root = tmp_path / "benchmarks" / "current"
    case_root.mkdir(parents=True)
    (case_root / "security.py").write_text(
        "def verify_token(value):\n    return bool(value)\n",
        encoding="utf-8",
    )
    (case_root / "app.py").write_text(
        "import security\nsecurity.verify_session('ok')\n",
        encoding="utf-8",
    )
    sibling = tmp_path / "benchmarks" / "sibling"
    sibling.mkdir(parents=True)
    (sibling / "security.py").write_text(
        "def verify_session(value):\n    return bool(value)\n",
        encoding="utf-8",
    )

    payload = verify_change_path(case_root)

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["member_name"] == "verify_session"
