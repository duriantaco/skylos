"""``hashlib.new("md5"|"sha1", data)`` is the same weak hash as
``hashlib.md5(data)``/``hashlib.sha1(data)`` and is reported the same way on
the production analyzer path: listed for credential data, demoted for data
that is not sensitive, and quiet with ``usedforsecurity=False``."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.reporting.listing import is_listed

CASES = {
    "md5_password": (
        "import hashlib\n"
        "def digest(password):\n"
        "    return hashlib.new('md5', password.encode()).hexdigest()\n"
    ),
    "upper_md5_password": (
        "import hashlib\n"
        "def digest(password):\n"
        "    return hashlib.new('MD5', password).hexdigest()\n"
    ),
    "sha1_data_keyword": (
        "import hashlib\n"
        "def digest(api_token):\n"
        "    return hashlib.new('sha1', data=api_token).hexdigest()\n"
    ),
    "name_keyword": (
        "import hashlib\n"
        "def digest(secret):\n"
        "    return hashlib.new(name='Sha1', data=secret).hexdigest()\n"
    ),
    "module_alias": (
        "import hashlib as h\n"
        "def digest(password):\n"
        "    return h.new('md5', password).hexdigest()\n"
    ),
    "imported_new": (
        "from hashlib import new\n"
        "def digest(password):\n"
        "    return new('sha1', password).hexdigest()\n"
    ),
    "update_object": (
        "import hashlib\n"
        "def digest(password):\n"
        "    h = hashlib.new('md5')\n"
        "    h.update(password.encode())\n"
        "    return h.hexdigest()\n"
    ),
    "url_input": (
        "import hashlib\n"
        "def fingerprint(url):\n"
        "    return hashlib.new('md5', url.encode()).hexdigest()[:8]\n"
    ),
    "parameter_input": (
        "import hashlib\n"
        "def digest(data):\n"
        "    return hashlib.new('md5', data).hexdigest()\n"
        "def cache_key(url):\n"
        "    return digest(url.encode())\n"
        "def etag(body):\n"
        "    return digest(body)\n"
    ),
    "optout": (
        "import hashlib\n"
        "def digest(password):\n"
        "    return hashlib.new('md5', password, usedforsecurity=False).hexdigest()\n"
    ),
    "sha256": (
        "import hashlib\n"
        "def digest(password):\n"
        "    return hashlib.new('sha256', password).hexdigest()\n"
    ),
    "other_new": (
        "import hashlib\n"
        "def new(kind, value):\n"
        "    return kind + value\n"
        "def digest(password, factory):\n"
        "    return new('md5', password), factory.new('md5', password)\n"
    ),
}


@pytest.fixture(scope="module")
def weak_hash_rows(tmp_path_factory):
    root = tmp_path_factory.mktemp("hashlib_new")
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    package = root / "app"
    package.mkdir()
    for name, code in CASES.items():
        (package / f"{name}.py").write_text(code)
    result = json.loads(
        analyze(str(root), enable_danger=True, grep_verify=False, all_advice=False)
    )
    rows = {}
    for row in result.get("danger", []):
        if row.get("rule_id") in {"SKY-D207", "SKY-D208"}:
            stem = row["file"].replace("\\", "/").rsplit("/", 1)[-1][:-3]
            rows.setdefault(stem, []).append(row)
    return rows


@pytest.mark.parametrize(
    ("case", "rule_id"),
    [
        ("md5_password", "SKY-D207"),
        ("upper_md5_password", "SKY-D207"),
        ("sha1_data_keyword", "SKY-D208"),
        ("name_keyword", "SKY-D208"),
        ("module_alias", "SKY-D207"),
        ("imported_new", "SKY-D208"),
        ("update_object", "SKY-D207"),
    ],
)
def test_weak_hashlib_new_of_credentials_is_listed(weak_hash_rows, case, rule_id):
    [row] = weak_hash_rows.get(case, [None])
    assert row is not None
    assert row["rule_id"] == rule_id
    assert row["severity"] == "MEDIUM"
    assert "low_risk_context" not in row
    assert is_listed(row, "danger")


@pytest.mark.parametrize("case", ["url_input", "parameter_input"])
def test_weak_hashlib_new_of_non_sensitive_data_is_demoted_not_dropped(
    weak_hash_rows, case
):
    [row] = weak_hash_rows[case]
    assert row["rule_id"] == "SKY-D207"
    assert row["low_risk_context"]["reason"] == "non-sensitive-hash-input"
    assert not is_listed(row, "danger")


@pytest.mark.parametrize("case", ["optout", "sha256", "other_new"])
def test_hashlib_new_lookalikes_stay_quiet(weak_hash_rows, case):
    assert weak_hash_rows.get(case) is None
