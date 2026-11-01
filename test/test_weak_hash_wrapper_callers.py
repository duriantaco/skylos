"""A weak hash of a parameter is judged by what callers in the module pass:
a credential, or a value derived from one, keeps md5/sha1/hashlib.new listed;
a wrapper whose callers all pass non-credential data stays demoted."""

import json

import pytest

from skylos.analyzer import analyze
from skylos.reporting.listing import is_listed

WRAPPER = "def digest(data):\n    return {call}.hexdigest()\n"

LISTED = {
    "new_wrapper": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.new('md5', data)")
        + "def login(password):\n    return digest(password.encode())\n",
    ),
    "md5_wrapper": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.md5(data)")
        + "def login(password):\n    return digest(password.encode())\n",
    ),
    "sha1_keyword_caller": (
        "SKY-D208",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.sha1(data)")
        + "def sign(api_token):\n    return digest(data=api_token)\n",
    ),
    "derived_in_caller": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.new('MD5', data)")
        + "def login(user):\n"
        "    material = user.password + ':salt'\n"
        "    return digest(material.encode())\n",
    ),
    "two_wrappers": (
        "SKY-D207",
        "import hashlib\n"
        "def inner(blob):\n    return hashlib.md5(blob).hexdigest()\n"
        "def outer(value):\n    return inner(value)\n"
        "def login(password):\n    return outer(password)\n",
    ),
    "method_wrapper": (
        "SKY-D208",
        "import hashlib\n"
        "class Hasher:\n"
        "    def digest(self, data):\n"
        "        return hashlib.sha1(data).hexdigest()\n"
        "def check(hasher, password):\n"
        "    return hasher.digest(password)\n",
    ),
    "relay_call_order": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.new('md5', data)")
        + "def relay(first, second):\n"
        "    digest(first)\n"
        "    digest(second)\n"
        "def login(password):\n"
        "    relay(b'public', password.encode())\n",
    ),
    "relay_call_order_swapped": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.new('md5', data)")
        + "def relay(first, second):\n"
        "    digest(second)\n"
        "    digest(first)\n"
        "def login(password):\n"
        "    relay(b'public', password.encode())\n",
    ),
    "cycle_beyond_trace_depth": (
        "SKY-D207",
        "import hashlib\n"
        "def digest(data, rounds):\n"
        "    if rounds:\n"
        "        return step_a(data, rounds - 1)\n"
        "    return hashlib.md5(data).hexdigest()\n"
        "def step_a(value, rounds):\n    return step_b(value, rounds)\n"
        "def step_b(value, rounds):\n    return step_c(value, rounds)\n"
        "def step_c(value, rounds):\n    return digest(value, rounds)\n",
    ),
    "callback_wrapper": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.md5(data)")
        + "def batch(password):\n    return list(map(digest, [password]))\n",
    ),
}

DEMOTED = {
    "non_credential_callers": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.new('md5', data)")
        + "def cache_key(url):\n    return digest(url.encode())\n"
        "def etag(body):\n    return digest(body)\n",
    ),
    "non_credential_method_callers": (
        "SKY-D208",
        "import hashlib\n"
        "class Hasher:\n"
        "    def digest(self, data):\n"
        "        return hashlib.sha1(data).hexdigest()\n"
        "def fingerprint(hasher, path):\n"
        "    return hasher.digest(path.encode())\n",
    ),
    "relay_non_credential": (
        "SKY-D207",
        "import hashlib\n"
        + WRAPPER.format(call="hashlib.new('md5', data)")
        + "def relay(first, second):\n"
        "    digest(first)\n"
        "    digest(second)\n"
        "def publish(url, body):\n"
        "    relay(b'public', url.encode())\n"
        "    relay(body, b'static')\n",
    ),
    "no_callers": (
        "SKY-D207",
        "import hashlib\n" + WRAPPER.format(call="hashlib.md5(data)"),
    ),
}


@pytest.fixture(scope="module")
def hash_rows(tmp_path_factory):
    root = tmp_path_factory.mktemp("hash_wrappers")
    (root / "pyproject.toml").write_text("[project]\nname = 'demo'\n")
    package = root / "app"
    package.mkdir()
    for name, (_, code) in {**LISTED, **DEMOTED}.items():
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


@pytest.mark.parametrize("case", sorted(LISTED))
def test_credential_hashed_through_a_wrapper_stays_listed(hash_rows, case):
    rule_id, _ = LISTED[case]
    [row] = hash_rows[case]
    assert row["rule_id"] == rule_id
    assert "low_risk_context" not in row
    assert is_listed(row, "danger")


@pytest.mark.parametrize("case", sorted(DEMOTED))
def test_wrapper_hashing_only_non_credential_data_stays_demoted(hash_rows, case):
    rule_id, _ = DEMOTED[case]
    [row] = hash_rows[case]
    assert row["rule_id"] == rule_id
    assert row["low_risk_context"]["reason"] == "non-sensitive-hash-input"
    assert not is_listed(row, "danger")
