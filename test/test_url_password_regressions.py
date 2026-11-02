"""Preserve ordinary URL credentials while recognizing exact sample values."""

import json

import pytest

from skylos.rules.secrets import scan_ctx


def _scan_url(url, *, constructor="URL"):
    source = f'DATABASE_URL = {constructor}("{url}")\n'
    findings = scan_ctx(
        {"relpath": "settings.py", "lines": source.splitlines(True), "tree": None},
        ignore_tests=False,
    )
    return source, findings


@pytest.mark.parametrize(
    "password",
    [
        "5432,Wq9xT7:bar",
        "5432,Wq9xT7:Wq9xT7",
        "5432,Wq9xT7:Zq81pLm2,qux:bar",
        "5432,Zq81pLm2:",
        "Zq81%66akepLm2",
        "Zq81pLm2%2Fprojects%2Fx",
        "Zq81pLm2%24%7BDB_PASSWORD%7D",
        "%5Aq81pLm2",
        "hunter2%20secret123",
        "password1%20password123",
        "my%20secret123",
        "a%20secret%20secret",
        "a%2520secret",
        "a%09secret",
        "a%20secret%20",
        "Zq81%xxpLm2",
        "Zq81%40pLm2",
    ],
)
@pytest.mark.parametrize("host", ["db.internal", "[::1]"])
def test_opaque_url_password_keeps_its_complete_span(password, host):
    source, findings = _scan_url(f"postgres://svc:{password}@{host}/app")
    [finding] = findings
    assert (finding["rule_id"], finding["severity"], finding["provider"]) == (
        "SKY-S101",
        "HIGH",
        "url_credentials",
    )
    assert source[finding["col"] : finding["end_col"]] == password
    assert finding["preview"] == "********"
    assert password not in json.dumps(findings)


@pytest.mark.parametrize(
    "url,password",
    [
        ("https://foo.com:123,admin:Zq81pLm2x@bar.com/path", "123,admin:Zq81pLm2x"),
        ("https://svc:123,foo:bar@bar.com/path", "123,foo:bar"),
        ("https://foo.com:123,foo:bar@db.internal/path", "123,foo:bar"),
        ("https://foo.com:123,Wq9xT7:bar@bar.com/path", "123,Wq9xT7:bar"),
        (
            "https://foo.com:123,opaque.internal:456,foo:bar@bar.com/path",
            "123,opaque.internal:456,foo:bar",
        ),
        (
            "https://foo.com:123,admin:Zq81@pLm2,foo:bar@bar.com/path",
            "123,admin:Zq81@pLm2,foo:bar",
        ),
    ],
)
@pytest.mark.parametrize("constructor", ["URL", "MultiHostUrl"])
def test_host_list_lookalikes_do_not_rewrite_ordinary_userinfo(
    url, password, constructor
):
    source, findings = _scan_url(url, constructor=constructor)
    [finding] = findings
    assert finding["provider"] == "url_credentials"
    assert source[finding["col"] : finding["end_col"]] == password
    assert finding["preview"] == "********"
    assert password not in json.dumps(findings)


def test_encoded_literal_equal_to_username_is_not_a_placeholder_reference():
    password = "Zq81%70Lm2"
    source, findings = _scan_url(f"postgres://Zq81pLm2:{password}@db.internal/app")
    [finding] = findings
    assert finding["provider"] == "url_credentials"
    assert source[finding["col"] : finding["end_col"]] == password


@pytest.mark.parametrize(
    "url",
    [
        "HTTPS://jo%40email.com:a%20secret@müller.de:1234/pa%20th",
        "postgres://svc:A%20SECRET@db.internal/app",
        "postgres://svc:%70assword@db.internal/app",
        "postgres://svc:changeme@db.internal/app",
        "https://foo.com:123,foo:bar@bar.com/path",
        "https://foo.com:123,baz.com:456,foo:bar@bar.com/path",
    ],
)
def test_exact_documented_url_placeholders_stay_quiet(url):
    _source, findings = _scan_url(url)
    assert findings == []


@pytest.mark.parametrize(
    "url,is_secret",
    [
        ("postgres://svc:5432,Wq9xT7:bar@db.internal/app", True),
        ("postgres://svc:Zq81%66akepLm2@db.internal/app", True),
        ("postgres://svc:Zq81pLm2%2Fprojects%2Fx@[::1]/app", True),
        ("postgres://svc:hunter2%20secret123@db.internal/app", True),
        ("postgres://svc:a%20secret@db.internal/app", False),
        ("https://foo.com:123,foo:bar@bar.com/path", False),
    ],
)
def test_url_password_decision_reaches_listing_gate_and_source_safety(
    tmp_path, url, is_secret
):
    from skylos.analyzer import analyze
    from skylos.audit.investigator_tools import safety
    from skylos.core.gatekeeper import check_gate
    from skylos.reporting.listing import is_listed

    source = f'DATABASE_URL = "{url}"\n'
    (tmp_path / "settings.py").write_text(source)
    result = json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_secrets=True,
            grep_verify=False,
            trace_file=False,
        )
    )
    findings = result.get("secrets", [])
    assert not result.get("analysis_errors")
    assert bool(findings) is is_secret
    assert all(is_listed(finding, "secrets") for finding in findings)
    passed, _reasons = check_gate(result, {"gate": {"max_secrets": 0}})
    assert passed is not is_secret

    guard = safety.EvidenceSafetyMixin()
    guard._denied_paths = set()
    guard._redacted_source_files = set()
    guard._sensitive_denials = 0
    if is_secret:
        with pytest.raises(safety.AuditToolError, match="withheld as sensitive"):
            guard._safe_source_view("settings.py", source)
    else:
        assert guard._safe_source_view("settings.py", source) == source
