import base64
from hashlib import sha256
import json

import pytest

from skylos.analyzer import analyze
from skylos.cicd.review import filter_findings_to_diff
from skylos.core.baseline import filter_new_findings, load_baseline, save_baseline
from skylos.rules.secrets import scan_ctx


def _pem(*, trailing_der=b""):
    # A fixed, unissued Ed25519 PKCS#8 structure with a synthetic body.
    prefix = bytes.fromhex("302e020100300506032b657004220420")
    material = sha256(b"skylos-offline-private-key-group-35").digest()
    body = base64.b64encode(prefix + material + trailing_der).decode()
    return f"-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----"


def _scan(text, path="app.py"):
    return scan_ctx({"relpath": path, "lines": text.splitlines(True)})


@pytest.mark.parametrize("escaped", [False, True])
def test_parsed_private_pem_owns_its_bare_body_findings(escaped):
    pem = _pem()
    source = json.dumps(pem) if escaped else pem
    findings = _scan(source)
    assert [finding["provider"] for finding in findings] == ["private_key_block"]
    finding = findings[0]
    container = finding["private_key_container"]
    assert container["format"] == "pkcs8"
    assert container["algorithm"] == "Ed25519"
    assert container["validation"] == "structural"
    assert container["end_line"] == (1 if escaped else 3)
    assert finding["end_col"] < (
        container["end_col"] if escaped else len(source.splitlines()[0]) + 1
    )
    [fragment] = container["fragments"]
    assert fragment["line"] == (1 if escaped else 2)
    assert finding["related_locations"][0]["start_line"] == fragment["line"]
    assert pem.splitlines()[1] not in json.dumps(finding)


def test_unproven_pem_keeps_header_and_body_reports():
    findings = _scan(_pem(trailing_der=b"\0"))
    assert [finding["provider"] for finding in findings] == [
        "private_key_block",
        "generic",
    ]
    assert "private_key_container" not in findings[0]


def test_neighboring_keys_and_independent_credentials_stay_separate():
    pem = _pem()
    token = "gh" + "p_" + sha256(b"unissued-provider-fixture").hexdigest()[:36]
    password = sha256(b"synthetic-keyed-password").hexdigest()
    source = f'{pem}\nAPI_PASSWORD = "{password}"\n{pem}\nTOKEN = "{token}"\n'
    findings = _scan(source)
    assert [(finding["provider"], finding["line"]) for finding in findings] == [
        ("private_key_block", 1),
        ("generic", 4),
        ("private_key_block", 5),
        ("github", 8),
    ]
    assert [
        finding["private_key_container"]["fragments"][0]["line"]
        for finding in findings
        if finding["provider"] == "private_key_block"
    ] == [2, 6]


def test_diff_and_baseline_still_track_grouped_body_lines(tmp_path):
    findings = _scan(_pem())
    assert filter_findings_to_diff(findings, [{"file": "app.py", "start": 2, "end": 2}])
    assert not filter_findings_to_diff(
        findings, [{"file": "app.py", "start": 3, "end": 3}]
    )
    result = {"secrets": findings}
    older_baseline = {"fingerprints": ["SKY-S101:app.py:1"]}
    assert filter_new_findings(result, older_baseline)["secrets"] == findings
    save_baseline(tmp_path, result)
    updated_baseline = load_baseline(tmp_path)
    assert "SKY-S101:app.py:2" in updated_baseline["fingerprints"]
    assert filter_new_findings(result, updated_baseline)["secrets"] == []


def test_native_inline_ignore_preserves_unignored_body_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = tmp_path / "app.js"
    source.write_text(f'/* skylos: ignore[SKY-S101] */ const key = `{_pem()}`;\n')
    report = json.loads(
        analyze(
            str(source),
            enable_secrets=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
        )
    )
    assert [
        (finding["provider"], finding["line"]) for finding in report["secrets"]
    ] == [("generic", 2)]
    assert [
        (finding["provider"], finding["line"])
        for finding in report["suppressed"]
        if finding.get("category") == "secrets"
    ] == [("private_key_block", 1)]
