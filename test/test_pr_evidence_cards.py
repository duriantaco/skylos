import pytest

from skylos.cicd.evidence import build_evidence_card
from skylos.cicd.review import _evidence_source_url, _format_evidence_card_comment
from skylos.cicd.risk_passport import build_risk_passport, format_risk_passport_markdown


def _finding(**extra):
    return {
        "category": "danger",
        "severity": "HIGH",
        "rule_id": "SKY-D211",
        "message": "SQL built from user input",
        "file": "app.py",
        "line": 9,
        **extra,
    }


def _context(**extra):
    return {
        "head_sha": "a" * 40,
        "snapshot_id": "b" * 64,
        "file_digests": {"app.py": "c" * 64},
        "committed_files": ["app.py"],
        "nodes": [
            {"id": "view", "file": "app.py", "line": 4},
            {"id": "query", "file": "db.py", "line": 3},
        ],
        "edges": [{"from": "view", "to": "query", "kind": "static_call"}],
        "related_tests": ["test/test_app.py"],
        "limitations": ["Dynamic dispatch is unresolved."],
        **extra,
    }


def test_policy_classification_is_preserved_but_plain_rule_match_is_not_proof():
    card = build_evidence_card(_finding())
    assert (card.label, card.confidence, card.gate_blocking) == ("proven", 92, True)
    assert card.evidence_status == "static_match"
    assert "No runtime reproducer" in " ".join(card.limitations)


@pytest.mark.parametrize(
    "payload",
    [
        {"verification": {"verdict": "VERIFIED"}},
        {"evidence_status": "reproduced", "confidence": 99},
        {"execution_receipt": {"passed": True, "command": "pytest"}},
    ],
)
@pytest.mark.parametrize("source", ["llm", "static"])
def test_finding_claims_cannot_self_attest_as_executed_evidence(payload, source):
    finding = _finding(_source=source, **payload)
    card = build_evidence_card(finding)
    expected = "needs_context" if source == "llm" else "static_match"
    assert card.evidence_status == expected
    body = _format_evidence_card_comment(finding)
    assert ("Needs context" if source == "llm" else "Static match") in body
    assert "Checks:** Not run" in body
    assert "Reproduced" not in body
    assert "Confidence:" not in body


def test_complete_static_packet_is_a_source_path_without_runtime_claim():
    packet = {
        "evidence_kind": "authorization_guard",
        "source": "Next.js POST route entry",
        "sink": "database mutation",
        "path": ["route entry", "database mutation"],
        "guards_missing": [
            "route-local rejecting authentication guard before mutation"
        ],
        "analysis_complete": True,
    }
    finding = _finding(rule_id="SKY-D280", metadata={"security_evidence": packet})
    assert build_evidence_card(finding).evidence_status == "source_path"
    body = _format_evidence_card_comment(finding)
    assert "Source: Next.js POST route entry" in body
    assert "Sink: database mutation" in body
    assert "Path step: route entry" in body
    assert "not establish runtime reachability" in body
    packet["analysis_complete"] = False
    assert build_evidence_card(finding).evidence_status == "needs_context"


def test_generic_call_graph_does_not_promote_a_rule_match_to_source_path():
    body = _format_evidence_card_comment(
        _finding(), context_packet=_context(), repo="owner/repo"
    )
    assert "**Evidence:** Static match · **Severity:** HIGH" in body
    assert "Source path found" not in body
    assert "Nearby static calls (context only)" in body
    assert "view → query" in body
    assert "Related test candidates — Not run" in body
    assert "test/test_app.py" in body
    assert "b" * 64 in body
    assert "c" * 64 in body
    assert "Dynamic dispatch is unresolved" in body
    assert "/blob/" + "a" * 40 + "/app.py#L9" in body
    assert body.index("**Impact:") < body.index("<details>")


@pytest.mark.parametrize(
    "severity, expected",
    [
        ("HIGH", "HIGH"),
        ("critical", "CRITICAL"),
        ("LOW", "LOW"),
        ("HIGH** @all", "UNKNOWN"),
    ],
)
def test_severity_is_shown_separately_from_evidence_and_is_allowlisted(
    severity, expected
):
    body = _format_evidence_card_comment(_finding(severity=severity))
    assert f"**Evidence:** Static match · **Severity:** {expected}" in body
    assert "@all" not in body


@pytest.mark.parametrize(
    "extra",
    [
        {"head_sha": "main"},
        {"head_sha": "a" * 7},
        {"head_sha": "a" * 41},
        {"committed_files": []},
    ],
)
def test_source_link_requires_matching_committed_bytes_and_full_head(extra):
    body = _format_evidence_card_comment(
        _finding(), context_packet=_context(**extra), repo="owner/repo"
    )
    assert "View collected source" not in body


@pytest.mark.parametrize(
    "repo,path",
    [
        ("https://evil.invalid/x", "app.py"),
        ("owner/repo?x", "app.py"),
        ("owner/repo", "../app.py"),
        ("owner/repo", "/app.py"),
        ("owner/repo", "x/../app.py"),
        ("owner/repo", "x\\app.py"),
    ],
)
def test_source_links_reject_repository_and_path_escape(repo, path):
    packet = _context(committed_files=[path])
    assert _evidence_source_url(repo, path, 9, packet) is None


def test_source_links_encode_markdown_and_url_metacharacters():
    path = "src/a [x]#).py"
    url = _evidence_source_url("owner/repo", path, 3, _context(committed_files=[path]))
    assert url.endswith("/src/a%20%5Bx%5D%23%29.py#L3")


def test_context_output_redacts_secrets_and_neutralizes_mentions():
    token = "gh" + "p_" + "aB3dE5fG7hJ9kL2mN4pQ6rS8tU0vW2xY"
    packet = _context(
        related_tests=[f"test/{token}@all.py"], limitations=[f"@all {token}"]
    )
    body = _format_evidence_card_comment(_finding(), context_packet=packet)
    assert token not in body
    assert "@all" not in body
    assert "redacted" in body


def test_passport_keeps_gate_and_legacy_payload_but_displays_evidence_status():
    finding = _finding(ai_declared=True)
    passport = build_risk_passport(all_findings=[finding], diff_findings=[finding])
    assert passport["recommendation"] == "BLOCK"
    assert passport["changed_line_evidence"] == {
        "proven": 1,
        "likely": 0,
        "speculative": 0,
    }
    assert passport["reasons"] == [
        "Declared agent file association: proven HIGH security finding"
    ]
    body = "\n".join(format_risk_passport_markdown(passport))
    assert "Static match 1" in body
    assert "Proven 1" not in body
    assert ": proven HIGH" not in body
