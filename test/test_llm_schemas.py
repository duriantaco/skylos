from skylos.llm.schemas import FINDING_SCHEMA, normalize_json_response_text, parse_llm_response


def test_normalize_json_response_text_strips_fences_and_json_prefix():
    raw = '```json\n{"findings": []}\n```'

    assert normalize_json_response_text(raw) == '{"findings": []}'


def test_parse_llm_response_accepts_fenced_json():
    raw = '```json\n{"findings": [{"rule_id": "SKY-D211", "issue_type": "security", "severity": "high", "message": "SQL injection", "line": 7, "end_line": null, "explanation": null, "suggestion": null, "confidence": "high", "symbol": "load_user", "security_details": {"attack_path": "request id reaches query string", "impact": "data disclosure", "fix": "use parameters", "evidence_lines": [7, 8], "unsafe_if": "request id is user-controlled"}}]}\n```'

    findings = parse_llm_response(raw, "demo.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "SKY-D211"
    assert findings[0].location.file == "demo.py"
    assert findings[0].location.line == 7
    assert findings[0].symbol == "load_user"
    assert findings[0].security_details == {
        "attack_path": "request id reaches query string",
        "impact": "data disclosure",
        "fix": "use parameters",
        "evidence_lines": [7, 8],
        "unsafe_if": "request id is user-controlled",
    }
    assert findings[0].to_dict()["security_details"]["fix"] == "use parameters"
    assert (
        findings[0].to_sarif_result()["properties"]["security_details"]["impact"]
        == "data disclosure"
    )


def test_finding_schema_requires_nullable_security_details():
    assert "security_details" in FINDING_SCHEMA["required"]
    assert FINDING_SCHEMA["additionalProperties"] is False
    assert FINDING_SCHEMA["properties"]["security_details"]["anyOf"][1] == {
        "type": "null"
    }


def test_parse_llm_response_accepts_null_security_details():
    raw = '{"findings": [{"rule_id": "SKY-Q301", "issue_type": "quality", "severity": "medium", "message": "Complex function", "line": 3, "end_line": null, "explanation": "too many branches", "suggestion": "split it", "confidence": "medium", "symbol": "handle", "security_details": null}]}'

    findings = parse_llm_response(raw, "demo.py")

    assert len(findings) == 1
    assert findings[0].security_details is None
