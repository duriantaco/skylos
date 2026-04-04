from skylos.llm.schemas import normalize_json_response_text, parse_llm_response


def test_normalize_json_response_text_strips_fences_and_json_prefix():
    raw = '```json\n{"findings": []}\n```'

    assert normalize_json_response_text(raw) == '{"findings": []}'


def test_parse_llm_response_accepts_fenced_json():
    raw = '```json\n{"findings": [{"rule_id": "SKY-D211", "issue_type": "security", "severity": "high", "message": "SQL injection", "line": 7, "end_line": null, "explanation": null, "suggestion": null, "confidence": "high", "symbol": "load_user"}]}\n```'

    findings = parse_llm_response(raw, "demo.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "SKY-D211"
    assert findings[0].location.file == "demo.py"
    assert findings[0].location.line == 7
    assert findings[0].symbol == "load_user"
