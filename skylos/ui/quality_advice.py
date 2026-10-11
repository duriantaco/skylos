"""Context for signature advice; finding records and gate policy stay intact."""

from pathlib import PurePath


def pytest_signature_advice(finding):
    if finding.get("rule_id") not in {"SKY-C303", "SKY-L029"}:
        return ""
    path = PurePath(str(finding.get("file") or finding.get("file_path") or ""))
    names = str(finding.get("name") or finding.get("simple_name") or "").split(".")
    function_index = -2 if finding.get("rule_id") == "SKY-L029" else -1
    function_name = names[function_index] if len(names) >= abs(function_index) else ""
    if (
        path.suffix != ".py"
        or not (path.name.startswith("test_") or path.stem.endswith("_test"))
        or not function_name.startswith("test_")
    ):
        return ""
    return (
        "If pytest supplies these inputs as fixtures or parametrized cases, "
        "review test setup and case clarity; defaults or keyword-only arguments "
        "do not reduce fixture dependencies. Ordinary manually called helpers "
        "still benefit from signature advice."
    )


def pytest_signature_title(finding):
    if finding.get("rule_id") == "SKY-C303":
        noun = (
            "parameters"
            if "total parameters" in str(finding.get("message") or "")
            else "arguments"
        )
        return f"{finding.get('value', '?')} {noun} (limit {finding.get('threshold', '?')})"
    return f"Boolean input '{finding.get('simple_name') or finding.get('value') or '?'}' on a test function"
