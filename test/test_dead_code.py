from skylos.dead_code import DEAD_CODE_RESULT_KEYS, collect_dead_code_findings


def test_collect_dead_code_findings_includes_parameters():
    result = {
        "unused_functions": [{"name": "old_func"}],
        "unused_classes": [{"name": "OldClass"}],
        "unused_variables": [{"name": "OLD"}],
        "unused_imports": [{"name": "json"}],
        "unused_parameters": [{"name": "param"}],
    }

    findings = collect_dead_code_findings(result)

    assert DEAD_CODE_RESULT_KEYS[-1] == "unused_parameters"
    assert [finding["name"] for finding in findings] == [
        "old_func",
        "OldClass",
        "OLD",
        "json",
        "param",
    ]
