from skylos.benchmarks.agent_behavior import run_agent_behavior_manifest


def test_checked_in_agent_behavior_benchmark_covers_all_terminal_states():
    result = run_agent_behavior_manifest("benchmarks/agent_behavior/manifest.json")

    assert result["status"] == "pass"
    assert result["summary"] == {"case_count": 3, "passed": 3, "failed": 0}
    assert {case["id"]: case["actual_status"] for case in result["cases"]} == {
        "contract-pass": "pass",
        "forbidden-tool-violation": "fail",
        "missing-typed-evidence": "incomplete",
    }
