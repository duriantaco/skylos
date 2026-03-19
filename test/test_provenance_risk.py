from unittest.mock import patch, MagicMock

from skylos.provenance import (
    FileProvenance,
    ProvenanceReport,
    RiskIntersection,
    compute_risk_intersections,
)


def _make_report(agent_files_data=None):
    files = {}
    agent_files = []
    human_files = []

    for path, agent_name in agent_files_data or []:
        files[path] = FileProvenance(
            file_path=path,
            agent_authored=True,
            agent_name=agent_name,
            agent_lines=[(1, 10)],
            indicators=[
                {
                    "type": "co-author",
                    "commit": "abc1234",
                    "detail": "test",
                    "agent_name": agent_name,
                }
            ],
        )
        agent_files.append(path)

    return ProvenanceReport(
        files=files,
        agent_files=agent_files,
        human_files=human_files,
        summary={
            "total_files": len(files),
            "agent_count": len(agent_files),
            "human_count": 0,
            "agents_seen": list({name for _, name in (agent_files_data or [])}),
        },
        confidence="medium" if agent_files else "low",
    )


def _mock_integration(location):
    m = MagicMock()
    m.location = location
    return m


def _mock_defense_result(location, passed):
    m = MagicMock()
    m.location = location
    m.passed = passed
    return m


def test_no_ai_files_returns_empty():
    report = _make_report([])
    result = compute_risk_intersections("/fake/repo", report)

    assert result.high_risk == []
    assert result.medium_risk == []
    assert result.summary["high"] == 0
    assert result.summary["medium"] == 0
    assert result.summary["total_ai_files"] == 0


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_ai_file_with_integration_only_is_medium(mock_detect, mock_defend):
    mock_detect.return_value = (
        [_mock_integration("src/llm_handler.py:10")],
        MagicMock(),
    )
    mock_defend.return_value = ([], MagicMock(), MagicMock())

    report = _make_report([("src/llm_handler.py", "claude")])
    result = compute_risk_intersections("/fake/repo", report)

    assert len(result.medium_risk) == 1
    assert result.medium_risk[0]["file_path"] == "src/llm_handler.py"
    assert "has_llm_integration" in result.medium_risk[0]["reasons"]
    assert result.high_risk == []
    assert result.summary["medium"] == 1
    assert result.summary["high"] == 0


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_ai_file_with_failed_defense_only_is_medium(mock_detect, mock_defend):
    mock_detect.return_value = ([], MagicMock())
    mock_defend.return_value = (
        [_mock_defense_result("src/handler.py:5", False)],
        MagicMock(),
        MagicMock(),
    )

    report = _make_report([("src/handler.py", "copilot")])
    result = compute_risk_intersections("/fake/repo", report)

    assert len(result.medium_risk) == 1
    assert result.medium_risk[0]["file_path"] == "src/handler.py"
    assert "failed_defense_check" in result.medium_risk[0]["reasons"]
    assert result.high_risk == []


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_ai_file_with_integration_and_failed_defense_is_high(mock_detect, mock_defend):
    mock_detect.return_value = (
        [_mock_integration("src/agent.py:20")],
        MagicMock(),
    )
    mock_defend.return_value = (
        [_mock_defense_result("src/agent.py:20", False)],
        MagicMock(),
        MagicMock(),
    )

    report = _make_report([("src/agent.py", "cursor")])
    result = compute_risk_intersections("/fake/repo", report)

    assert len(result.high_risk) == 1
    assert result.high_risk[0]["file_path"] == "src/agent.py"
    assert "has_llm_integration" in result.high_risk[0]["reasons"]
    assert "failed_defense_check" in result.high_risk[0]["reasons"]
    assert result.medium_risk == []
    assert result.summary["high"] == 1


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_ai_file_with_no_overlap_not_in_results(mock_detect, mock_defend):
    mock_detect.return_value = (
        [_mock_integration("other/file.py:10")],
        MagicMock(),
    )
    mock_defend.return_value = (
        [_mock_defense_result("other/file.py:10", False)],
        MagicMock(),
        MagicMock(),
    )

    report = _make_report([("src/safe.py", "claude")])
    result = compute_risk_intersections("/fake/repo", report)

    assert result.high_risk == []
    assert result.medium_risk == []
    assert result.summary["total_ai_files"] == 1


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_mixed_risk_levels(mock_detect, mock_defend):
    mock_detect.return_value = (
        [
            _mock_integration("src/danger.py:10"),
            _mock_integration("src/partial.py:5"),
        ],
        MagicMock(),
    )
    mock_defend.return_value = (
        [_mock_defense_result("src/danger.py:10", False)],
        MagicMock(),
        MagicMock(),
    )

    report = _make_report(
        [
            ("src/danger.py", "claude"),
            ("src/partial.py", "copilot"),
            ("src/clean.py", "cursor"),
        ]
    )
    result = compute_risk_intersections("/fake/repo", report)

    assert len(result.high_risk) == 1
    assert result.high_risk[0]["file_path"] == "src/danger.py"
    assert len(result.medium_risk) == 1
    assert result.medium_risk[0]["file_path"] == "src/partial.py"
    assert result.summary["high"] == 1
    assert result.summary["medium"] == 1
    assert result.summary["total_ai_files"] == 3


def test_risk_intersection_to_dict():
    ri = RiskIntersection(
        high_risk=[
            {"file_path": "a.py", "agent_name": "claude", "reasons": ["ai_authored"]}
        ],
        medium_risk=[],
        summary={"high": 1, "medium": 0, "total_ai_files": 1},
    )
    d = ri.to_dict()
    assert d["high_risk"] == ri.high_risk
    assert d["medium_risk"] == []
    assert d["summary"]["high"] == 1


@patch("skylos.defend.engine.run_defense_checks")
@patch("skylos.discover.detector.detect_integrations")
def test_absolute_path_integration_normalized(mock_detect, mock_defend):
    mock_detect.return_value = (
        [_mock_integration("/fake/repo/src/agent.py:10")],
        MagicMock(),
    )
    mock_defend.return_value = ([], MagicMock(), MagicMock())

    report = _make_report([("src/agent.py", "claude")])
    result = compute_risk_intersections("/fake/repo", report)

    assert len(result.medium_risk) == 1
    assert result.medium_risk[0]["file_path"] == "src/agent.py"
