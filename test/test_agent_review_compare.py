from scripts.compare_codex_skylos_agent_review import _extract_codex_usage, _score


def test_extract_codex_usage_parses_turn_completed_usage():
    stdout = "\n".join(
        [
            '{"type":"thread.started","thread_id":"abc"}',
            '{"type":"item.completed","item":{"id":"item_0","type":"agent_message","text":"OK"}}',
            '{"type":"turn.completed","usage":{"input_tokens":11876,"cached_input_tokens":6528,"output_tokens":27}}',
        ]
    )

    usage = _extract_codex_usage(stdout)

    assert usage == {
        "input_tokens": 11876,
        "cached_input_tokens": 6528,
        "output_tokens": 27,
    }


def test_extract_codex_usage_ignores_non_json_lines():
    stdout = "\n".join(
        [
            "Reading additional input from stdin...",
            '{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":2,"output_tokens":5}}',
        ]
    )

    usage = _extract_codex_usage(stdout)

    assert usage == {
        "input_tokens": 10,
        "cached_input_tokens": 2,
        "output_tokens": 5,
    }


def test_score_allows_expected_positive_findings_for_mixed_precision_guard_case():
    case = {
        "taxonomy": ["security", "precision_guard"],
        "budget": {"max_seconds": 1.0},
        "expect": {
            "present": {"security": ["restore_session"]},
            "absent": {"security": ["restore_session_safe"]},
        },
    }

    score = _score({"restore_session"}, 1, case, elapsed_seconds=0.1)

    assert score == {
        "recall": 1.0,
        "absence_guard": 1.0,
        "latency": 1.0,
        "overall_score": 100.0,
    }


def test_score_keeps_clean_precision_guard_strict():
    case = {
        "taxonomy": ["precision_guard"],
        "budget": {"max_seconds": 1.0},
        "expect": {
            "present": {},
            "absent": {"quality": ["normalize_name"]},
        },
    }

    score = _score({"normalize_name"}, 1, case, elapsed_seconds=0.1)

    assert score["absence_guard"] == 0.0
    assert score["overall_score"] == 65.0
