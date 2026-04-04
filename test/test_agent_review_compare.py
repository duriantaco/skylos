from scripts.compare_codex_skylos_agent_review import _extract_codex_usage


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
