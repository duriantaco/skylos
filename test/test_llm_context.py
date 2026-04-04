from skylos.llm.context import ContextBuilder


def test_build_analysis_context_includes_compact_review_hints():
    source = (
        "def branchy_handler(flag_a, flag_b, flag_c):\n"
        "    if flag_a:\n"
        "        if flag_b:\n"
        "            return 1\n"
        "        return 2\n"
        "    if flag_c:\n"
        "        return 3\n"
        "    return 4\n\n"
        "def resolve_user(flag):\n"
        "    if flag:\n"
        "        return 'present'\n"
        "    return\n\n"
        "def append_tag(tag, tags=[]):\n"
        "    tags.append(tag)\n"
        "    return tags\n\n"
        "def parse_payload(payload):\n"
        "    try:\n"
        "        return int(payload)\n"
        "    except ValueError:\n"
        "        pass\n"
        "    return 0\n"
    )

    context = ContextBuilder().build_analysis_context(
        source,
        file_path="demo.py",
        include_review_hints=True,
    )

    assert "[REVIEW HINTS]" in context
    assert "branchy_handler (line 1): branch-heavy function" in context
    assert "resolve_user (line 10): mixed return behavior" in context
    assert (
        "append_tag (line 15): mutable default state; parameter default(s) tags are shared across calls."
        in context
    )
    assert (
        "parse_payload (line 19): swallowed exception; except ValueError only passes"
        in context
    )


def test_build_analysis_context_includes_repo_context():
    source = "def handler(value):\n    return value\n"

    context = ContextBuilder().build_analysis_context(
        source,
        file_path="demo.py",
        repo_metadata=(
            "- review_score=140\n"
            "- entrypoints: conventional entry file `app.py`\n"
            "- imported_by: test_demo.py\n"
            "- hotspot signals: handler is branch-heavy (6 control-flow points)"
        ),
    )

    assert "[REPO CONTEXT]" in context
    assert "review_score=140" in context
    assert "entrypoints: conventional entry file `app.py`" in context
