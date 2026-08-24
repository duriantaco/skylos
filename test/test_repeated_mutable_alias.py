import json

from skylos.analyzer import analyze


def _analyze(tmp_path, source, *, ignore=()):
    path = tmp_path / "app.py"
    path.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
        source,
        encoding="utf-8",
    )
    if ignore:
        config = tmp_path / "pyproject.toml"
        rendered = ", ".join(f'"{rule_id}"' for rule_id in ignore)
        config.write_text(  # skylos: ignore[SKY-D324] pytest-owned temporary fixture path
            f"[tool.skylos]\nignore = [{rendered}]\n",
            encoding="utf-8",
        )
    return json.loads(
        analyze(
            str(tmp_path),
            conf=0,
            enable_quality=True,
            grep_verify=False,
        )
    )


def test_l034_reaches_analyzer_quality_output(tmp_path):
    result = _analyze(
        tmp_path,
        "def fallbacks(count: int):\n    return [{'status': 'missing'}] * count\n",
    )

    aliases = [
        finding for finding in result["quality"] if finding["rule_id"] == "SKY-L034"
    ]

    assert len(aliases) == 1
    assert aliases[0]["line"] == 2
    assert aliases[0]["severity"] == "MEDIUM"


def test_l034_respects_project_ignore(tmp_path):
    result = _analyze(
        tmp_path,
        "def fallbacks(count: int):\n    return [{'status': 'missing'}] * count\n",
        ignore=("SKY-L034",),
    )

    assert all(finding["rule_id"] != "SKY-L034" for finding in result["quality"])


def test_l034_skips_exact_bool_repeat_count_in_analyzer(tmp_path):
    result = _analyze(
        tmp_path,
        "def maybe_item(include: bool):\n    return [{}] * include\n",
    )

    assert all(finding["rule_id"] != "SKY-L034" for finding in result["quality"])


def test_l034_preserves_bool_bounded_inner_repeat_for_outer_alias(tmp_path):
    result = _analyze(
        tmp_path,
        "def repeated(include: bool, rows: int):\n"
        "    safe = [*[1, 2]] * rows\n"
        "    return ([{}] * include) * rows\n",
    )

    aliases = [
        finding for finding in result["quality"] if finding["rule_id"] == "SKY-L034"
    ]

    assert [finding["line"] for finding in aliases] == [3]


def test_l034_comprehension_walrus_invalidates_bool_parameter_in_analyzer(
    tmp_path,
):
    result = _analyze(
        tmp_path,
        "def repeated(count: bool, source):\n"
        "    [(count := 2) for _ in source]\n"
        "    return [{}] * count\n",
    )

    aliases = [
        finding for finding in result["quality"] if finding["rule_id"] == "SKY-L034"
    ]

    assert [finding["line"] for finding in aliases] == [3]
