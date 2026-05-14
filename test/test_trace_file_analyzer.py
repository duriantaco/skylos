import json

from skylos.analyzer import analyze


def _write_project(root):
    module = root / "app.py"
    module.write_text(
        "\n".join(
            [
                "def root_traced():",
                "    return 1",
                "",
                "def alt_traced():",
                "    return 2",
                "",
                "def truly_unused():",
                "    return 3",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return module


def _write_trace(path, module, function, line):
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "calls": [
                    {
                        "file": str(module),
                        "function": function,
                        "line": line,
                        "count": 1,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )


def _unused_function_names(result):
    return {item.get("name") for item in result.get("unused_functions", [])}


def test_analyzer_trace_file_loads_only_explicit_path(tmp_path):
    module = _write_project(tmp_path)
    _write_trace(tmp_path / ".skylos_trace", module, "root_traced", 1)
    alt_trace = tmp_path / "alt_trace.json"
    _write_trace(alt_trace, module, "alt_traced", 4)

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=alt_trace)
    )
    names = _unused_function_names(result)

    assert "alt_traced" not in names
    assert "root_traced" in names
    assert "truly_unused" in names


def test_analyzer_trace_file_false_ignores_project_root_trace(tmp_path):
    module = _write_project(tmp_path)
    _write_trace(tmp_path / ".skylos_trace", module, "root_traced", 1)

    result = json.loads(
        analyze(str(tmp_path), conf=0, grep_verify=False, trace_file=False)
    )
    names = _unused_function_names(result)

    assert "root_traced" in names
    assert "alt_traced" in names


def test_analyzer_default_trace_file_preserves_legacy_root_trace(tmp_path):
    module = _write_project(tmp_path)
    _write_trace(tmp_path / ".skylos_trace", module, "root_traced", 1)

    result = json.loads(analyze(str(tmp_path), conf=0, grep_verify=False))
    names = _unused_function_names(result)

    assert "root_traced" not in names
    assert "alt_traced" in names
