from io import StringIO

from rich.console import Console
from rich.theme import Theme

from skylos.ui.rich_report import _render_analysis_errors


def _render_errors(result):
    output = StringIO()
    console = Console(
        file=output,
        force_terminal=False,
        color_system=None,
        theme=Theme({"bad": "bold red", "muted": "dim"}),
        width=180,
    )
    _render_analysis_errors(console, result)
    return output.getvalue()


def test_aggregate_go_engine_error_shows_affected_files_and_engine_runtime():
    rendered = _render_errors(
        {
            "analysis_errors": [
                {
                    "kind": "language_engine_unavailable",
                    "message": "Go analysis incomplete: engine unavailable.",
                    "file": "/repo/first.go",
                    "line": 1,
                    "language": "go",
                    "affected_file_count": 4,
                }
            ]
        }
    )

    assert "Analysis incomplete: 4 affected files across 1 analysis error." in rendered
    assert "4 files" in rendered
    assert "Go engine" in rendered
    assert "Python ?" not in rendered


def test_syntax_error_keeps_python_runtime_and_single_file_rendering():
    rendered = _render_errors(
        {
            "analysis_errors": [
                {
                    "kind": "syntax_error",
                    "message": "invalid syntax",
                    "file": "/repo/broken.py",
                    "line": 7,
                    "python_version": "3.12.13",
                }
            ]
        }
    )

    assert "Analysis incomplete: 1 affected file across 1 analysis error." in rendered
    assert "syntax error: invalid syntax" in rendered
    assert "1 file" in rendered
    assert "Python 3.12.13" in rendered
