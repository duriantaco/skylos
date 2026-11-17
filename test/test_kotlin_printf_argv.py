import pytest

from skylos.visitors.languages.kotlin import scan_kotlin_file
from test.fixture_paths import write_fixture


def scan(tmp_path, expression):
    path = tmp_path / "App.kt"
    write_fixture(
        tmp_path,
        (path).relative_to(tmp_path),
        "import javax.servlet.http.HttpServletRequest\nclass Page { fun run(req: HttpServletRequest): Any { return "
        + expression
        + " } }",
        overwrite=True,
    )
    return {f["rule_id"] for f in scan_kotlin_file(str(path), {})[7]}


@pytest.mark.parametrize(
    "expression",
    [
        'ProcessBuilder("printf", "%s", req.getParameter("value")).start()',
        'ProcessBuilder("/usr/bin/printf", "%s", req.getParameter("value")).start()',
        'ProcessBuilder(listOf("printf", "%s", req.getParameter("value"))).start()',
        'ProcessBuilder("printf", "%s", "-c", req.getParameter("value")).start()',
    ],
)
def test_fixed_printf_format_keeps_input_as_data(tmp_path, expression):
    assert "SKY-D212" not in scan(tmp_path, expression)


@pytest.mark.parametrize(
    "expression",
    [
        'ProcessBuilder("printf", req.getParameter("format")).start()',
        'ProcessBuilder(req.getParameter("command"), "%s", "data").start()',
        'ProcessBuilder("sh", "-c", req.getParameter("command")).start()',
        'ProcessBuilder("printf-wrapper", "%s", req.getParameter("value")).start()',
        'ProcessBuilder("printf", "%b", req.getParameter("value")).start()',
    ],
)
def test_dynamic_command_or_format_is_not_whitelisted(tmp_path, expression):
    assert "SKY-D212" in scan(tmp_path, expression)
