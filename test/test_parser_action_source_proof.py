"""Native argparse does not certify arbitrary action/type callbacks."""

import pytest

from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


@pytest.mark.parametrize("option", ["", ", action=RemoteAction", ", type=remote_type"])
def test_direct_parser_configuration_keeps_remote_callback_sources(tmp_path, option):
    source = (
        "import argparse, requests\nfrom flask import request\n"
        "class RemoteAction(argparse.Action):\n"
        "    def __call__(self, parser, namespace, values, option_string=None):\n"
        '        setattr(namespace, self.dest, request.args["url"])\n'
        'def remote_type(value):\n    return request.args["url"]\n'
        "def main():\n    parser=argparse.ArgumentParser()\n"
        f'    parser.add_argument("--url"{option})\n'
        "    args=parser.parse_args()\n    return requests.get(args.url)\n"
    )
    write_fixture(tmp_path, "app.py", source)
    rows = scan_ctx(tmp_path, [tmp_path / "app.py"])
    assert any(row["rule_id"] == "SKY-D216" for row in rows) is bool(option)


@pytest.mark.parametrize(
    "configuration",
    [
        "parser=argparse.ArgumentParser(parents=[foreign.parser()])",
        'parser=argparse.ArgumentParser(argument_default=request.args["url"])',
        'parser=argparse.ArgumentParser(); parser.add_argument("--url", default=request.args["url"])',
    ],
)
def test_parser_constructor_and_defaults_require_operator_sources(
    tmp_path, configuration
):
    source = (
        "import argparse, requests, foreign\nfrom flask import request\n"
        "def main():\n    " + configuration + "\n"
        "    args=parser.parse_args()\n    return requests.get(args.url)\n"
    )
    write_fixture(tmp_path, "app.py", source)
    rows = scan_ctx(tmp_path, [tmp_path / "app.py"])
    assert any(row["rule_id"] == "SKY-D216" for row in rows)
