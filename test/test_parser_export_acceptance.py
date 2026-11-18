"""Independent source/provider checks; snippets are scanned, never executed."""

import pytest

from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture

PARSER = """import argparse, os, requests

def number(raw):
    value=float(raw)
    if value <= 0:
        raise ValueError('positive value required')
    return value

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--url', default=os.getenv('API_URL'))
    parser.add_argument('--timeout', type=number, default=5.0)
    args=parser.parse_args()
    return requests.get(args.url, timeout=args.timeout)

main()
"""

EXPORT = """import ast
from pathlib import Path
SOURCE=Path(__file__).parent / 'core.py'

def load():
    tree=ast.parse(SOURCE.read_text())
    namespace={}
    exec(compile(tree, str(SOURCE), 'exec'), namespace)
    return staticmethod(namespace['callback'])

load()
"""


def _rules(tmp_path, source, *, extra=None):
    write_fixture(tmp_path, "pyproject.toml", '[project]\nname="proof-review"\n')
    files = [write_fixture(tmp_path, "app.py", source)]
    for name, body in (extra or {}).items():
        files.append(write_fixture(tmp_path, name, body))
    return {row["rule_id"] for row in scan_ctx(tmp_path, files)}


def test_native_scalar_and_operator_default_preserve_cli_url(tmp_path):
    assert "SKY-D216" not in _rules(tmp_path, PARSER)


@pytest.mark.parametrize(
    "mutation",
    [
        "callback-escape",
        "callback-rebind",
        "builtin-float",
        "getenv-provider",
        "http-default",
        "custom-action",
        "http-environment",
    ],
)
def test_parser_scalar_or_default_proof_rejects_other_sources(tmp_path, mutation):
    source = PARSER
    if mutation == "callback-escape":
        source = source.replace(
            "def main():", "import foreign\nforeign.register(number)\n\ndef main():"
        )
    elif mutation == "callback-rebind":
        source = source.replace(
            "def main():", "import foreign\nnumber=foreign.number\n\ndef main():"
        )
    elif mutation == "builtin-float":
        source = source.replace(
            "def main():",
            "import builtins, foreign\nbuiltins.float=foreign.number\n\ndef main():",
        )
    elif mutation == "getenv-provider":
        source = source.replace(
            "def main():", "import foreign\nos.getenv=foreign.default\n\ndef main():"
        )
    elif mutation == "http-default":
        source = source.replace(
            "import argparse, os, requests",
            "import argparse, os, requests\nfrom flask import request",
        )
        source = source.replace("os.getenv('API_URL')", "request.args['url']")
    elif mutation == "custom-action":
        source = source.replace(
            "def main():",
            """from flask import request
class RemoteAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        namespace.url=request.args['url']

def main():""",
        )
        source = source.replace(
            "'--url', default=", "'--url', action=RemoteAction, default="
        )
    else:
        source += """
from fastapi import FastAPI
app=FastAPI()
@app.post('/fetch')
def fetch(url: str):
    os.environ['API_URL']=url
    return main()
"""
    assert "SKY-D216" in _rules(tmp_path, source)


def test_owned_source_export_through_native_descriptor_is_not_exec_input(tmp_path):
    assert "SKY-D202" not in _rules(
        tmp_path, EXPORT, extra={"core.py": "def callback():\n    return 1\n"}
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "local-wrapper",
        "builtin-wrapper",
        "imported-wrapper",
        "namespace-store",
        "namespace-alias",
        "namespace-escape",
        "request-source",
    ],
)
def test_owned_export_proof_rejects_wrapper_and_namespace_changes(tmp_path, mutation):
    source = EXPORT
    extra = {"core.py": "def callback():\n    return 1\n"}
    if mutation == "local-wrapper":
        source = source.replace(
            "def load():", "import foreign\nstaticmethod=foreign.wrap\n\ndef load():"
        )
    elif mutation == "builtin-wrapper":
        source = source.replace(
            "def load():",
            "import builtins, foreign\nbuiltins.staticmethod=foreign.wrap\n\ndef load():",
        )
    elif mutation == "imported-wrapper":
        source = source.replace("import ast", "import patcher\nimport ast")
        extra["patcher.py"] = (
            "import builtins, foreign\nbuiltins.staticmethod=foreign.wrap\n"
        )
    elif mutation == "namespace-store":
        source = source.replace(
            "    exec(compile",
            "    namespace['__builtins__']=external\n    exec(compile",
        )
    elif mutation == "namespace-alias":
        source = source.replace(
            "    exec(compile",
            "    alias=namespace\n    alias['__builtins__']=external\n    exec(compile",
        )
    elif mutation == "namespace-escape":
        source = source.replace(
            "    return staticmethod",
            "    foreign.consume(namespace)\n    return staticmethod",
        )
    else:
        source = source.replace("import ast", "from flask import request\nimport ast")
        source = source.replace("SOURCE.read_text()", "request.args['code']")
    assert "SKY-D202" in _rules(tmp_path, source, extra=extra)


@pytest.mark.parametrize("operand", ["os.environ['FETCH_URL']", "sys.argv[1]"])
@pytest.mark.parametrize("forwarded", [False, True])
def test_worker_url_transport_keeps_http_control_distinct_from_operator(
    tmp_path, operand, forwarded
):
    worker = (
        "import os, sys, requests\n"
        "def fetch():\n    return requests.get(" + operand + ", timeout=5)\n"
        "fetch()\n"
    )
    extra = {}
    if forwarded:
        arguments = "[sys.executable, 'app.py', url]"
        keywords = ""
        if operand.startswith("os.environ"):
            arguments = "[sys.executable, 'app.py']"
            keywords = ", env={'FETCH_URL': url}"
        extra["z_routes.py"] = (
            "import subprocess, sys\nfrom fastapi import FastAPI\napp=FastAPI()\n"
            "@app.post('/fetch')\ndef route(url: str):\n"
            "    return subprocess.run(" + arguments + keywords + ")\n"
        )
    rules = _rules(tmp_path, worker, extra=extra)
    assert ("SKY-D216" in rules) is forwarded


@pytest.mark.parametrize(
    "dependency",
    [
        "argparse._ActionsContainer.add_argument",
        "argparse._StoreAction.__call__",
    ],
)
def test_parser_operator_proof_requires_native_configuration_and_store_dependencies(
    tmp_path, dependency
):
    source = PARSER.replace(
        "def main():",
        "import foreign\n" + dependency + "=foreign.inject\n\ndef main():",
    )
    assert "SKY-D216" in _rules(tmp_path, source)


@pytest.mark.parametrize(
    ("mapping", "core"),
    [
        (
            "{'transform': eval, 'payload': code}",
            "RESULT=transform(payload)\ndef callback():\n    return RESULT\n",
        ),
        (
            "{'__builtins__': {'str': eval}, 'payload': code}",
            "RESULT=str(payload)\ndef callback():\n    return RESULT\n",
        ),
    ],
)
def test_owned_source_proof_rejects_injected_executable_globals(
    tmp_path, mapping, core
):
    source = EXPORT.replace("def load():", "def load(code):")
    source = source.replace("namespace={}", "namespace=" + mapping)
    source = source.replace(
        "\nload()\n",
        """
from fastapi import FastAPI
app=FastAPI()
@app.post('/load')
def route(code: str):
    return load(code)
""",
    )
    assert "SKY-D202" in _rules(tmp_path, source, extra={"core.py": core})


@pytest.mark.parametrize(
    "replacement",
    [
        "import os, foreign\nos.environ=foreign.mapping\n",
        "import argparse, foreign\nargparse._StoreAction.__call__=foreign.inject\n",
    ],
)
def test_parser_producer_contract_checks_imported_wrapper_dependencies(
    tmp_path, replacement
):
    source = PARSER.replace("def main():", "import patcher\n\ndef main():")
    assert "SKY-D216" in _rules(tmp_path, source, extra={"patcher.py": replacement})
