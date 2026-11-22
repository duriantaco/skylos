import json
import shutil
import subprocess
from importlib import resources
from pathlib import Path

import pytest
import yaml

from skylos.commands.rules_cmd import run_rules_command


def test_pack_inventory_excludes_traversal_rules():
    pack = resources.files("skylos.rules").joinpath("packs/vulnhunter.yml")
    rules = yaml.safe_load(pack.read_text(encoding="utf-8"))["rules"]
    ids = {rule["id"] for rule in rules}
    assert len(ids) == len(rules) == 42
    assert {"VH127", "VH131", "VH137", "VH138", "VHOG153"} <= ids
    assert ids.isdisjoint(
        {
            "VHOG106",
            "VHOG107",
            "VHOG116",
            "VHOG119",
            "VHOG136",
            "VHOG140",
            "VHOG144",
            "VHOG148",
            "VHOG152",
            "VHOG154",
            "VHOG156",
        }
    )


def test_missing_engine_is_reported(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert run_rules_command(["vulnhunter", str(tmp_path)]) == 2
    assert "Semgrep" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("errors", "expected"), [([], 1), ([{"type": "Timeout"}], 2)]
)
def test_findings_do_not_hide_reported_scan_errors(
    tmp_path, monkeypatch, capsys, errors, expected
):
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/semgrep")

    def scan(command, *, check):
        status_report = Path(command[command.index("--json-output") + 1])
        status_report.write_text(
            json.dumps({"results": [{"check_id": "test-finding"}], "errors": errors}),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(subprocess, "run", scan)
    assert run_rules_command(["vulnhunter", "--format", "sarif", str(tmp_path)]) == expected
    assert ("scan incomplete" in capsys.readouterr().err) == bool(errors)


@pytest.mark.skipif(not shutil.which("semgrep"), reason="requires Semgrep CLI")
def test_paired_examples_through_pack_cli(tmp_path, capfd):
    from textwrap import dedent

    for ext in ("c", "cpp"):
        (tmp_path / f"shell.{ext}").write_text(
            dedent("""\
            #include <stdlib.h>
            int main(int count, char **inputs) {
                if (count == 2) return system(inputs[1]);
                return system("true");
            }
            void helper(char *name) { system(name); }
        """)
        )
    (tmp_path / "app.py").write_text(
        dedent("""\
        from ariadne.asgi import GraphQL
        from flask import request
        from pymongo import MongoClient
        def service(uri, schema, rules, oracle):
            db = MongoClient(uri)
            db["test"]["items"].find_one(request.get_json())
            db["test"]["items"].find_one({"id": 2})
            GraphQL(schema, introspection=True)
            GraphQL(schema, introspection=False, validation_rules=rules)
            return oracle.functions.latestRoundData().call()[1]
    """)
    )
    assert run_rules_command(["vulnhunter", "--format", "json", str(tmp_path)]) == 1
    report = json.loads(capfd.readouterr().out)
    assert not report["errors"]
    assert {
        (row["check_id"], Path(row["path"]).name, row["start"]["line"])
        for row in report["results"]
    } == {
        ("VHOG153", "shell.c", 3),
        ("VHOG153", "shell.cpp", 3),
        ("VH127", "app.py", 6),
        ("VH137", "app.py", 8),
        ("VH138", "app.py", 8),
        ("VH131", "app.py", 10),
    }
