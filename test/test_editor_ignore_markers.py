"""The markers the VS Code extension writes are the ones the CLI honours.

editors/vscode/test/suppressionCore.test.js asserts the same literal strings
from the extension side. The markers the extension used to write must still
leave findings reported: they were never a CLI suppression.
"""

from __future__ import annotations

import json
import textwrap

import pytest

from skylos.analyzer import analyze


def _write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(text).lstrip(), encoding="utf-8")


@pytest.fixture
def scan(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SKYLOS_CUSTOM_RULES", "[]")
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".git").mkdir()

    def run():
        result = json.loads(analyze(str(root), conf=0, enable_danger=True))
        danger = sorted(
            (item["file"].rsplit("/", 1)[-1], item["line"], item["rule_id"])
            for item in result.get("danger", [])
        )
        dead = sorted(
            item["simple_name"] for item in result.get("unused_functions", [])
        )
        return danger, dead

    return root, run


def test_markers_written_by_the_extension_suppress_only_their_target(scan):
    root, run = scan
    _write(
        root,
        "rules.py",
        """
        import sqlite3
        from flask import request


        def handler():
            conn = sqlite3.connect("x.db")
            name = request.args.get("name")
            conn.execute("SELECT * FROM t WHERE n = '" + name + "'")  # skylos: ignore[SKY-D211]
            conn.execute("DELETE FROM t WHERE n = '" + name + "'")
            conn.execute("UPDATE t SET n = '" + name + "'")  # skylos: ignore[SKY-D212]


        def dead_marked():  # skylos: ignore
            return 1
        """,
    )
    _write(
        root,
        "whole.py",
        """
        #!/usr/bin/env python3
        # -*- coding: utf-8 -*-
        # skylos: ignore-start
        def whole_file_dead():
            return 1
        """,
    )
    _write(
        root,
        "api.ts",
        """
        import { exec } from "child_process";

        export function run(req: any) {
          exec("ls " + req.query.dir);  // skylos: ignore[SKY-D212]
          /* skylos: ignore[SKY-D212] */ exec("cat " + req.query.file); // keep
          exec("rm " + req.query.path);
          exec("du " + req.query.size);  // skylos: ignore[SKY-D211]
        }

        function deadMarked() {  // skylos: ignore
          return 1;
        }
        """,
    )
    _write(
        root,
        "whole.ts",
        """
        #!/usr/bin/env node
        // skylos: ignore-start
        function wholeFileDead() {
          return 1;
        }
        """,
    )

    danger, dead = run()

    assert danger == [
        ("api.ts", 6, "SKY-D212"),
        ("api.ts", 7, "SKY-D212"),
        ("rules.py", 9, "SKY-D211"),
        ("rules.py", 10, "SKY-D211"),
    ]
    assert "dead_marked" not in dead
    assert "whole_file_dead" not in dead
    assert "deadMarked" not in dead
    assert "wholeFileDead" not in dead


def test_markers_the_extension_used_to_write_still_report(scan):
    root, run = scan
    _write(
        root,
        "mod.py",
        """
        # skylos-ignore-file
        def file_marker_unused():
            return 1


        def dash_marker_unused():  # skylos-ignore
            return 2
        """,
    )
    _write(
        root,
        "web.ts",
        """
        // skylos-ignore-file
        function dashMarkerUnused() {  // skylos-ignore
          return 1;
        }
        """,
    )
    _write(root, ".skylosignore", "listed_unused\n")
    _write(root, "third.py", "def listed_unused():\n    return 1\n")

    _, dead = run()

    assert {
        "file_marker_unused",
        "dash_marker_unused",
        "dashMarkerUnused",
        "listed_unused",
    } <= set(dead)
