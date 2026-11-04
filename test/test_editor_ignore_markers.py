"""The markers the VS Code extension writes are the ones the CLI honours.

editors/vscode/test/suppressionCore.test.js asserts the same literal strings
from the extension side. The markers the extension used to write must still
leave findings reported: they were never a CLI suppression.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

import pytest

from skylos.analyzer import analyze
from skylos.core.inline_directives import inline_ignores
from skylos.visitors.languages.go import clear_go_cache


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


_SECURITY_MARKER_CASES = {
    "run.sh": (
        "SKY-D212",
        """
        #!/bin/bash
        eval "$1" # skylos: ignore[SKY-D212] operator input
        eval "$2" # skylos: ignore[SKY-D211]
        eval "$3 # skylos: ignore[SKY-D212]"
        eval "$4" # skylos: ignore
        """,
    ),
    "Handler.java": (
        "SKY-D211",
        """
        import java.sql.*;
        import javax.servlet.http.*;

        public class Handler {
            public void handle(HttpServletRequest request, Connection conn) throws Exception {
                String name = request.getParameter("name");
                Statement stmt = conn.createStatement();
                stmt.executeQuery("SELECT * FROM a WHERE n = '" + name + "'"); // skylos: ignore[SKY-D211] admin lookup
                stmt.executeQuery("SELECT * FROM b WHERE n = '" + name + "'"); // skylos: ignore[SKY-D212]
                stmt.executeQuery("SELECT * FROM c WHERE n = '" + name + "' // skylos: ignore[SKY-D211]");
                stmt.executeQuery("SELECT * FROM d WHERE n = '" + name + "'"); /* skylos: ignore */
            }
        }
        """,
    ),
    "app.php": (
        "SKY-D211",
        """
        <?php
        function handle($pdo) {
            $name = $_GET['name'];
            $pdo->query("SELECT * FROM a WHERE n = '" . $name . "'"); // skylos: ignore[SKY-D211]
            $pdo->query("SELECT * FROM b WHERE n = '" . $name . "'"); // skylos: ignore[SKY-D212]
            $pdo->query("SELECT * FROM c WHERE n = '" . $name . "' # skylos: ignore");
            $pdo->query("SELECT * FROM d WHERE n = '" . $name . "'"); # skylos: ignore
        }
        """,
    ),
    "Repo.cs": (
        "SKY-D211",
        """
        using System.Data.SqlClient;

        public class Repo {
            public void Handle(string name, SqlConnection conn) {
                var a = new SqlCommand("SELECT * FROM a WHERE n = '" + name + "'", conn); // skylos: ignore[SKY-D211]
                var b = new SqlCommand("SELECT * FROM b WHERE n = '" + name + "'", conn); // skylos: ignore[SKY-D212]
                var c = new SqlCommand(@"SELECT * FROM c WHERE n = '" + name + @"' // skylos: ignore", conn);
                var d = new SqlCommand("SELECT * FROM d WHERE n = '" + name + "'", conn); // skylos: ignore
            }
        }
        """,
    ),
    "src/lib.rs": (
        "SKY-D212",
        """
        use std::process::Command;

        pub fn run<'a>(cmd: &'a str) {
            Command::new("sh").arg("-c").arg(cmd).spawn().unwrap(); // skylos: ignore[SKY-D212]
            Command::new("sh").arg("-c").arg(cmd).spawn().unwrap(); // skylos: ignore[SKY-D211]
            Command::new("sh").arg("-c").arg(cmd).arg("// skylos: ignore").spawn().unwrap();
            Command::new("sh").arg("-c").arg(cmd).spawn().unwrap(); // skylos: ignore
        }
        """,
    ),
    "lib/app.dart": (
        "SKY-D212",
        """
        import 'dart:io';

        void handle(String name) {
          Process.run('sh', ['-c', name]); // skylos: ignore[SKY-D212]
          Process.run('sh', ['-c', name]); // skylos: ignore[SKY-D211]
          Process.run('sh', ['-c', name, '// skylos: ignore']);
          /* skylos: ignore */ Process.run('sh', ['-c', name]);
        }
        """,
    ),
    "Handler.kt": (
        "SKY-D211",
        """
        import java.sql.Connection
        import javax.servlet.http.HttpServletRequest

        class Handler(private val conn: Connection) {
            fun run(request: HttpServletRequest) {
                val id = request.getParameter("id")
                conn.createStatement().executeQuery("SELECT * FROM a WHERE id = " + id) // skylos: ignore[SKY-D211]
                conn.createStatement().executeQuery("SELECT * FROM b WHERE id = " + id) // skylos: ignore[SKY-D212]
                conn.createStatement().executeQuery("SELECT * FROM c WHERE id = " + id + " // skylos: ignore")
                conn.createStatement().executeQuery("SELECT * FROM d WHERE id = " + id) // skylos: ignore
            }
        }
        """,
    ),
    "main.go": (
        "SKY-D211",
        """
        package main

        import (
            "database/sql"
            "net/http"
        )

        func handler(w http.ResponseWriter, r *http.Request, db *sql.DB) {
            id := r.URL.Query().Get("id")
            db.Query("SELECT * FROM a WHERE id = " + id) // skylos: ignore[SKY-D211]
            db.Query("SELECT * FROM b WHERE id = " + id) //nolint:gosec
            db.Query("SELECT * FROM c WHERE id = " + id + " // skylos: ignore")
            db.Query("SELECT * FROM d WHERE id = " + id) // skylos: ignore
        }

        func main() {
            var db *sql.DB
            http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { handler(w, r, db) })
        }
        """,
    ),
}


def _finding_lines(source):
    lines = textwrap.dedent(source).lstrip().splitlines()
    return [
        number
        for number, line in enumerate(lines, start=1)
        if "SELECT" in line
        or "Process.run" in line
        or "spawn()" in line
        or line.startswith("eval")
    ]


@pytest.mark.parametrize("relative", sorted(_SECURITY_MARKER_CASES))
def test_comment_markers_suppress_named_security_rules_in_every_language(
    scan, monkeypatch, relative
):
    if relative.endswith(".dart"):
        pytest.importorskip("tree_sitter_dart_orchard")
    if relative.endswith(".go"):
        engine = Path(__file__).resolve().parent.parent / "skylos/engines/go/skylos-go"
        if not engine.is_file():
            pytest.skip("repo skylos-go engine binary not available")
        monkeypatch.setenv("SKYLOS_GO_BIN", str(engine))
        clear_go_cache()
    root, _ = scan
    rule_id, source = _SECURITY_MARKER_CASES[relative]
    if relative == "main.go":
        _write(root, "go.mod", "module example.com/demo\n\ngo 1.22\n")
    _write(root, relative, source)
    named, other_rule, in_string, blanket = _finding_lines(source)

    result = json.loads(analyze(str(root), conf=0, enable_danger=True))

    reported = sorted(
        item["line"] for item in result.get("danger", []) if item["rule_id"] == rule_id
    )
    suppressed = sorted(
        item["line"]
        for item in result.get("suppressed", [])
        if item.get("rule_id") == rule_id
        and item.get("reason") == "inline ignore comment"
    )
    assert reported == [other_rule, in_string]
    assert suppressed == [named, blanket]


def test_rule_scoped_markers_hide_only_the_named_dead_code_rule(scan):
    root, _ = scan
    _write(
        root,
        "mod.py",
        """
        import json  # skylos: ignore[SKY-U002]
        import csv  # skylos: ignore[SKY-U001]


        def unused_a():  # skylos: ignore[SKY-U001] kept for plugins
            return 1


        def unused_b():  # skylos: ignore[SKY-U002]
            return 2


        def unused_c():  # skylos: ignore[SKY-U001, SKY-U003]
            return 3


        class UnusedK:  # skylos: ignore[SKY-U004]
            pass


        class UnusedL:  # skylos: ignore[SKY-U001]
            pass
        """,
    )
    _write(
        root,
        "Util.kt",
        """
        class Util {
            private fun hiddenK() {} // skylos: ignore[SKY-U001]
            private fun shownK() {} // skylos: ignore[SKY-U002]
            private fun shownInString() { val s = "${mapOf("k" to "// skylos: ignore")["k"]}" }
        }
        """,
    )
    _write(
        root,
        "util.cpp",
        """
        static void hidden_cpp() {} // skylos: ignore[SKY-U001]
        static void shown_cpp() {} // skylos: ignore[SKY-U003]
        static void shown_raw() { auto r = R"x(
        // skylos: ignore
        )x"; }
        """,
    )

    result = json.loads(analyze(str(root), conf=0))

    def names(key):
        return {item["simple_name"] for item in result.get(key, [])}

    assert "csv" in names("unused_imports")
    assert "json" not in names("unused_imports")
    functions = names("unused_functions")
    assert {
        "unused_b",
        "shownK",
        "shownInString",
        "shown_cpp",
        "shown_raw",
    } <= functions
    assert not {"unused_a", "unused_c", "hiddenK", "hidden_cpp"} & functions
    assert "UnusedL" in names("unused_classes")
    assert "UnusedK" not in names("unused_classes")


@pytest.mark.parametrize(
    ("relative", "text", "lines", "rules"),
    [
        (
            "a.kt",
            'val s = "${m["// skylos: ignore"]}"\nf() // skylos: ignore\n',
            {2},
            {},
        ),
        (
            "a.rs",
            "fn f<'a>(x: &'a str) {} // skylos: ignore\n"
            'let s = r#"// skylos: ignore"#;\n'
            "let c = '\"'; // skylos: ignore[SKY-D212]\n",
            {1},
            {3: {"SKY-D212"}},
        ),
        (
            "a.cs",
            'var a = @"C:\\ // skylos: ignore";\n'
            'var b = $"{d["k // skylos: ignore"]}";\n'
            "f(); // skylos: ignore\n",
            {3},
            {},
        ),
        (
            "a.sh",
            "cat <<EOF\n# skylos: ignore-start\nEOF\n"
            'x="$(echo "a # skylos: ignore")"\n'
            "echo ${#arr} # skylos: ignore[SKY-D212]\n"
            "x=$((y << 2))\n"
            'eval "$1" # skylos: ignore\n',
            {7},
            {5: {"SKY-D212"}},
        ),
        (
            "a.php",
            "<p>// skylos: ignore</p>\n<?php\n#[Attr] // skylos: ignore[SKY-D211]\n"
            "$h = <<<EOT\n// skylos: ignore\nEOT;\n",
            set(),
            {3: {"SKY-D211"}},
        ),
        (
            "a.java",
            "/*\n skylos: ignore\n*/\nf();\n// TODO skylos: ignore\ng();\n",
            set(),
            {},
        ),
        ("a.go", 's := "open\n// skylos: ignore\n', set(), {}),
    ],
)
def test_directives_are_read_only_from_real_comments(relative, text, lines, rules):
    assert inline_ignores(relative, text) == (lines, rules)


def test_directive_source_rejects_symlink(tmp_path):
    from skylos.analysis.file_processing import _read_directive_source

    source = tmp_path / "source.java"
    source.write_text("run(); // skylos: ignore[SKY-D212]\n", encoding="utf-8")
    link = tmp_path / "linked.java"
    try:
        link.symlink_to(source)
    except OSError:
        pytest.skip("symlinks are not supported on this filesystem")

    assert _read_directive_source(link) is None


@pytest.mark.parametrize("location", ["contained", "outside", "symlink_parent"])
def test_directive_source_respects_supplied_project_root(tmp_path, location):
    from skylos.analysis.file_processing import _read_directive_source

    root = tmp_path / "repo"
    root.mkdir()
    source = root / "src" / "source.java"
    source.parent.mkdir()
    content = "run(); // skylos: ignore[SKY-D212]\n"
    source.write_text(content, encoding="utf-8")
    if location == "outside":
        source = tmp_path / "outside.java"
        source.write_text(content, encoding="utf-8")
    elif location == "symlink_parent":
        alias = root / "alias"
        try:
            alias.symlink_to(source.parent, target_is_directory=True)
        except OSError:
            pytest.skip("symlinks are not supported on this filesystem")
        source = alias / source.name

    result = _read_directive_source(source, project_root=root)

    assert result == (content if location == "contained" else None)


@pytest.mark.parametrize("extra_byte", [False, True])
def test_directive_source_enforces_byte_limit(tmp_path, extra_byte):
    from skylos.analysis.file_processing import (
        _MAX_DIRECTIVE_SOURCE_BYTES,
        _read_directive_source,
    )

    source = tmp_path / "source.java"
    payload = "é".encode("utf-8") * (_MAX_DIRECTIVE_SOURCE_BYTES // 2)
    payload += b"x" * (_MAX_DIRECTIVE_SOURCE_BYTES - len(payload))
    if extra_byte:
        payload += b"x"
    source.write_bytes(payload)

    result = _read_directive_source(source)

    assert result == (None if extra_byte else payload.decode("utf-8"))


def test_directive_source_preserves_source_newlines(tmp_path):
    from skylos.analysis.file_processing import _read_directive_source

    source = tmp_path / "source.java"
    payload = b"run();\r\n// skylos: ignore[SKY-D212]\rnext();\n"
    source.write_bytes(payload)

    result = _read_directive_source(source)

    assert result == payload.decode("utf-8")
    assert inline_ignores(source, result) == (set(), {})
