import ast
import textwrap
import tempfile
from pathlib import Path

from skylos.rules.quality.logic import (
    EmptyErrorHandlerRule,
    MissingResourceCleanupRule,
    DebugLeftoverRule,
)
from skylos.rules.quality.unused_deps import scan_unused_dependencies


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(textwrap.dedent(code))
    findings = []
    context = {"filename": filename, "mod": "test_module"}
    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings

class TestEmptyErrorHandler:
    def test_except_pass(self):
        code = """
        try:
            x = 1
        except:
            pass
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_except_exception_pass(self):
        code = """
        try:
            x = 1
        except Exception:
            pass
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_except_continue(self):
        code = """
        for i in range(10):
            try:
                x = 1
            except:
                continue
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_except_return(self):
        code = """
        def foo():
            try:
                x = 1
            except ValueError:
                return
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        rid_findings = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert any(f["severity"] == "HIGH" for f in rid_findings)

    def test_except_return_none(self):
        code = """
        def foo():
            try:
                x = 1
            except ValueError:
                return None
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        rid_findings = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert any(f["severity"] == "HIGH" for f in rid_findings)

    def test_except_ellipsis(self):
        code = """
        try:
            x = 1
        except:
            ...
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_handler_only_comments(self):
        # Comments become string expressions in AST (docstrings), body is trivial
        code = """
        try:
            x = 1
        except:
            "this is a comment-like string"
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_contextlib_suppress_exception(self):
        code = """
        import contextlib
        with contextlib.suppress(Exception):
            do_something()
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_contextlib_suppress_base_exception(self):
        code = """
        import contextlib
        with contextlib.suppress(BaseException):
            do_something()
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L007" for f in findings)

    def test_handler_with_logging_not_flagged(self):
        code = """
        try:
            x = 1
        except Exception:
            logger.error("failed")
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert len(l007) == 0

    def test_handler_with_reraise_not_flagged(self):
        code = """
        try:
            x = 1
        except Exception:
            raise
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert len(l007) == 0

    def test_handler_with_actual_code_not_flagged(self):
        code = """
        try:
            x = 1
        except Exception as e:
            print(e)
            handle_error(e)
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert len(l007) == 0

    def test_keyboard_interrupt_not_flagged(self):
        code = """
        try:
            x = 1
        except KeyboardInterrupt:
            pass
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert len(l007) == 0

    def test_system_exit_not_flagged(self):
        code = """
        try:
            x = 1
        except SystemExit:
            pass
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert len(l007) == 0

    def test_contextlib_suppress_specific_not_flagged(self):
        code = """
        import contextlib
        with contextlib.suppress(FileNotFoundError):
            os.remove("tmp.txt")
        """
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert len(l007) == 0


class TestMissingResourceCleanup:
    def test_open_without_with(self):
        code = """
        def foo():
            f = open("x.txt")
            data = f.read()
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)

    def test_open_with_with_not_flagged(self):
        code = """
        def foo():
            with open("x.txt") as f:
                data = f.read()
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        l008 = [f for f in findings if f["rule_id"] == "SKY-L008"]
        assert len(l008) == 0

    def test_sqlite_connect_without_with(self):
        code = """
        import sqlite3
        def foo():
            conn = sqlite3.connect("db.sqlite")
            conn.execute("SELECT 1")
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)

    def test_return_open_not_flagged(self):
        code = """
        def get_file():
            f = open("x.txt")
            return f
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        l008 = [f for f in findings if f["rule_id"] == "SKY-L008"]
        assert len(l008) == 0

    def test_yield_open_not_flagged(self):
        code = """
        def gen_file():
            f = open("x.txt")
            yield f
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        l008 = [f for f in findings if f["rule_id"] == "SKY-L008"]
        assert len(l008) == 0

    def test_close_in_finally_not_flagged(self):
        code = """
        def foo():
            try:
                f = open("x.txt")
                data = f.read()
            finally:
                f.close()
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        l008 = [f for f in findings if f["rule_id"] == "SKY-L008"]
        assert len(l008) == 0

    def test_socket_without_with(self):
        code = """
        import socket
        def foo():
            s = socket.socket()
            s.connect(("localhost", 80))
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)

    def test_requests_session_without_with(self):
        code = """
        import requests
        def foo():
            s = requests.Session()
            s.get("http://example.com")
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)

    def test_psycopg2_without_with(self):
        code = """
        import psycopg2
        def foo():
            conn = psycopg2.connect("dbname=test")
            cur = conn.cursor()
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)

    def test_module_level_open_flagged(self):
        code = """
        f = open("config.txt")
        data = f.read()
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)

    def test_open_inside_with_block_not_flagged(self):
        code = """
        def foo():
            with open("a.txt") as a:
                with open("b.txt") as b:
                    pass
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        l008 = [f for f in findings if f["rule_id"] == "SKY-L008"]
        assert len(l008) == 0

    def test_tempfile_without_with(self):
        code = """
        import tempfile
        def foo():
            f = tempfile.NamedTemporaryFile()
            f.write(b"data")
        """
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)


class TestDebugLeftover:
    def test_print_flagged(self):
        code = 'print("debug")'
        findings = check_code(DebugLeftoverRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L009" for f in findings)

    def test_breakpoint_flagged(self):
        code = "breakpoint()"
        findings = check_code(DebugLeftoverRule(), code)
        assert len(findings) >= 1
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert any(f["severity"] == "HIGH" for f in l009)

    def test_pdb_set_trace_flagged(self):
        code = """
        import pdb
        pdb.set_trace()
        """
        findings = check_code(DebugLeftoverRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L009" for f in findings)

    def test_ic_flagged(self):
        code = """
        from icecream import ic
        ic(some_var)
        """
        findings = check_code(DebugLeftoverRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L009" for f in findings)

    def test_ipdb_set_trace_flagged(self):
        code = """
        import ipdb
        ipdb.set_trace()
        """
        findings = check_code(DebugLeftoverRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L009" for f in findings)

    def test_print_in_cli_not_flagged(self):
        code = 'print("Hello user")'
        findings = check_code(DebugLeftoverRule(), code, filename="cli.py")
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert len(l009) == 0

    def test_print_in_test_file_not_flagged(self):
        code = 'print("test output")'
        findings = check_code(DebugLeftoverRule(), code, filename="test_something.py")
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert len(l009) == 0

    def test_print_in_main_not_flagged(self):
        code = 'print("main output")'
        findings = check_code(DebugLeftoverRule(), code, filename="__main__.py")
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert len(l009) == 0

    def test_print_in_scripts_dir_not_flagged(self):
        code = 'print("running script")'
        findings = check_code(
            DebugLeftoverRule(), code, filename="scripts/deploy.py"
        )
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert len(l009) == 0

    def test_breakpoint_in_cli_still_flagged(self):
        code = "breakpoint()"
        findings = check_code(DebugLeftoverRule(), code, filename="cli.py")
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert len(l009) >= 1

    def test_pprint_flagged(self):
        code = """
        from pprint import pprint
        pprint(data)
        """
        findings = check_code(DebugLeftoverRule(), code)
        assert any(f["rule_id"] == "SKY-L009" for f in findings)


class TestUnusedDependencies:
    def _make_project(self, tmpdir, requirements, py_code):
        req_path = tmpdir / "requirements.txt"
        req_path.write_text(requirements, encoding="utf-8")

        py_file = tmpdir / "app.py"
        py_file.write_text(textwrap.dedent(py_code), encoding="utf-8")

        return tmpdir, [py_file]

    def test_declared_and_imported_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            root, files = self._make_project(
                tmpdir,
                "requests\n",
                "import requests\nrequests.get('http://example.com')\n",
            )
            findings = scan_unused_dependencies(root, files)
            u005 = [f for f in findings if f["rule_id"] == "SKY-U005"]
            assert len(u005) == 0

    def test_declared_never_imported_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            root, files = self._make_project(
                tmpdir,
                "requests\nflask\n",
                "import requests\nrequests.get('http://example.com')\n",
            )
            findings = scan_unused_dependencies(root, files)
            u005 = [f for f in findings if f["rule_id"] == "SKY-U005"]
            assert len(u005) >= 1
            assert any("flask" in f["name"] for f in u005)

    def test_cli_only_package_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            root, files = self._make_project(
                tmpdir,
                "pytest\nblack\nruff\n",
                "x = 1\n",
            )
            findings = scan_unused_dependencies(root, files)
            u005 = [f for f in findings if f["rule_id"] == "SKY-U005"]
            assert len(u005) == 0

    def test_own_project_name_not_flagged(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            pyproj = tmpdir / "pyproject.toml"
            pyproj.write_text(
                '[project]\nname = "mypackage"\ndependencies = ["mypackage"]\n',
                encoding="utf-8",
            )
            py_file = tmpdir / "app.py"
            py_file.write_text("x = 1\n", encoding="utf-8")
            findings = scan_unused_dependencies(tmpdir, [py_file])
            u005 = [f for f in findings if f["rule_id"] == "SKY-U005"]
            names = [f["name"] for f in u005]
            assert "mypackage" not in names

    def test_no_manifest_no_findings(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            py_file = tmpdir / "app.py"
            py_file.write_text("import os\n", encoding="utf-8")
            findings = scan_unused_dependencies(tmpdir, [py_file])
            assert len(findings) == 0

    def test_hyphen_underscore_mapping(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            root, files = self._make_project(
                tmpdir,
                "my-package\n",
                "import my_package\nmy_package.do_stuff()\n",
            )
            findings = scan_unused_dependencies(root, files)
            u005 = [f for f in findings if f["rule_id"] == "SKY-U005"]
            assert len(u005) == 0

    def test_multiple_unused(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            root, files = self._make_project(
                tmpdir,
                "requests\nflask\ncelery\n",
                "x = 1\n",
            )
            findings = scan_unused_dependencies(root, files)
            u005 = [f for f in findings if f["rule_id"] == "SKY-U005"]
            # celery is in RUNTIME_PLUGIN_PACKAGES, so it's skipped
            names = {f["name"] for f in u005}
            assert "requests" in names
            assert "flask" in names

    def test_pyproject_toml_deps(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir = Path(tmpdir)
            pyproj = tmpdir / "pyproject.toml"
            pyproj.write_text(
                '[project]\nname = "myapp"\ndependencies = ["click", "rich"]\n',
                encoding="utf-8",
            )
            py_file = tmpdir / "app.py"
            py_file.write_text("import click\n", encoding="utf-8")
            findings = scan_unused_dependencies(tmpdir, [py_file])
            u005 = [f for f in findings if f["rule_id"] == "SKY-U005"]
            names = {f["name"] for f in u005}
            assert "rich" in names
            assert "click" not in names
