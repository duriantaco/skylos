import ast
import textwrap
import tempfile
from pathlib import Path

from skylos.rules.quality.logic import (
    EmptyErrorHandlerRule,
    MissingResourceCleanupRule,
    DebugLeftoverRule,
    SecurityTodoRule,
    DisabledSecurityRule,
    PhantomCallRule,
    InsecureRandomRule,
    HardcodedCredentialRule,
    ErrorDisclosureRule,
    BroadFilePermissionsRule,
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
        findings = check_code(DebugLeftoverRule(), code, filename="scripts/deploy.py")
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


def check_code_with_source(rule, code, filename="test.py"):
    dedented = textwrap.dedent(code)
    tree = ast.parse(dedented)
    findings = []
    context = {"filename": filename, "mod": "test_module", "_source": dedented}
    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


class TestSecurityTodo:
    def test_todo_auth(self):
        code = """
        # TODO: add authentication check here
        def get_users():
            return db.query("SELECT * FROM users")
        """
        findings = check_code_with_source(SecurityTodoRule(), code)
        assert any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_fixme_validate(self):
        code = """
        def search(q):
            # FIXME: sanitize and validate input
            return db.execute(f"SELECT * FROM items WHERE name = '{q}'")
        """
        findings = check_code_with_source(SecurityTodoRule(), code)
        assert any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_hack_disable_ssl(self):
        code = """
        import requests
        # HACK: disable ssl verify for now
        requests.get("https://api.example.com", verify=False)
        """
        findings = check_code_with_source(SecurityTodoRule(), code)
        assert any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_todo_password(self):
        code = """
        # TODO: stop hardcoding password
        PASSWORD = "admin123"
        """
        findings = check_code_with_source(SecurityTodoRule(), code)
        assert any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_temp_bypass(self):
        code = """
        # TEMP: bypass auth security check
        def api_call():
            pass
        """
        findings = check_code_with_source(SecurityTodoRule(), code)
        assert any(f["rule_id"] == "SKY-L010" for f in findings)

    def test_normal_todo_not_flagged(self):
        code = """
        for i in range(10):
            pass
        """
        findings = check_code_with_source(SecurityTodoRule(), code)
        l010 = [f for f in findings if f["rule_id"] == "SKY-L010"]
        assert len(l010) == 0

    def test_normal_fixme_not_flagged(self):
        code = """
        x = 1
        """
        findings = check_code_with_source(SecurityTodoRule(), code)
        l010 = [f for f in findings if f["rule_id"] == "SKY-L010"]
        assert len(l010) == 0


class TestDisabledSecurity:
    def test_verify_false(self):
        code = """
        import requests
        requests.get("https://api.example.com", verify=False)
        """
        findings = check_code(DisabledSecurityRule(), code)
        assert any(f["rule_id"] == "SKY-L011" for f in findings)

    def test_verify_true_not_flagged(self):
        code = """
        import requests
        requests.get("https://api.example.com", verify=True)
        """
        findings = check_code(DisabledSecurityRule(), code)
        l011 = [f for f in findings if f["rule_id"] == "SKY-L011"]
        assert len(l011) == 0

    def test_create_unverified_context(self):
        code = """
        import ssl
        ctx = ssl._create_unverified_context()
        """
        findings = check_code(DisabledSecurityRule(), code)
        assert any(f["rule_id"] == "SKY-L011" for f in findings)

    def test_csrf_exempt(self):
        code = """
        from django.views.decorators.csrf import csrf_exempt

        @csrf_exempt
        def my_view(request):
            pass
        """
        findings = check_code(DisabledSecurityRule(), code)
        assert any(f["rule_id"] == "SKY-L011" for f in findings)

    def test_debug_true(self):
        code = """
        DEBUG = True
        """
        findings = check_code(DisabledSecurityRule(), code)
        assert any(f["rule_id"] == "SKY-L011" for f in findings)

    def test_debug_false_not_flagged(self):
        code = """
        DEBUG = False
        """
        findings = check_code(DisabledSecurityRule(), code)
        l011 = [f for f in findings if f["rule_id"] == "SKY-L011"]
        assert len(l011) == 0

    def test_allowed_hosts_wildcard(self):
        code = """
        ALLOWED_HOSTS = ["*"]
        """
        findings = check_code(DisabledSecurityRule(), code)
        assert any(f["rule_id"] == "SKY-L011" for f in findings)

    def test_allowed_hosts_specific_not_flagged(self):
        code = """
        ALLOWED_HOSTS = ["example.com", "www.example.com"]
        """
        findings = check_code(DisabledSecurityRule(), code)
        l011 = [f for f in findings if f["rule_id"] == "SKY-L011"]
        assert len(l011) == 0

    def test_check_hostname_false(self):
        code = """
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        """
        code2 = """
        some_func(check_hostname=False)
        """
        findings = check_code(DisabledSecurityRule(), code2)
        assert any(f["rule_id"] == "SKY-L011" for f in findings)

    def test_test_file_not_flagged(self):
        code = """
        import requests
        requests.get("https://api.example.com", verify=False)
        """
        findings = check_code(DisabledSecurityRule(), code, filename="test_api.py")
        l011 = [f for f in findings if f["rule_id"] == "SKY-L011"]
        assert len(l011) == 0


class TestPhantomCall:
    def test_sanitize_input_phantom(self):
        code = """
        def process(data):
            clean = sanitize_input(data)
            return clean
        """
        findings = check_code(PhantomCallRule(), code)
        assert any(f["rule_id"] == "SKY-L012" for f in findings)

    def test_validate_token_phantom(self):
        code = """
        def check_request(request):
            validate_token(request.headers["Authorization"])
        """
        findings = check_code(PhantomCallRule(), code)
        assert any(f["rule_id"] == "SKY-L012" for f in findings)

    def test_escape_html_phantom(self):
        code = """
        def render(text):
            return escape_html(text)
        """
        findings = check_code(PhantomCallRule(), code)
        assert any(f["rule_id"] == "SKY-L012" for f in findings)

    def test_defined_locally_not_flagged(self):
        code = """
        def sanitize_input(data):
            return data.strip()

        def process(data):
            clean = sanitize_input(data)
            return clean
        """
        findings = check_code(PhantomCallRule(), code)
        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_imported_not_flagged(self):
        code = """
        from bleach import clean_html

        def render(text):
            return clean_html(text)
        """
        findings = check_code(PhantomCallRule(), code)
        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_method_call_not_flagged(self):
        code = """
        def process(data, validator):
            return validator.sanitize_input(data)
        """
        findings = check_code(PhantomCallRule(), code)
        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_non_security_function_not_flagged(self):
        code = """
        def process():
            result = calculate_total(items)
            return result
        """
        findings = check_code(PhantomCallRule(), code)
        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_multiple_phantoms(self):
        code = """
        def handler(request):
            sanitize_input(request.body)
            validate_token(request.headers["token"])
            escape_html(request.body)
        """
        findings = check_code(PhantomCallRule(), code)
        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 3


class TestInsecureRandom:
    def test_random_for_token(self):
        code = """
        import random
        token = random.randint(100000, 999999)
        """
        findings = check_code(InsecureRandomRule(), code)
        assert any(f["rule_id"] == "SKY-L013" for f in findings)

    def test_random_for_password(self):
        code = """
        import random
        password = random.choice("abcdefghij")
        """
        findings = check_code(InsecureRandomRule(), code)
        assert any(f["rule_id"] == "SKY-L013" for f in findings)

    def test_random_for_session(self):
        code = """
        import random
        session_id = random.randbytes(16)
        """
        findings = check_code(InsecureRandomRule(), code)
        assert any(f["rule_id"] == "SKY-L013" for f in findings)

    def test_random_for_csrf(self):
        code = """
        import random
        csrf_token = random.randrange(0, 2**128)
        """
        findings = check_code(InsecureRandomRule(), code)
        assert any(f["rule_id"] == "SKY-L013" for f in findings)

    def test_random_non_security_not_flagged(self):
        code = """
        import random
        color = random.choice(["red", "blue", "green"])
        """
        findings = check_code(InsecureRandomRule(), code)
        l013 = [f for f in findings if f["rule_id"] == "SKY-L013"]
        assert len(l013) == 0

    def test_secrets_module_not_flagged(self):
        code = """
        import secrets
        token = secrets.token_urlsafe(32)
        """
        findings = check_code(InsecureRandomRule(), code)
        l013 = [f for f in findings if f["rule_id"] == "SKY-L013"]
        assert len(l013) == 0

    def test_test_file_not_flagged(self):
        code = """
        import random
        token = random.randint(0, 9999)
        """
        findings = check_code(InsecureRandomRule(), code, filename="test_auth.py")
        l013 = [f for f in findings if f["rule_id"] == "SKY-L013"]
        assert len(l013) == 0

    def test_attribute_target(self):
        code = """
        import random
        self.api_key = random.randint(0, 999999)
        """
        findings = check_code(InsecureRandomRule(), code)
        assert any(f["rule_id"] == "SKY-L013" for f in findings)


class TestHardcodedCredential:
    def test_password_assignment(self):
        code = """
        password = "admin123"
        """
        findings = check_code(HardcodedCredentialRule(), code)
        assert any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_api_key_assignment(self):
        code = """
        api_key = "sk-1234567890abcdef"
        """
        findings = check_code(HardcodedCredentialRule(), code)
        assert any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_db_password_assignment(self):
        code = """
        db_password = "mysecretpass"
        """
        findings = check_code(HardcodedCredentialRule(), code)
        assert any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_dsn_with_credentials(self):
        code = """
        database_url = "postgresql://admin:secretpass@localhost:5432/mydb"
        """
        findings = check_code(HardcodedCredentialRule(), code)
        assert any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_placeholder_downgraded(self):
        code = """
        password = "changeme"
        """
        findings = check_code(HardcodedCredentialRule(), code)
        l014 = [f for f in findings if f["rule_id"] == "SKY-L014"]
        assert len(l014) >= 1
        assert l014[0]["severity"] == "MEDIUM"

    def test_env_lookup_not_flagged(self):
        code = """
        import os
        password = os.getenv("DB_PASSWORD")
        """
        findings = check_code(HardcodedCredentialRule(), code)
        l014 = [f for f in findings if f["rule_id"] == "SKY-L014"]
        assert len(l014) == 0

    def test_empty_string_not_flagged(self):
        code = """
        password = ""
        """
        findings = check_code(HardcodedCredentialRule(), code)
        l014 = [f for f in findings if f["rule_id"] == "SKY-L014"]
        assert len(l014) == 0

    def test_function_default_credential(self):
        code = """
        def connect(password="admin123"):
            pass
        """
        findings = check_code(HardcodedCredentialRule(), code)
        assert any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_non_credential_var_not_flagged(self):
        code = """
        username = "admin"
        """
        findings = check_code(HardcodedCredentialRule(), code)
        l014 = [f for f in findings if f["rule_id"] == "SKY-L014"]
        assert len(l014) == 0

    def test_suffix_match(self):
        code = """
        my_app_password = "hunter2"
        """
        findings = check_code(HardcodedCredentialRule(), code)
        assert any(f["rule_id"] == "SKY-L014" for f in findings)

    def test_test_file_not_flagged(self):
        code = """
        password = "testpass123"
        """
        findings = check_code(HardcodedCredentialRule(), code, filename="test_auth.py")
        l014 = [f for f in findings if f["rule_id"] == "SKY-L014"]
        assert len(l014) == 0


class TestErrorDisclosure:
    def test_return_str_e(self):
        code = """
        try:
            do_something()
        except Exception as e:
            return str(e)
        """
        findings = check_code(ErrorDisclosureRule(), code)
        assert any(f["rule_id"] == "SKY-L017" for f in findings)

    def test_return_repr_e(self):
        code = """
        try:
            do_something()
        except Exception as e:
            return repr(e)
        """
        findings = check_code(ErrorDisclosureRule(), code)
        assert any(f["rule_id"] == "SKY-L017" for f in findings)

    def test_return_dict_with_str_e(self):
        code = """
        try:
            do_something()
        except Exception as e:
            return {"error": str(e)}
        """
        findings = check_code(ErrorDisclosureRule(), code)
        assert any(f["rule_id"] == "SKY-L017" for f in findings)

    def test_jsonresponse_str_e(self):
        code = """
        try:
            do_something()
        except Exception as e:
            return JsonResponse({"error": str(e)})
        """
        findings = check_code(ErrorDisclosureRule(), code)
        assert any(f["rule_id"] == "SKY-L017" for f in findings)

    def test_fstring_with_exception(self):
        code = """
        try:
            do_something()
        except Exception as e:
            return f"Error: {e}"
        """
        findings = check_code(ErrorDisclosureRule(), code)
        assert any(f["rule_id"] == "SKY-L017" for f in findings)

    def test_traceback_format_exc(self):
        code = """
        import traceback
        try:
            do_something()
        except Exception as e:
            return traceback.format_exc()
        """
        findings = check_code(ErrorDisclosureRule(), code)
        assert any(f["rule_id"] == "SKY-L017" for f in findings)

    def test_logging_not_flagged(self):
        code = """
        try:
            do_something()
        except Exception as e:
            logger.error(str(e))
            return {"error": "Internal server error"}
        """
        findings = check_code(ErrorDisclosureRule(), code)
        l017 = [f for f in findings if f["rule_id"] == "SKY-L017"]
        assert len(l017) == 0

    def test_no_exception_var_not_flagged(self):
        code = """
        try:
            do_something()
        except Exception:
            return {"error": "Something went wrong"}
        """
        findings = check_code(ErrorDisclosureRule(), code)
        l017 = [f for f in findings if f["rule_id"] == "SKY-L017"]
        assert len(l017) == 0

    def test_test_file_not_flagged(self):
        code = """
        try:
            do_something()
        except Exception as e:
            return str(e)
        """
        findings = check_code(ErrorDisclosureRule(), code, filename="test_api.py")
        l017 = [f for f in findings if f["rule_id"] == "SKY-L017"]
        assert len(l017) == 0


class TestBroadFilePermissions:
    def test_chmod_777(self):
        code = """
        import os
        os.chmod("myfile.txt", 0o777)
        """
        findings = check_code(BroadFilePermissionsRule(), code)
        assert any(f["rule_id"] == "SKY-L020" for f in findings)

    def test_world_writable(self):
        code = """
        import os
        os.chmod("config.ini", 0o666)
        """
        findings = check_code(BroadFilePermissionsRule(), code)
        assert any(f["rule_id"] == "SKY-L020" for f in findings)

    def test_sensitive_file_broad_perms(self):
        code = """
        import os
        os.chmod("server.pem", 0o644)
        """
        findings = check_code(BroadFilePermissionsRule(), code)
        assert any(f["rule_id"] == "SKY-L020" for f in findings)

    def test_sensitive_key_file(self):
        code = """
        import os
        os.chmod("private.key", 0o640)
        """
        findings = check_code(BroadFilePermissionsRule(), code)
        assert any(f["rule_id"] == "SKY-L020" for f in findings)

    def test_env_file_broad(self):
        code = """
        import os
        os.chmod(".env", 0o755)
        """
        findings = check_code(BroadFilePermissionsRule(), code)
        assert any(f["rule_id"] == "SKY-L020" for f in findings)

    def test_safe_perms_not_flagged(self):
        code = """
        import os
        os.chmod("script.sh", 0o755)
        """
        findings = check_code(BroadFilePermissionsRule(), code)
        l020 = [f for f in findings if f["rule_id"] == "SKY-L020"]
        assert len(l020) == 0

    def test_sensitive_file_strict_perms_not_flagged(self):
        code = """
        import os
        os.chmod("server.pem", 0o600)
        """
        findings = check_code(BroadFilePermissionsRule(), code)
        l020 = [f for f in findings if f["rule_id"] == "SKY-L020"]
        assert len(l020) == 0

    def test_test_file_not_flagged(self):
        code = """
        import os
        os.chmod("myfile.txt", 0o777)
        """
        findings = check_code(
            BroadFilePermissionsRule(), code, filename="test_perms.py"
        )
        l020 = [f for f in findings if f["rule_id"] == "SKY-L020"]
        assert len(l020) == 0
