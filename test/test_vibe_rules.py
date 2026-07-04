import ast
import os
import shutil
import textwrap
import tempfile
import warnings
from pathlib import Path

import pytest

from skylos.rules.ai_defect import PhantomCallRule, PhantomDecoratorRule
from skylos.rules.quality.logic import (
    EmptyErrorHandlerRule,
    MissingResourceCleanupRule,
    DebugLeftoverRule,
    SecurityTodoRule,
    DisabledSecurityRule,
    UnfinishedGenerationRule,
    UndefinedConfigRule,
    StaleMockRule,
    InsecureRandomRule,
    HardcodedCredentialRule,
    ErrorDisclosureRule,
    BroadFilePermissionsRule,
    MissingNetworkTimeoutRule,
)
from skylos.rules.ai_defect.phantom_refs import scan_repo_phantom_security_references
from skylos.rules.quality.unused_deps import scan_unused_dependencies
from skylos.rules.vibe_dictionary import build_vibe_dictionary


def check_code(rule, code, filename="test.py"):
    tree = ast.parse(textwrap.dedent(code))
    findings = []
    context = {"filename": filename, "mod": "test_module"}
    for node in ast.walk(tree):
        res = rule.visit_node(node, context)
        if res:
            findings.extend(res)
    return findings


def scan_repo_code(files):
    tmpdir = tempfile.mkdtemp()
    try:
        root = Path(tmpdir)
        (root / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        for rel_path, content in files.items():
            target = root / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(content), encoding="utf-8")
        py_files = sorted(root.rglob("*.py"))
        return scan_repo_phantom_security_references(root, py_files)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestEmptyErrorHandlerFindings:
    @pytest.mark.parametrize(
        ("code", "expected_severity"),
        [
            pytest.param(
                """
                try:
                    x = 1
                except:
                    pass
                """,
                None,
                id="except-pass",
            ),
            pytest.param(
                """
                try:
                    x = 1
                except Exception:
                    pass
                """,
                None,
                id="except-exception-pass",
            ),
            pytest.param(
                """
                for i in range(10):
                    try:
                        x = 1
                    except:
                        continue
                """,
                None,
                id="except-continue",
            ),
            pytest.param(
                """
                def foo():
                    try:
                        x = 1
                    except Exception:
                        return
                """,
                "HIGH",
                id="except-return",
            ),
            pytest.param(
                """
                def foo():
                    try:
                        x = 1
                    except Exception:
                        return None
                """,
                "HIGH",
                id="except-return-none",
            ),
            pytest.param(
                """
                try:
                    x = 1
                except:
                    ...
                """,
                None,
                id="except-ellipsis",
            ),
            pytest.param(
                """
                try:
                    x = 1
                except:
                    "this is a comment-like string"
                """,
                None,
                id="comment-only-handler",
            ),
            pytest.param(
                """
                import contextlib
                with contextlib.suppress(Exception):
                    do_something()
                """,
                None,
                id="suppress-exception",
            ),
            pytest.param(
                """
                import contextlib
                with contextlib.suppress(BaseException):
                    do_something()
                """,
                None,
                id="suppress-base-exception",
            ),
            pytest.param(
                """
                def parse(raw):
                    try:
                        return parse_payload(raw)
                    except Exception:
                        return {}
                """,
                "HIGH",
                id="broad-except-empty-dict-return",
            ),
            pytest.param(
                """
                def parse(raw):
                    try:
                        return parse_payload(raw)
                    except Exception:
                        return ""
                """,
                "HIGH",
                id="broad-except-empty-string-return",
            ),
            pytest.param(
                """
                def parse(raw):
                    try:
                        return parse_payload(raw)
                    except Exception:
                        return dict()
                """,
                "HIGH",
                id="broad-except-dict-constructor-return",
            ),
        ],
    )
    def test_swallowing_handlers_are_flagged(self, code, expected_severity):
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert l007
        if expected_severity is not None:
            assert any(f["severity"] == expected_severity for f in l007)


class TestEmptyErrorHandlerSafeCases:
    @pytest.mark.parametrize(
        "code",
        [
            pytest.param(
                """
                try:
                    x = 1
                except Exception:
                    logger.error("failed")
                """,
                id="logging",
            ),
            pytest.param(
                """
                try:
                    x = 1
                except Exception:
                    raise
                """,
                id="reraise",
            ),
            pytest.param(
                """
                try:
                    x = 1
                except Exception as e:
                    print(e)
                    handle_error(e)
                """,
                id="actual-code",
            ),
            pytest.param(
                """
                try:
                    x = 1
                except KeyboardInterrupt:
                    pass
                """,
                id="keyboard-interrupt",
            ),
            pytest.param(
                """
                try:
                    x = 1
                except SystemExit:
                    pass
                """,
                id="system-exit",
            ),
            pytest.param(
                """
                import contextlib
                with contextlib.suppress(FileNotFoundError):
                    os.remove("tmp.txt")
                """,
                id="specific-suppress",
            ),
            pytest.param(
                """
                def parse(raw):
                    try:
                        return int(raw)
                    except ValueError:
                        return None
                """,
                id="narrow-return-none-fallback",
            ),
            pytest.param(
                """
                def parse_json(raw):
                    try:
                        return json.loads(raw)
                    except ValueError:
                        return {}
                """,
                id="narrow-return-empty-dict-fallback",
            ),
            pytest.param(
                """
                for raw in rows:
                    try:
                        values.append(int(raw))
                    except ValueError:
                        continue
                """,
                id="narrow-continue-fallback",
            ),
            pytest.param(
                """
                try:
                    import optional_plugin
                except ImportError:
                    pass
                """,
                id="narrow-pass-fallback",
            ),
        ],
    )
    def test_non_swallowing_handlers_are_not_flagged(self, code):
        findings = check_code(EmptyErrorHandlerRule(), code)
        l007 = [f for f in findings if f["rule_id"] == "SKY-L007"]
        assert len(l007) == 0


class TestEmptyErrorHandlerOutputShape:
    def test_output_shape_for_except_and_broad_suppress(self):
        rule = EmptyErrorHandlerRule()
        context = {"filename": "sample.py", "mod": "sample"}

        except_code = """
        try:
            x = 1
        except Exception:
            pass
        """
        suppress_code = """
        import contextlib
        with contextlib.suppress(Exception):
            x = 1
        """

        def collect(code):
            findings = []
            tree = ast.parse(textwrap.dedent(code))
            for node in ast.walk(tree):
                result = rule.visit_node(node, context)
                if result:
                    findings.extend(result)
            return findings

        assert collect(except_code) == [
            {
                "rule_id": "SKY-L007",
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "block",
                "name": "except",
                "simple_name": "except",
                "value": "trivial",
                "threshold": 0,
                "message": "Empty error handler silently swallows exceptions.",
                "file": "sample.py",
                "basename": "sample.py",
                "line": 4,
                "col": 0,
            }
        ]
        assert collect(suppress_code) == [
            {
                "rule_id": "SKY-L007",
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "block",
                "name": "suppress",
                "simple_name": "suppress",
                "value": "broad",
                "threshold": 0,
                "message": "contextlib.suppress(Exception) silently swallows all errors.",
                "file": "sample.py",
                "basename": "sample.py",
                "line": 3,
                "col": 0,
            }
        ]


class TestMissingResourceCleanupOpenCases:
    @pytest.mark.parametrize(
        ("code", "is_flagged"),
        [
            pytest.param(
                """
                def foo():
                    f = open("x.txt")
                    data = f.read()
                """,
                True,
                id="open-without-with",
            ),
            pytest.param(
                """
                def foo():
                    with open("x.txt") as f:
                        data = f.read()
                """,
                False,
                id="open-with-with",
            ),
            pytest.param(
                """
                def get_file():
                    f = open("x.txt")
                    return f
                """,
                False,
                id="return-open",
            ),
            pytest.param(
                """
                def gen_file():
                    f = open("x.txt")
                    yield f
                """,
                False,
                id="yield-open",
            ),
            pytest.param(
                """
                def foo():
                    try:
                        f = open("x.txt")
                        data = f.read()
                    finally:
                        f.close()
                """,
                False,
                id="close-in-finally",
            ),
            pytest.param(
                """
                f = open("config.txt")
                data = f.read()
                """,
                True,
                id="module-level-open",
            ),
            pytest.param(
                """
                def foo():
                    with open("a.txt") as a:
                        with open("b.txt") as b:
                            pass
                """,
                False,
                id="nested-open-with",
            ),
        ],
    )
    def test_open_cleanup_patterns(self, code, is_flagged):
        findings = check_code(MissingResourceCleanupRule(), code)
        l008 = [f for f in findings if f["rule_id"] == "SKY-L008"]
        if is_flagged:
            assert l008
        else:
            assert len(l008) == 0


class TestMissingResourceCleanupConnectionAndFlowCases:
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


class TestMissingResourceCleanupAdditionalResourceCases:
    @pytest.mark.parametrize(
        "code",
        [
            pytest.param(
                """
                import socket
                def foo():
                    s = socket.socket()
                    s.connect(("localhost", 80))
                """,
                id="socket",
            ),
            pytest.param(
                """
                import requests
                def foo():
                    s = requests.Session()
                    s.get("http://example.com")
                """,
                id="requests-session",
            ),
            pytest.param(
                """
                import psycopg2
                def foo():
                    conn = psycopg2.connect("dbname=test")
                    cur = conn.cursor()
                """,
                id="psycopg2",
            ),
            pytest.param(
                """
                import tempfile
                def foo():
                    f = tempfile.NamedTemporaryFile()
                    f.write(b"data")
                """,
                id="tempfile",
            ),
        ],
    )
    def test_resource_variants_without_with_are_flagged(self, code):
        findings = check_code(MissingResourceCleanupRule(), code)
        assert len(findings) >= 1
        assert any(f["rule_id"] == "SKY-L008" for f in findings)


class TestMissingResourceCleanupOutputShape:
    def test_output_shape_for_assignment_and_expression_resources(self):
        rule = MissingResourceCleanupRule()
        context = {"filename": "sample.py", "mod": "sample"}

        assign_code = """
        def load():
            f = open("x.txt")
            return 1
        """
        expr_code = """
        open("x.txt")
        """

        def collect(code):
            findings = []
            tree = ast.parse(textwrap.dedent(code))
            for node in ast.walk(tree):
                result = rule.visit_node(node, context)
                if result:
                    findings.extend(result)
            return findings

        assert collect(assign_code) == [
            {
                "rule_id": "SKY-L008",
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "resource",
                "name": "open",
                "simple_name": "open",
                "value": "no_cleanup",
                "threshold": 0,
                "message": "Resource 'open' opened without 'with' statement. Use a context manager to ensure cleanup.",
                "file": "sample.py",
                "basename": "sample.py",
                "line": 3,
                "col": 4,
            }
        ]
        assert collect(expr_code) == [
            {
                "rule_id": "SKY-L008",
                "kind": "logic",
                "severity": "MEDIUM",
                "type": "resource",
                "name": "open",
                "simple_name": "open",
                "value": "no_cleanup",
                "threshold": 0,
                "message": "Resource 'open' opened without 'with' statement. Use a context manager to ensure cleanup.",
                "file": "sample.py",
                "basename": "sample.py",
                "line": 2,
                "col": 0,
            }
        ]


class TestDebugLeftoverFindings:
    @pytest.mark.parametrize(
        ("code", "filename", "expected_severity"),
        [
            pytest.param('print("debug")', "test.py", None, id="print"),
            pytest.param("breakpoint()", "test.py", "HIGH", id="breakpoint"),
            pytest.param(
                """
                import pdb
                pdb.set_trace()
                """,
                "test.py",
                None,
                id="pdb",
            ),
            pytest.param(
                """
                from icecream import ic
                ic(some_var)
                """,
                "test.py",
                None,
                id="icecream",
            ),
            pytest.param(
                """
                import ipdb
                ipdb.set_trace()
                """,
                "test.py",
                None,
                id="ipdb",
            ),
            pytest.param("breakpoint()", "cli.py", None, id="cli-breakpoint"),
            pytest.param(
                """
                from pprint import pprint
                pprint(data)
                """,
                "test.py",
                None,
                id="pprint",
            ),
        ],
    )
    def test_debug_leftovers_are_flagged(self, code, filename, expected_severity):
        findings = check_code(DebugLeftoverRule(), code, filename=filename)
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert l009
        if expected_severity is not None:
            assert any(f["severity"] == expected_severity for f in l009)


class TestDebugLeftoverSafeCases:
    @pytest.mark.parametrize(
        ("code", "filename"),
        [
            pytest.param('print("Hello user")', "cli.py", id="cli"),
            pytest.param('print("test output")', "test_something.py", id="test-file"),
            pytest.param('print("main output")', "__main__.py", id="dunder-main"),
            pytest.param(
                'print("running script")', "scripts/deploy.py", id="scripts-dir"
            ),
        ],
    )
    def test_allowed_prints_are_not_flagged(self, code, filename):
        findings = check_code(DebugLeftoverRule(), code, filename=filename)
        l009 = [f for f in findings if f["rule_id"] == "SKY-L009"]
        assert len(l009) == 0


class TestDebugLeftoverAdditionalFindings:
    def test_debug_leftover_regression_coverage(self):
        findings = check_code(DebugLeftoverRule(), "breakpoint()", filename="cli.py")
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
    @pytest.mark.parametrize(
        ("code", "is_flagged"),
        [
            pytest.param(
                """
                # TODO: add authentication check here
                def get_users():
                    return db.query("SELECT * FROM users")
                """,
                True,
                id="todo-auth",
            ),
            pytest.param(
                """
                def search(q):
                    # FIXME: sanitize and validate input
                    return db.execute(f"SELECT * FROM items WHERE name = '{q}'")
                """,
                True,
                id="fixme-validate",
            ),
            pytest.param(
                """
                import requests
                # HACK: disable ssl verify for now
                requests.get("https://api.example.com", verify=False)
                """,
                True,
                id="hack-disable-ssl",
            ),
            pytest.param(
                """
                # TODO: stop hardcoding password
                PASSWORD = "admin123"
                """,
                True,
                id="todo-password",
            ),
            pytest.param(
                """
                # TEMP: bypass auth security check
                def api_call():
                    pass
                """,
                True,
                id="temp-bypass",
            ),
            pytest.param(
                """
                for i in range(10):
                    pass
                """,
                False,
                id="ordinary-loop",
            ),
            pytest.param(
                """
                x = 1
                """,
                False,
                id="plain-assignment",
            ),
        ],
    )
    def test_security_todo_detection(self, code, is_flagged):
        findings = check_code_with_source(SecurityTodoRule(), code)
        l010 = [f for f in findings if f["rule_id"] == "SKY-L010"]
        if is_flagged:
            assert l010
        else:
            assert len(l010) == 0


class TestDisabledSecurity:
    @pytest.mark.parametrize(
        ("code", "filename", "is_flagged"),
        [
            pytest.param(
                """
                import requests
                requests.get("https://api.example.com", verify=False)
                """,
                "test.py",
                True,
                id="verify-false",
            ),
            pytest.param(
                """
                import requests
                requests.get("https://api.example.com", verify=True)
                """,
                "test.py",
                False,
                id="verify-true",
            ),
            pytest.param(
                """
                import ssl
                ctx = ssl._create_unverified_context()
                """,
                "test.py",
                True,
                id="unverified-context",
            ),
            pytest.param(
                """
                from django.views.decorators.csrf import csrf_exempt

                @csrf_exempt
                def my_view(request):
                    pass
                """,
                "test.py",
                True,
                id="csrf-exempt",
            ),
            pytest.param(
                """
                DEBUG = True
                """,
                "test.py",
                True,
                id="debug-true",
            ),
            pytest.param(
                """
                DEBUG = False
                """,
                "test.py",
                False,
                id="debug-false",
            ),
            pytest.param(
                """
                ALLOWED_HOSTS = ["*"]
                """,
                "test.py",
                True,
                id="allowed-hosts-wildcard",
            ),
            pytest.param(
                """
                ALLOWED_HOSTS = ["example.com", "www.example.com"]
                """,
                "test.py",
                False,
                id="allowed-hosts-specific",
            ),
            pytest.param(
                """
                some_func(check_hostname=False)
                """,
                "test.py",
                True,
                id="check-hostname-false",
            ),
            pytest.param(
                """
                import requests
                requests.get("https://api.example.com", verify=False)
                """,
                "test_api.py",
                False,
                id="test-file",
            ),
        ],
    )
    def test_disabled_security_detection(self, code, filename, is_flagged):
        findings = check_code(DisabledSecurityRule(), code, filename=filename)
        l011 = [f for f in findings if f["rule_id"] == "SKY-L011"]
        if is_flagged:
            assert l011
        else:
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

    def test_custom_vibe_dictionary_phantom_name(self):
        vibe = build_vibe_dictionary(
            {"extra_phantom_names": ["verify_enterprise_auth"]}
        )
        code = """
        def check_request(request):
            verify_enterprise_auth(request)
        """
        findings = check_code(PhantomCallRule(vibe_dictionary=vibe), code)
        assert any(f["rule_id"] == "SKY-L012" for f in findings)

    def test_escape_html_phantom(self):
        code = """
        def render(text):
            return escape_html(text)
        """
        findings = check_code(PhantomCallRule(), code)
        assert any(f["rule_id"] == "SKY-L012" for f in findings)
        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert l012[0]["vibe_category"] == "hallucinated_reference"
        assert l012[0]["ai_likelihood"] == "high"

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

    def test_repo_local_module_attribute_call_phantom(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(request):
                        return request
                """,
                "app/views.py": """
                    from app import security

                    def handler(request):
                        return security.require_auth(request)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 1
        assert l012[0]["name"] == "security.require_auth"
        assert l012[0]["simple_name"] == "require_auth"

    def test_repo_local_module_attribute_call_phantom_for_stale_helper(self):
        findings = scan_repo_code(
            {
                "billing/__init__.py": "",
                "billing/totals.py": """
                    def calculate_total(items):
                        return sum(items)
                """,
                "billing/workflow.py": """
                    from billing import totals

                    def create_invoice(items):
                        return totals.compute_total(items)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 1
        assert l012[0]["name"] == "totals.compute_total"
        assert l012[0]["simple_name"] == "compute_total"

    def test_repo_dynamic_module_not_flagged(self):
        findings = scan_repo_code(
            {
                "guards/__init__.py": """
                    def __getattr__(name):
                        return lambda *args, **kwargs: None
                """,
                "app.py": """
                    import guards

                    def handler(request):
                        return guards.require_auth(request)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_repo_function_local_import_is_detected(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(request):
                        return request
                """,
                "app/views.py": """
                    def handler(request):
                        from app import security
                        return security.require_auth(request)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 1
        assert l012[0]["name"] == "security.require_auth"

    def test_repo_root_package_import_chain_is_detected(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(request):
                        return request
                """,
                "app/views.py": """
                    import app.security

                    def handler(request):
                        return app.security.require_auth(request)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 1
        assert l012[0]["name"] == "app.security.require_auth"

    def test_repo_shadowed_import_name_not_flagged(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(request):
                        return request
                """,
                "app/views.py": """
                    from app import security

                    def handler(security):
                        return security.require_auth(request=None)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_repo_imported_module_with_parse_error_not_flagged(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def broken(
                """,
                "app/views.py": """
                    from app import security

                    def handler(request):
                        return security.require_auth(request)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_repo_symlinked_external_python_file_not_scanned(self):
        tmpdir = tempfile.mkdtemp()
        external_dir = tempfile.mkdtemp()
        try:
            root = Path(tmpdir)
            external = Path(external_dir) / "security.py"
            external.write_text(
                textwrap.dedent(
                    """
                    def broken(
                    """
                ),
                encoding="utf-8",
            )
            (root / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
            app = root / "app"
            app.mkdir()
            (app / "__init__.py").write_text("", encoding="utf-8")
            os.symlink(external, app / "security.py")
            (app / "views.py").write_text(
                textwrap.dedent(
                    """
                    from app import security

                    def handler(request):
                        return security.require_auth(request)
                    """
                ),
                encoding="utf-8",
            )

            py_files = sorted(root.rglob("*.py"))
            findings = scan_repo_phantom_security_references(root, py_files)
            l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
            assert len(l012) == 0
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
            shutil.rmtree(external_dir, ignore_errors=True)

    def test_repo_class_body_shadowed_alias_not_flagged(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(request):
                        return request
                """,
                "app/views.py": """
                    from app import security

                    class WrappedView:
                        security = object()

                        @security.require_auth
                        def get(self):
                            return "ok"
                """,
            }
        )

        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0

    def test_repo_class_body_import_is_detected(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(fn):
                        return fn
                """,
                "app/views.py": """
                    class WrappedView:
                        from app import security

                        @security.require_auth
                        def get(self):
                            return "ok"
                """,
            }
        )

        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 1
        assert l023[0]["name"] == "security.require_auth"

    def test_repo_class_body_import_does_not_leak_into_method_body(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(request):
                        return request
                """,
                "app/views.py": """
                    class WrappedView:
                        from app import security

                        def get(self, request):
                            return security.require_auth(request)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 0

    def test_repo_class_body_shadow_does_not_hide_module_call_in_method_body(self):
        findings = scan_repo_code(
            {
                "app/__init__.py": "",
                "app/security.py": """
                    def authenticate(request):
                        return request
                """,
                "app/views.py": """
                    from app import security

                    class WrappedView:
                        security = object()

                        def get(self, request):
                            return security.require_auth(request)
                """,
            }
        )

        l012 = [f for f in findings if f["rule_id"] == "SKY-L012"]
        assert len(l012) == 1
        assert l012[0]["name"] == "security.require_auth"


class TestInsecureRandom:
    @pytest.mark.parametrize(
        ("code", "filename", "is_flagged"),
        [
            pytest.param(
                """
                import random
                token = random.randint(100000, 999999)
                """,
                "test.py",
                True,
                id="token-randint",
            ),
            pytest.param(
                """
                import random
                password = random.choice("abcdefghij")
                """,
                "test.py",
                True,
                id="password-choice",
            ),
            pytest.param(
                """
                import random
                session_id = random.randbytes(16)
                """,
                "test.py",
                True,
                id="session-randbytes",
            ),
            pytest.param(
                """
                import random
                csrf_token = random.randrange(0, 2**128)
                """,
                "test.py",
                True,
                id="csrf-randrange",
            ),
            pytest.param(
                """
                import random
                color = random.choice(["red", "blue", "green"])
                """,
                "test.py",
                False,
                id="non-security-random",
            ),
            pytest.param(
                """
                import secrets
                token = secrets.token_urlsafe(32)
                """,
                "test.py",
                False,
                id="secrets-module",
            ),
            pytest.param(
                """
                import random
                token = random.randint(0, 9999)
                """,
                "test_auth.py",
                False,
                id="test-file",
            ),
            pytest.param(
                """
                import random
                self.api_key = random.randint(0, 999999)
                """,
                "test.py",
                True,
                id="attribute-target",
            ),
        ],
    )
    def test_insecure_random_detection(self, code, filename, is_flagged):
        findings = check_code(InsecureRandomRule(), code, filename=filename)
        l013 = [f for f in findings if f["rule_id"] == "SKY-L013"]
        if is_flagged:
            assert l013
        else:
            assert len(l013) == 0


class TestHardcodedCredential:
    @pytest.mark.parametrize(
        ("code", "filename", "is_flagged", "expected_severity"),
        [
            pytest.param(
                """
                password = "admin123"
                """,
                "test.py",
                True,
                None,
                id="password-assignment",
            ),
            pytest.param(
                """
                api_key = "sk-1234567890abcdef"
                """,
                "test.py",
                True,
                None,
                id="api-key",
            ),
            pytest.param(
                """
                db_password = "mysecretpass"
                """,
                "test.py",
                True,
                None,
                id="db-password",
            ),
            pytest.param(
                """
                database_url = "postgresql://admin:secretpass@localhost:5432/mydb"
                """,
                "test.py",
                True,
                None,
                id="dsn-with-credentials",
            ),
            pytest.param(
                """
                password = "changeme"
                """,
                "test.py",
                True,
                "MEDIUM",
                id="placeholder-downgraded",
            ),
            pytest.param(
                """
                import os
                password = os.getenv("DB_PASSWORD")
                """,
                "test.py",
                False,
                None,
                id="env-lookup",
            ),
            pytest.param(
                """
                password = ""
                """,
                "test.py",
                False,
                None,
                id="empty-string",
            ),
            pytest.param(
                """
                def connect(password="admin123"):
                    pass
                """,
                "test.py",
                True,
                None,
                id="function-default",
            ),
            pytest.param(
                """
                username = "admin"
                """,
                "test.py",
                False,
                None,
                id="non-credential-var",
            ),
            pytest.param(
                """
                my_app_password = "hunter2"
                """,
                "test.py",
                True,
                None,
                id="suffix-match",
            ),
            pytest.param(
                """
                password = "testpass123"
                """,
                "test_auth.py",
                False,
                None,
                id="test-file",
            ),
        ],
    )
    def test_hardcoded_credential_detection(
        self, code, filename, is_flagged, expected_severity
    ):
        findings = check_code(HardcodedCredentialRule(), code, filename=filename)
        l014 = [f for f in findings if f["rule_id"] == "SKY-L014"]
        if is_flagged:
            assert l014
            if expected_severity is not None:
                assert l014[0]["severity"] == expected_severity
        else:
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


class TestMissingNetworkTimeout:
    def test_requests_call_without_timeout_flagged(self):
        code = """
        import requests
        def fetch():
            return requests.get("https://api.example.com/data")
        """
        findings = check_code(MissingNetworkTimeoutRule(), code, filename="app.py")
        l031 = [f for f in findings if f["rule_id"] == "SKY-L031"]
        assert l031
        assert l031[0]["name"] == "requests.get"

    def test_httpx_call_without_timeout_flagged(self):
        code = """
        import httpx
        def send(payload):
            return httpx.post("https://api.example.com/data", json=payload)
        """
        findings = check_code(MissingNetworkTimeoutRule(), code, filename="app.py")
        assert any(f["rule_id"] == "SKY-L031" for f in findings)

    def test_urlopen_without_timeout_flagged(self):
        code = """
        from urllib.request import urlopen
        def fetch(url):
            return urlopen(url)
        """
        findings = check_code(MissingNetworkTimeoutRule(), code, filename="app.py")
        assert any(f["rule_id"] == "SKY-L031" for f in findings)

    def test_timeout_keyword_not_flagged(self):
        code = """
        import requests
        def fetch():
            return requests.get("https://api.example.com/data", timeout=5)
        """
        findings = check_code(MissingNetworkTimeoutRule(), code, filename="app.py")
        l031 = [f for f in findings if f["rule_id"] == "SKY-L031"]
        assert len(l031) == 0

    def test_timeout_none_is_flagged(self):
        code = """
        import requests
        def fetch():
            return requests.get("https://api.example.com/data", timeout=None)
        """
        findings = check_code(MissingNetworkTimeoutRule(), code, filename="app.py")
        l031 = [f for f in findings if f["rule_id"] == "SKY-L031"]
        assert l031
        assert l031[0]["value"] == "timeout_none"

    def test_test_file_not_flagged(self):
        code = """
        import requests
        requests.get("https://api.example.com/data")
        """
        findings = check_code(
            MissingNetworkTimeoutRule(), code, filename="test_http.py"
        )
        l031 = [f for f in findings if f["rule_id"] == "SKY-L031"]
        assert len(l031) == 0


class TestPhantomDecorator:
    def test_phantom_require_auth(self):
        code = """
        @require_auth
        def secret_endpoint():
            return "secret"
        """
        findings = check_code(PhantomDecoratorRule(), code)
        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert l023
        assert l023[0]["category"] == "ai_defect"
        assert l023[0]["defect_type"] == "hallucinated_reference"

    def test_phantom_rate_limit_with_args(self):
        code = """
        @rate_limit(100)
        def api_handler():
            return "ok"
        """
        findings = check_code(PhantomDecoratorRule(), code)
        assert any(f["rule_id"] == "SKY-L023" for f in findings)

    def test_phantom_on_class(self):
        code = """
        @authenticate
        class AdminView:
            pass
        """
        findings = check_code(PhantomDecoratorRule(), code)
        assert any(f["rule_id"] == "SKY-L023" for f in findings)

    def test_defined_locally_not_flagged(self):
        code = """
        def require_auth(fn):
            return fn

        @require_auth
        def secret():
            return "secret"
        """
        findings = check_code(PhantomDecoratorRule(), code)
        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0

    def test_imported_not_flagged(self):
        code = """
        from flask_login import login_required as require_auth

        @require_auth
        def secret():
            return "secret"
        """
        findings = check_code(PhantomDecoratorRule(), code)
        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0

    def test_method_decorator_not_flagged(self):
        code = """
        @app.require_auth
        def secret():
            return "secret"
        """
        findings = check_code(PhantomDecoratorRule(), code)
        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0

    def test_non_security_decorator_not_flagged(self):
        code = """
        @my_custom_decorator
        def handler():
            pass
        """
        findings = check_code(PhantomDecoratorRule(), code)
        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0

    def test_multiple_phantom_decorators(self):
        code = """
        @require_auth
        @rate_limit(50)
        def admin_endpoint():
            return "admin"
        """
        findings = check_code(PhantomDecoratorRule(), code)
        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 2

    def test_repo_local_module_decorator_phantom(self):
        findings = scan_repo_code(
            {
                "pkg/__init__.py": "",
                "pkg/guards.py": """
                    def authenticate(fn):
                        return fn
                """,
                "pkg/views.py": """
                    from . import guards as auth

                    @auth.require_auth
                    def secret():
                        return "secret"
                """,
            }
        )

        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 1
        assert l023[0]["name"] == "auth.require_auth"
        assert l023[0]["simple_name"] == "require_auth"

    def test_repo_reexported_package_member_not_flagged(self):
        findings = scan_repo_code(
            {
                "pkg/__init__.py": """
                    from .guards import require_auth
                """,
                "pkg/guards.py": """
                    def require_auth(fn):
                        return fn
                """,
                "pkg/views.py": """
                    import pkg

                    @pkg.require_auth
                    def secret():
                        return "secret"
                """,
            }
        )

        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0

    def test_repo_module_alias_reexport_resolves(self):
        findings = scan_repo_code(
            {
                "pkg/__init__.py": """
                    from . import guards as security
                """,
                "pkg/guards.py": """
                    def authenticate(fn):
                        return fn
                """,
                "pkg/views.py": """
                    import pkg

                    @pkg.security.require_auth
                    def secret():
                        return "secret"
                """,
            }
        )

        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 1
        assert l023[0]["name"] == "pkg.security.require_auth"

    def test_repo_star_reexport_not_flagged(self):
        findings = scan_repo_code(
            {
                "pkg/__init__.py": """
                    from .guards import *
                """,
                "pkg/guards.py": """
                    def require_auth(fn):
                        return fn
                """,
                "pkg/views.py": """
                    import pkg

                    @pkg.require_auth
                    def secret():
                        return "secret"
                """,
            }
        )

        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0

    def test_third_party_module_attribute_not_flagged(self):
        findings = scan_repo_code(
            {
                "app.py": """
                    import flask_login

                    @flask_login.require_auth
                    def secret():
                        return "secret"
                """
            }
        )

        l023 = [f for f in findings if f["rule_id"] == "SKY-L023"]
        assert len(l023) == 0


class TestUnfinishedGeneration:
    def test_pass_body(self):
        code = """
        def process_payment(amount):
            pass
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        assert any(f["rule_id"] == "SKY-L026" for f in findings)
        assert any(f["value"] == "pass" for f in findings if f["rule_id"] == "SKY-L026")

    def test_ellipsis_body(self):
        code = """
        def validate_user(token):
            ...
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        assert any(f["rule_id"] == "SKY-L026" for f in findings)

    def test_not_implemented_error(self):
        code = """
        def send_notification(user, message):
            raise NotImplementedError
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        assert any(f["rule_id"] == "SKY-L026" for f in findings)

    def test_not_implemented_error_call(self):
        code = """
        def send_notification(user, message):
            raise NotImplementedError("not done yet")
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        assert any(f["rule_id"] == "SKY-L026" for f in findings)

    def test_docstring_then_pass(self):
        code = """
        def verify_payment(order):
            \"\"\"Verify payment for the given order.\"\"\"
            pass
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        assert any(f["rule_id"] == "SKY-L026" for f in findings)

    def test_docstring_then_ellipsis_no_deprecation_warning(self):
        code = """
        def validate_user(token):
            \"\"\"Validate the given token.\"\"\"
            ...
        """
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            findings = check_code(UnfinishedGenerationRule(), code)

        assert any(f["rule_id"] == "SKY-L026" for f in findings)
        assert [
            str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)
        ] == []

    def test_real_implementation_not_flagged(self):
        code = """
        def add(a, b):
            return a + b
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0

    def test_abstract_method_not_flagged(self):
        code = """
        from abc import abstractmethod

        class Base:
            @abstractmethod
            def process(self):
                pass
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0

    def test_test_file_not_flagged(self):
        code = """
        def test_placeholder():
            pass
        """
        findings = check_code(
            UnfinishedGenerationRule(), code, filename="test_something.py"
        )
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0

    def test_init_file_not_flagged(self):
        code = """
        def setup():
            pass
        """
        findings = check_code(UnfinishedGenerationRule(), code, filename="__init__.py")
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0

    def test_dunder_method_not_flagged(self):
        code = """
        class MyClass:
            def __repr__(self):
                pass
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0

    def test_async_function_flagged(self):
        code = """
        async def fetch_data(url):
            pass
        """
        findings = check_code(UnfinishedGenerationRule(), code)
        assert any(f["rule_id"] == "SKY-L026" for f in findings)

    @pytest.mark.parametrize(
        ("body", "marker"),
        [
            ("return None", "return None"),
            ("return ''", 'return ""'),
            ("return []", "return list"),
            ("return {}", "return dict"),
            ("return dict()", "return dict"),
            ("return list()", "return list"),
        ],
    )
    def test_placeholder_return_body_flagged(self, body, marker):
        code = f"""
        def build_invoice_payload(order):
            {body}
        """
        findings = check_code(UnfinishedGenerationRule(), code, filename="app.py")
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert l026
        assert any(f["value"] == marker for f in l026)

    def test_empty_collection_fastapi_get_with_response_contract_not_flagged(self):
        code = """
        from fastapi import APIRouter

        router = APIRouter()

        @router.get("/users", response_model=list[str])
        def list_users() -> list[str]:
            return []
        """
        findings = check_code(UnfinishedGenerationRule(), code, filename="app.py")
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0

    def test_real_logic_with_none_fallback_not_flagged(self):
        code = """
        def find_user(users, target):
            for user in users:
                if user.id == target:
                    return user
            return None
        """
        findings = check_code(UnfinishedGenerationRule(), code, filename="app.py")
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0

    def test_placeholder_return_test_file_not_flagged(self):
        code = """
        def helper():
            return None
        """
        findings = check_code(
            UnfinishedGenerationRule(), code, filename="test_helpers.py"
        )
        l026 = [f for f in findings if f["rule_id"] == "SKY-L026"]
        assert len(l026) == 0


class TestUndefinedConfig:
    def test_getenv_feature_flag(self):
        code = """
        import os
        if os.getenv("ENABLE_RATE_LIMIT"):
            apply_rate_limit()
        """
        findings = check_code(UndefinedConfigRule(), code)
        assert any(f["rule_id"] == "SKY-L016" for f in findings)

    def test_environ_get_feature_flag(self):
        code = """
        import os
        if os.environ.get("FEATURE_NEW_UI"):
            show_new_ui()
        """
        findings = check_code(UndefinedConfigRule(), code)
        assert any(f["rule_id"] == "SKY-L016" for f in findings)

    def test_use_prefix_flag(self):
        code = """
        import os
        use_cache = os.getenv("USE_REDIS_CACHE")
        """
        findings = check_code(UndefinedConfigRule(), code)
        assert any(f["rule_id"] == "SKY-L016" for f in findings)

    def test_well_known_env_not_flagged(self):
        code = """
        import os
        db = os.getenv("DATABASE_URL")
        """
        findings = check_code(UndefinedConfigRule(), code)
        l016 = [f for f in findings if f["rule_id"] == "SKY-L016"]
        assert len(l016) == 0

    def test_non_flag_env_not_flagged(self):
        code = """
        import os
        api_url = os.getenv("API_BASE_URL")
        """
        findings = check_code(UndefinedConfigRule(), code)
        l016 = [f for f in findings if f["rule_id"] == "SKY-L016"]
        assert len(l016) == 0

    def test_env_set_in_same_file_not_flagged(self):
        code = """
        import os
        os.environ["ENABLE_CACHE"] = "1"
        if os.getenv("ENABLE_CACHE"):
            use_cache()
        """
        findings = check_code(UndefinedConfigRule(), code)
        l016 = [f for f in findings if f["rule_id"] == "SKY-L016"]
        assert len(l016) == 0


def _check_stale_mock(test_code, module_path, module_code):
    import shutil

    tmpdir = tempfile.mkdtemp()
    try:
        (Path(tmpdir) / "pyproject.toml").write_text("[tool.skylos]\n")

        parts = module_path.split(".")
        if len(parts) > 1:
            mod_dir = Path(tmpdir) / "/".join(parts[:-1])
            mod_dir.mkdir(parents=True, exist_ok=True)
            mod_file = mod_dir / (parts[-1] + ".py")
        else:
            mod_file = Path(tmpdir) / (parts[0] + ".py")
        mod_file.write_text(textwrap.dedent(module_code))

        test_file = Path(tmpdir) / "test_x.py"
        dedented = textwrap.dedent(test_code)
        test_file.write_text(dedented)

        tree = ast.parse(dedented)
        rule = StaleMockRule()
        findings = []
        context = {"filename": str(test_file), "mod": "test_x"}
        for nd in ast.walk(tree):
            res = rule.visit_node(nd, context)
            if res:
                findings.extend(res)
        return findings
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


class TestStaleMock:
    def test_stale_mock_renamed_function(self):
        findings = _check_stale_mock(
            test_code="""
            from unittest.mock import patch

            @patch("app.email.send_email")
            def test_notify(mock_send):
                pass
            """,
            module_path="app.email",
            module_code="""
            def notify_user(user, message):
                pass
            """,
        )
        l024 = [f for f in findings if f["rule_id"] == "SKY-L024"]
        assert len(l024) == 1
        assert "send_email" in l024[0]["message"]
        assert l024[0]["vibe_category"] == "stale_reference"

    def test_valid_mock_not_flagged(self):
        findings = _check_stale_mock(
            test_code="""
            from unittest.mock import patch

            @patch("app.email.send_email")
            def test_send(mock_send):
                pass
            """,
            module_path="app.email",
            module_code="""
            def send_email(to, subject, body):
                pass
            """,
        )
        l024 = [f for f in findings if f["rule_id"] == "SKY-L024"]
        assert len(l024) == 0

    def test_stale_mock_inline_patch(self):
        findings = _check_stale_mock(
            test_code="""
            from unittest.mock import patch

            def test_something():
                with patch("app.email.send_notification"):
                    pass
            """,
            module_path="app.email",
            module_code="""
            def send_email(to, body):
                pass
            """,
        )
        l024 = [f for f in findings if f["rule_id"] == "SKY-L024"]
        assert len(l024) == 1

    def test_mock_targets_imported_name(self):
        findings = _check_stale_mock(
            test_code="""
            from unittest.mock import patch

            @patch("app.email.smtplib")
            def test_smtp(mock_smtp):
                pass
            """,
            module_path="app.email",
            module_code="""
            import smtplib

            def send_email():
                smtplib.SMTP("localhost")
            """,
        )
        l024 = [f for f in findings if f["rule_id"] == "SKY-L024"]
        assert len(l024) == 0

    def test_non_test_file_not_scanned(self):
        findings = check_code(
            StaleMockRule(),
            """
        from unittest.mock import patch
        patch("app.nonexistent.function")
        """,
            filename="app.py",
        )
        l024 = [f for f in findings if f["rule_id"] == "SKY-L024"]
        assert len(l024) == 0

    def test_mock_targets_class(self):
        findings = _check_stale_mock(
            test_code="""
            from unittest.mock import patch

            @patch("app.email.EmailClient")
            def test_client(mock_cls):
                pass
            """,
            module_path="app.email",
            module_code="""
            class EmailClient:
                pass
            """,
        )
        l024 = [f for f in findings if f["rule_id"] == "SKY-L024"]
        assert len(l024) == 0

    def test_mock_targets_variable(self):
        findings = _check_stale_mock(
            test_code="""
            from unittest.mock import patch

            @patch("app.config.DEFAULT_TIMEOUT")
            def test_timeout(mock_val):
                pass
            """,
            module_path="app.config",
            module_code="""
            DEFAULT_TIMEOUT = 30
            """,
        )
        l024 = [f for f in findings if f["rule_id"] == "SKY-L024"]
        assert len(l024) == 0
