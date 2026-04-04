import textwrap

from skylos_mcp.server import _validate_code_change_impl, _get_security_context_impl


def _make_diff(filename, removed_lines=None, added_lines=None, hunk_start=1):
    removed_lines = removed_lines or []
    added_lines = added_lines or []
    old_count = len(removed_lines) + 1
    new_count = len(added_lines) + 1
    lines = [
        f"--- a/{filename}",
        f"+++ b/{filename}",
        f"@@ -{hunk_start},{old_count} +{hunk_start},{new_count} @@",
        " # context line",
    ]
    for r in removed_lines:
        lines.append(f"-{r}")
    for a in added_lines:
        lines.append(f"+{a}")
    return "\n".join(lines)


class TestValidateCodeChangeRegressions:
    def test_regression_removing_login_required(self):
        diff = _make_diff(
            "views.py",
            removed_lines=["@login_required"],
            added_lines=[],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        findings = result["findings"]
        assert any(
            "login_required" in f.get("message", "").lower()
            or "auth" in f.get("message", "").lower()
            or f.get("kind") == "regression"
            for f in findings
        )


class TestValidateCodeChangeDangerousPatterns:
    def test_eval_in_added_code(self):
        diff = _make_diff(
            "handler.py",
            added_lines=["    result = eval(user_input)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D201" for f in result["findings"])

    def test_exec_in_added_code(self):
        diff = _make_diff(
            "handler.py",
            added_lines=["    exec(code_string)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D202" for f in result["findings"])

    def test_os_system_in_added_code(self):
        diff = _make_diff(
            "deploy.py",
            added_lines=["    os.system(cmd)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D203" for f in result["findings"])
        assert any(f["severity"] == "CRITICAL" for f in result["findings"])

    def test_pickle_loads_in_added_code(self):
        diff = _make_diff(
            "cache.py",
            added_lines=["    obj = pickle.loads(data)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D205" for f in result["findings"])
        assert any(f["severity"] == "CRITICAL" for f in result["findings"])

    def test_pickle_load_in_added_code(self):
        diff = _make_diff(
            "cache.py",
            added_lines=["    obj = pickle.load(fp)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D204" for f in result["findings"])

    def test_yaml_load_in_added_code(self):
        diff = _make_diff(
            "config.py",
            added_lines=["    data = yaml.load(raw)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D206" for f in result["findings"])

    def test_marshal_loads_in_added_code(self):
        diff = _make_diff(
            "codec.py",
            added_lines=["    obj = marshal.loads(payload)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D233" for f in result["findings"])

    def test_dunder_import_in_added_code(self):
        diff = _make_diff(
            "plugin.py",
            added_lines=["    mod = __import__(name)"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D240" for f in result["findings"])

    def test_compile_in_added_code(self):
        diff = _make_diff(
            "dsl.py",
            added_lines=["    code = compile(src, '<string>', 'exec')"],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D241" for f in result["findings"])


class TestValidateCodeChangeSecrets:
    def test_github_token_in_added_code(self):
        fake_token = "ghp_" + "A" * 36
        diff = _make_diff(
            "config.py",
            added_lines=[f'    GITHUB_TOKEN = "{fake_token}"'],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        secret_findings = [f for f in result["findings"] if f["kind"] == "secret"]
        assert len(secret_findings) >= 1
        assert any("SKY-S101" == f["rule_id"] for f in secret_findings)

    def test_aws_key_in_added_code(self):
        fake_key = "AKIA" + "B" * 16
        diff = _make_diff(
            "settings.py",
            added_lines=[f'    AWS_ACCESS_KEY_ID = "{fake_key}"'],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        secret_findings = [f for f in result["findings"] if f["kind"] == "secret"]
        assert len(secret_findings) >= 1


class TestValidateCodeChangeSQLInjection:
    def test_fstring_execute(self):
        diff = _make_diff(
            "db.py",
            added_lines=['    cursor.execute(f"SELECT * FROM {table}")'],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D220" for f in result["findings"])

    def test_format_execute(self):
        diff = _make_diff(
            "db.py",
            added_lines=['    cursor.execute("SELECT * FROM {}".format(table))'],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D220" for f in result["findings"])

    def test_percent_execute(self):
        diff = _make_diff(
            "db.py",
            added_lines=['    cursor.execute("SELECT * FROM %s" % table)'],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "fail"
        assert any(f["rule_id"] == "SKY-D220" for f in result["findings"])


class TestValidateCodeChangeCleanDiff:
    def test_clean_diff_passes(self):
        diff = _make_diff(
            "utils.py",
            added_lines=[
                "    x = 1 + 2",
                "    return x",
            ],
        )
        result = _validate_code_change_impl(diff)
        assert result["status"] == "pass"
        assert result["findings"] == []
        assert result["summary"] == "No issues found"


class TestValidateCodeChangeMultipleFiles:
    def test_multiple_files_in_diff(self):
        diff1 = _make_diff(
            "handler.py",
            added_lines=["    result = eval(user_input)"],
        )
        diff2 = _make_diff(
            "cache.py",
            added_lines=["    obj = pickle.loads(data)"],
        )
        combined_diff = diff1 + "\n" + diff2
        result = _validate_code_change_impl(combined_diff)
        assert result["status"] == "fail"
        files_with_findings = {f["file"] for f in result["findings"]}
        assert "handler.py" in files_with_findings
        assert "cache.py" in files_with_findings


class TestValidateCodeChangeLineNumbers:
    def test_line_numbers_tracked(self):
        diff = textwrap.dedent("""\
            --- a/app.py
            +++ b/app.py
            @@ -10,3 +10,5 @@
             # existing code
             x = 1
            +    result = eval(user_input)
            +    y = 2
        """).strip()
        result = _validate_code_change_impl(diff)
        eval_finding = [f for f in result["findings"] if f["rule_id"] == "SKY-D201"]
        assert len(eval_finding) == 1
        assert eval_finding[0]["line"] == 12
        assert eval_finding[0]["file"] == "app.py"


class TestValidateCodeChangeSummary:
    def test_summary_format_single_kind(self):
        diff = _make_diff(
            "handler.py",
            added_lines=["    eval(x)", "    exec(y)"],
        )
        result = _validate_code_change_impl(diff)
        assert "dangerous pattern" in result["summary"]
        assert "found" in result["summary"]

    def test_summary_format_multiple_kinds(self):
        fake_token = "ghp_" + "A" * 36
        diff = _make_diff(
            "handler.py",
            added_lines=["    eval(x)", f'    TOKEN = "{fake_token}"'],
        )
        result = _validate_code_change_impl(diff)
        assert "dangerous pattern" in result["summary"]
        assert "secret" in result["summary"]


class TestGetSecurityContextFrameworks:
    def test_detect_flask_framework(self, tmp_path):
        app_file = tmp_path / "app.py"
        app_file.write_text("from flask import Flask\napp = Flask(__name__)\n")
        result = _get_security_context_impl(str(tmp_path))
        assert "Flask" in result["frameworks"]

    def test_detect_django_framework(self, tmp_path):
        settings = tmp_path / "settings.py"
        settings.write_text("from django.conf import settings\nDEBUG = True\n")
        result = _get_security_context_impl(str(tmp_path))
        assert "Django" in result["frameworks"]

    def test_detect_fastapi_framework(self, tmp_path):
        main = tmp_path / "main.py"
        main.write_text("from fastapi import FastAPI\napp = FastAPI()\n")
        result = _get_security_context_impl(str(tmp_path))
        assert "FastAPI" in result["frameworks"]

    def test_detect_express_framework(self, tmp_path):
        app_js = tmp_path / "app.js"
        app_js.write_text(
            "const express = require('express');\nconst app = express();\n"
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "Express" in result["frameworks"]

    def test_detect_nextjs_framework(self, tmp_path):
        config = tmp_path / "next.config.js"
        config.write_text("module.exports = { reactStrictMode: true };\n")
        page = tmp_path / "page.tsx"
        page.write_text("import Link from 'next/link';\n")
        result = _get_security_context_impl(str(tmp_path))
        assert "Next.js" in result["frameworks"]

    def test_no_framework_detected(self, tmp_path):
        util = tmp_path / "util.py"
        util.write_text("def add(a, b):\n    return a + b\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["frameworks"] == []


class TestGetSecurityContextAuthPatterns:
    def test_detect_login_required(self, tmp_path):
        views = tmp_path / "views.py"
        views.write_text(
            textwrap.dedent("""\
            from django.contrib.auth.decorators import login_required

            @login_required
            def dashboard(request):
                return render(request, 'dashboard.html')
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "@login_required" in result["auth_patterns"]

    def test_detect_jwt_required(self, tmp_path):
        api = tmp_path / "api.py"
        api.write_text(
            textwrap.dedent("""\
            @jwt_required
            def protected_endpoint():
                return {"data": "secret"}
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "@jwt_required" in result["auth_patterns"]

    def test_detect_fastapi_depends(self, tmp_path):
        main = tmp_path / "main.py"
        main.write_text(
            textwrap.dedent("""\
            from fastapi import Depends

            def get_items(user=Depends(get_current_user)):
                return items
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "Depends(get_current_user)" in result["auth_patterns"]

    def test_detect_auth_middleware(self, tmp_path):
        app = tmp_path / "app.py"
        app.write_text(
            textwrap.dedent("""\
            from starlette.middleware.authentication import AuthenticationMiddleware
            app.add_middleware(AuthenticationMiddleware)
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "AuthenticationMiddleware" in result["auth_patterns"]

    def test_no_auth_patterns(self, tmp_path):
        util = tmp_path / "util.py"
        util.write_text("def add(a, b):\n    return a + b\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["auth_patterns"] == []


class TestGetSecurityContextHeaders:
    def test_detect_csp_header(self, tmp_path):
        middleware = tmp_path / "middleware.py"
        middleware.write_text(
            textwrap.dedent("""\
            response.headers["Content-Security-Policy"] = "default-src 'self'"
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "Content-Security-Policy" in result["security_headers"]

    def test_detect_hsts_header(self, tmp_path):
        middleware = tmp_path / "middleware.py"
        middleware.write_text(
            textwrap.dedent("""\
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "Strict-Transport-Security" in result["security_headers"]

    def test_detect_helmet_middleware(self, tmp_path):
        app = tmp_path / "app.js"
        app.write_text("const helmet = require('helmet');\napp.use(helmet());\n")
        result = _get_security_context_impl(str(tmp_path))
        assert "security_middleware_detected" in result["security_headers"]

    def test_no_security_headers(self, tmp_path):
        util = tmp_path / "util.py"
        util.write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["security_headers"] == []


class TestGetSecurityContextRateLimiting:
    def test_detect_rate_limit_decorator(self, tmp_path):
        api = tmp_path / "api.py"
        api.write_text(
            textwrap.dedent("""\
            @rate_limit(limit=100, period=60)
            def search(request):
                return results
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert len(result["rate_limiting"]) >= 1

    def test_detect_slowapi(self, tmp_path):
        main = tmp_path / "main.py"
        main.write_text(
            textwrap.dedent("""\
            from slowapi import Limiter
            limiter = Limiter(key_func=get_remote_address)
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "slowapi" in result["rate_limiting"]

    def test_no_rate_limiting(self, tmp_path):
        util = tmp_path / "util.py"
        util.write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["rate_limiting"] == []


class TestGetSecurityContextValidation:
    def test_detect_pydantic_basemodel(self, tmp_path):
        models = tmp_path / "models.py"
        models.write_text(
            textwrap.dedent("""\
            from pydantic import BaseModel

            class User(BaseModel):
                name: str
                age: int
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "BaseModel" in result["input_validation"]

    def test_detect_marshmallow(self, tmp_path):
        schema = tmp_path / "schema.py"
        schema.write_text(
            textwrap.dedent("""\
            import marshmallow
            class UserSchema(marshmallow.Schema):
                name = fields.Str()
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "marshmallow" in result["input_validation"]

    def test_detect_flask_form(self, tmp_path):
        forms = tmp_path / "forms.py"
        forms.write_text(
            textwrap.dedent("""\
            from flask_wtf import FlaskForm
            class LoginForm(FlaskForm):
                username = StringField()
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "FlaskForm" in result["input_validation"]

    def test_no_validation(self, tmp_path):
        util = tmp_path / "util.py"
        util.write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["input_validation"] == []


class TestGetSecurityContextPolicy:
    def test_skylos_yml_loaded(self, tmp_path):
        policy_file = tmp_path / ".skylos.yml"
        policy_file.write_text(
            textwrap.dedent("""\
            rules:
              SKY-D201:
                severity: CRITICAL
            exclude:
              - tests/
        """)
        )
        (tmp_path / "app.py").write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["policy"] is not None
        assert "rules" in result["policy"]
        assert "SKY-D201" in result["policy"]["rules"]

    def test_skylos_yaml_loaded(self, tmp_path):
        policy_file = tmp_path / ".skylos.yaml"
        policy_file.write_text("min_score: 80\n")
        (tmp_path / "app.py").write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["policy"] is not None
        assert result["policy"]["min_score"] == 80

    def test_no_policy(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert result["policy"] is None


class TestGetSecurityContextEmptyProject:
    def test_empty_project(self, tmp_path):
        result = _get_security_context_impl(str(tmp_path))
        assert result["frameworks"] == []
        assert result["auth_patterns"] == []
        assert result["security_headers"] == []
        assert result["rate_limiting"] == []
        assert result["input_validation"] == []
        assert result["policy"] is None

    def test_nonexistent_path(self):
        result = _get_security_context_impl("/tmp/nonexistent_path_xyz_12345")
        assert "error" in result


class TestGetSecurityContextSkipsDirs:
    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "evil"
        nm.mkdir(parents=True)
        evil_file = nm / "app.py"
        evil_file.write_text("from flask import Flask\n")
        (tmp_path / "readme.py").write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert "Flask" not in result["frameworks"]

    def test_skips_venv(self, tmp_path):
        venv = tmp_path / "venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "app.py").write_text("from flask import Flask\n")
        (tmp_path / "main.py").write_text("x = 1\n")
        result = _get_security_context_impl(str(tmp_path))
        assert "Flask" not in result["frameworks"]


class TestGetSecurityContextMultiplePatterns:
    def test_detects_multiple_patterns(self, tmp_path):
        app = tmp_path / "app.py"
        app.write_text(
            textwrap.dedent("""\
            from flask import Flask
            from pydantic import BaseModel

            @login_required
            def dashboard():
                response.headers["Content-Security-Policy"] = "default-src 'self'"
                return "ok"
        """)
        )
        result = _get_security_context_impl(str(tmp_path))
        assert "Flask" in result["frameworks"]
        assert "@login_required" in result["auth_patterns"]
        assert "Content-Security-Policy" in result["security_headers"]
        assert "BaseModel" in result["input_validation"]
