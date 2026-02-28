import json
from pathlib import Path

import pytest

from skylos.visitors.languages.typescript import scan_typescript_file

_BENCHMARKS_DIR = Path(__file__).parent.parent / "manual" / "mixed_repo"


def _scan_ts(tmp_path, code):
    p = tmp_path / "test.ts"
    p.write_text(code, encoding="utf-8")
    results = scan_typescript_file(str(p))
    defs, refs, _, _, _, _, quality, danger, *_ = results
    return defs, refs, quality, danger


def _def_names(defs):
    return {d.name for d in defs}


def _ref_names(refs):
    return {r[0] for r in refs}


def _unused(defs, refs):
    """Return set of def names that have no matching ref."""
    rn = _ref_names(refs)
    return {
        d.name
        for d in defs
        if d.name not in rn and not getattr(d, "is_exported", False)
    }


class TestTSDangerRules:
    def test_eval_detected(self, tmp_path):
        _, _, _, danger = _scan_ts(tmp_path, 'eval("alert(1)");')
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D201" in ids

    def test_innerhtml_detected(self, tmp_path):
        code = 'document.getElementById("x")!.innerHTML = "<b>xss</b>";'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D226" in ids

    def test_new_function_detected(self, tmp_path):
        code = 'const f = new Function("return 1");'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D202" in ids

    def test_settimeout_string_detected(self, tmp_path):
        code = 'setTimeout("alert(1)", 1000);'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D202" in ids

    def test_setinterval_string_detected(self, tmp_path):
        code = 'setInterval("document.write(1)", 5000);'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D202" in ids

    def test_outerhtml_detected(self, tmp_path):
        code = 'document.getElementById("x")!.outerHTML = "<div>replaced</div>";'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D226" in ids

    def test_settimeout_callback_safe(self, tmp_path):
        code = 'setTimeout(() => { console.log("ok"); }, 100);'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D202" not in ids

    def test_regex_exec_not_flagged(self, tmp_path):
        """regex.exec() is safe — should NOT trigger SKY-D212."""
        code = 'const regex = /hello/g;\nconst m = regex.exec("hello world");'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D212" not in ids

    def test_db_exec_not_flagged(self, tmp_path):
        """db.exec() / stmt.exec() should NOT trigger SKY-D212."""
        code = 'const db = getDB();\ndb.exec("SELECT 1");'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D212" not in ids

    def test_child_process_exec_flagged(self, tmp_path):
        """child_process.exec() SHOULD trigger SKY-D212."""
        code = 'import cp from "child_process";\ncp.exec("rm -rf /");'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D212" in ids


class TestTSQualityRules:
    def test_cyclomatic_complexity(self, tmp_path):
        code = (
            "function complex(x: number) {\n"
            "    if (x > 0) {\n"
            "        if (x > 1) { return 1; }\n"
            "        else { return 2; }\n"
            "    } else if (x < -5) {\n"
            "        switch(x) {\n"
            "            case -6: return 6;\n"
            "            case -7: return 7;\n"
            "            case -8: return 8;\n"
            "            default: return 0;\n"
            "        }\n"
            "    }\n"
            "    for (let i = 0; i < 10; i++) {\n"
            "        while (x > 0) {\n"
            "            if (x % 2 === 0) { break; }\n"
            "            if (x % 3 === 0) { continue; }\n"
            "            x--;\n"
            "        }\n"
            "    }\n"
            "    return -1;\n"
            "}\n"
            "complex(1);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in quality}
        assert "SKY-Q301" in ids

    def test_nesting_depth(self, tmp_path):
        code = (
            "function deep(x: number) {\n"
            "    if (x > 0) {\n"
            "        for (let i = 0; i < 10; i++) {\n"
            "            while (i < 5) {\n"
            "                if (i % 2 === 0) {\n"
            "                    try { console.log(i); } catch (e) { }\n"
            "                }\n"
            "                break;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "deep(1);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        nesting = [f for f in quality if f["rule_id"] == "SKY-Q302"]
        assert len(nesting) > 0

    def test_too_many_params(self, tmp_path):
        code = (
            "function many(a: number, b: number, c: string, d: boolean, e: any, f: object) {\n"
            "    return a;\n"
            "}\n"
            "many(1, 2, 'x', true, null, {});\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        param_findings = [f for f in quality if f["rule_id"] == "SKY-C303"]
        assert len(param_findings) == 1
        assert "6 parameters" in param_findings[0]["message"]

    def test_small_function_no_findings(self, tmp_path):
        code = "function small(x: number): number {\n    return x + 1;\n}\nsmall(1);\n"
        _, _, quality, _ = _scan_ts(tmp_path, code)
        assert len(quality) == 0


class TestTSImports:
    def test_named_imports(self, tmp_path):
        code = "import { foo, bar } from './helpers';\nfoo();\n"
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        def_names = {d.name for d in defs}
        assert "foo" in def_names
        assert "bar" in def_names
        import_defs = [d for d in defs if d.type == "import"]
        assert len(import_defs) == 2

    def test_default_import(self, tmp_path):
        code = "import React from 'react';\nReact.createElement('div');\n"
        defs, _, _, _ = _scan_ts(tmp_path, code)
        import_defs = [d for d in defs if d.type == "import"]
        names = {d.name for d in import_defs}
        assert "React" in names

    def test_namespace_import(self, tmp_path):
        code = "import * as utils from './utils';\nutils.doThing();\n"
        defs, _, _, _ = _scan_ts(tmp_path, code)
        import_defs = [d for d in defs if d.type == "import"]
        names = {d.name for d in import_defs}
        assert "utils" in names

    def test_unused_import_detectable(self, tmp_path):
        code = (
            "import { unused } from './lib';\n"
            "function usedFunc() { return 42; }\n"
            "usedFunc();\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        def_names = {d.name for d in defs}
        ref_names = {r[0] for r in refs}
        assert "unused" in def_names
        assert "unused" not in ref_names


class TestTSDeadCodeFalsePositives:
    def test_callback_passed_as_argument(self, tmp_path):
        code = (
            "function transformer(x: number): number { return x * 2; }\n"
            "const results = [1, 2, 3].map(transformer);\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "transformer" not in _unused(defs, refs)

    def test_assigned_to_variable(self, tmp_path):
        code = "function helper() { return 42; }\nconst ref = helper;\n"
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "helper" not in _unused(defs, refs)

    def test_stored_in_array(self, tmp_path):
        code = (
            "function a() { return 1; }\n"
            "function b() { return 2; }\n"
            "const handlers = [a, b];\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "a" not in _unused(defs, refs)
        assert "b" not in _unused(defs, refs)

    def test_object_shorthand(self, tmp_path):
        code = "function myFunc() { return 1; }\nconst obj = { myFunc };\n"
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "myFunc" not in _unused(defs, refs)

    def test_type_annotation_reference(self, tmp_path):
        code = (
            "class UserModel { name: string = ''; }\n"
            "function process(user: UserModel): void { console.log(user); }\n"
            "process(new UserModel());\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "UserModel" not in _unused(defs, refs)

    def test_generic_type_parameter(self, tmp_path):
        code = (
            "class Item { id: number = 0; }\n"
            "class Box<T> { value: T; constructor(v: T) { this.value = v; } }\n"
            "const b: Box<Item> = new Box(new Item());\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "Item" not in _unused(defs, refs)
        assert "Box" not in _unused(defs, refs)

    def test_extends_clause(self, tmp_path):
        """Parent class in extends clause is a reference."""
        code = (
            "class Base { greet() { return 'hi'; } }\n"
            "class Child extends Base { wave() { return 'bye'; } }\n"
            "const c = new Child();\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "Base" not in _unused(defs, refs)

    def test_instanceof_check(self, tmp_path):
        """Class used in instanceof is a reference."""
        code = (
            "class AppError extends Error { code: number = 500; }\n"
            "function check(e: unknown) {\n"
            "    if (e instanceof AppError) { console.log('app error'); }\n"
            "}\n"
            "check(new AppError());\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "AppError" not in _unused(defs, refs)

    def test_decorator_marks_class_used(self, tmp_path):
        code = (
            "function Component(t: any) { return t; }\n"
            "@Component\n"
            "class MyWidget { render() { return 'hi'; } }\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "MyWidget" not in _unused(defs, refs)
        assert "Component" not in _unused(defs, refs)

    def test_export_default_marks_exported(self, tmp_path):
        code = "export default function main() { return 1; }\n"
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        main_def = [d for d in defs if d.name == "main"][0]
        assert main_def.is_exported is True

    def test_export_statement_at_bottom(self, tmp_path):
        code = "function internal() { return 42; }\nexport { internal };\n"
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "internal" not in _unused(defs, refs)

    def test_constructor_not_flagged(self, tmp_path):
        code = (
            "class Svc {\n"
            "    constructor(private db: any) {}\n"
            "    run() { return this.db; }\n"
            "}\n"
            "const s = new Svc({});\n"
            "s.run();\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        def_names = _def_names(defs)
        assert "constructor" not in def_names

    def test_return_statement_reference(self, tmp_path):
        """fn returned from another fn is a reference."""
        code = (
            "function inner() { return 1; }\n"
            "function outer() { return inner; }\n"
            "outer();\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "inner" not in _unused(defs, refs)


class TestTSDeadCodeTruePositives:
    def test_unused_function_flagged(self, tmp_path):
        code = "function used() { return 1; }\nfunction dead() { return 2; }\nused();\n"
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "dead" in _unused(defs, refs)
        assert "used" not in _unused(defs, refs)

    def test_unused_class_flagged(self, tmp_path):
        code = (
            "class UsedClass { run() { return 1; } }\n"
            "class DeadClass { run() { return 2; } }\n"
            "const x = new UsedClass();\n"
        )
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "DeadClass" in _unused(defs, refs)
        assert "UsedClass" not in _unused(defs, refs)

    def test_unused_import_flagged(self, tmp_path):
        code = "import { used, dead } from './lib';\nused();\n"
        defs, refs, _, _ = _scan_ts(tmp_path, code)
        assert "dead" in _unused(defs, refs)
        assert "used" not in _unused(defs, refs)


class TestTSClassDefs:
    def test_class_captured_as_def(self, tmp_path):
        code = "class Foo { bar() { return 1; } }\n"
        defs, _, _, _ = _scan_ts(tmp_path, code)
        class_defs = [d for d in defs if d.type == "class"]
        names = {d.name for d in class_defs}
        assert "Foo" in names

    def test_multiple_classes(self, tmp_path):
        code = "class Alpha { }\nclass Beta { }\nclass Gamma { }\n"
        defs, _, _, _ = _scan_ts(tmp_path, code)
        class_defs = [d for d in defs if d.type == "class"]
        assert len(class_defs) == 3
        names = {d.name for d in class_defs}
        assert names == {"Alpha", "Beta", "Gamma"}

    def test_exported_class_detected(self, tmp_path):
        code = "export class ApiService { fetch() { return null; } }\n"
        defs, _, _, _ = _scan_ts(tmp_path, code)
        cls = [d for d in defs if d.name == "ApiService"][0]
        assert cls.is_exported is True
        assert cls.type == "class"


class TestMixedRepoIntegration:
    def test_mixed_repo_finds_dead_code_in_both(self, tmp_path):
        """Both Python and TS dead code should appear in results."""
        from skylos.analyzer import analyze

        (tmp_path / "utils.py").write_text(
            "def used_helper():\n"
            "    return 42\n"
            "\n"
            "def dead_python_func():\n"
            "    return 'nobody calls me'\n"
            "\n"
            "result = used_helper()\n"
        )

        (tmp_path / "app.ts").write_text(
            "function usedHandler(): string { return 'ok'; }\n"
            "function deadTsFunc(): string { return 'nobody calls me'; }\n"
            "usedHandler();\n"
        )

        result_json = analyze(str(tmp_path), conf=10)
        result = json.loads(result_json)

        unused_names = {f["name"] for f in result.get("unused_functions", [])}
        assert "dead_python_func" in unused_names, (
            f"Python dead code not found in {unused_names}"
        )
        assert "deadTsFunc" in unused_names, f"TS dead code not found in {unused_names}"
        assert "used_helper" not in unused_names
        assert "usedHandler" not in unused_names

    def test_mixed_repo_danger_from_ts(self, tmp_path):
        from skylos.analyzer import analyze

        (tmp_path / "safe.py").write_text("x = 1\n")
        (tmp_path / "dangerous.ts").write_text('eval("alert(1)");\n')

        result_json = analyze(str(tmp_path), conf=10, enable_danger=True)
        result = json.loads(result_json)

        danger_rules = {f["rule_id"] for f in result.get("danger", [])}
        assert "SKY-D201" in danger_rules

    def test_mixed_repo_quality_from_ts(self, tmp_path):
        from skylos.analyzer import analyze

        (tmp_path / "ok.py").write_text("x = 1\n")
        (tmp_path / "messy.ts").write_text(
            "function deep(x: number) {\n"
            "    if (x > 0) {\n"
            "        for (let i = 0; i < 10; i++) {\n"
            "            while (i < 5) {\n"
            "                if (i % 2 === 0) {\n"
            "                    try { console.log(i); } catch(e) { }\n"
            "                }\n"
            "                break;\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "}\n"
            "deep(1);\n"
        )

        result_json = analyze(str(tmp_path), conf=10, enable_quality=True)
        result = json.loads(result_json)

        quality_rules = {f.get("rule_id") for f in result.get("quality", [])}
        assert "SKY-Q302" in quality_rules


class TestHardBenchmark:
    EXPECTED_DEAD = {
        "defaultExport",
        "DeadInterface",
        "DeadAlias",
        "DeadEnum",
        "deadStandalone",
        "anotherDeadFn",
        "OrphanService",
        "BaseProcessor",
        "createLogger",
        "syncToCloud",
        "subtract",
        "multiply",
        "notExportedNotCalled",
        "identity",
        "deeplyBuriedDead",
        "parseInput",
        "isPullRequest",
    }

    EXPECTED_ALIVE = {
        "processRepo",
        "handleClick",
        "extraValidator",
        "formatNumber",
        "createFormatter",
        "fallbackMessage",
        "defaultGreeting",
        "serialize",
        "html",
        "LogClass",
        "WithRetry",
        "createCounter",
        "fetchStars",
        "toUpperCase",
        "firstItem",
        "filterMerged",
        "getDefaultPort",
        "getDefaultHost",
        "logStartup",
        "stringify",
        "isRepository",
        "dynamicLookup",
        "phantomRef",
        "describeStatus",
        "greet",
        "add",
        "isEven",
        "ServiceA",
        "ServiceB",
        "EventBus",
        "MathUtils",
        "CustomError",
        "Repository",
        "PullRequest",
        "EventHandler",
        "Status",
        "map",
        "filter",
        "helpers",
    }

    @pytest.fixture(autouse=True)
    def _scan(self, tmp_path):
        src = _BENCHMARKS_DIR / "hard_benchmark.ts"
        if not src.exists():
            pytest.skip("hard_benchmark.ts not found")
        self.defs, self.refs, _, _ = _scan_ts(tmp_path, src.read_text())
        self.unused = _unused(self.defs, self.refs)

    def test_all_dead_detected(self):
        for name in self.EXPECTED_DEAD:
            assert name in self.unused, f"{name} should be flagged as dead"

    def test_no_false_positives(self):
        for name in self.EXPECTED_ALIVE:
            assert name not in self.unused, f"{name} is alive but was flagged"


class TestRealisticBenchmark:
    EXPECTED_DEAD = {
        "useRef",
        "_",
        "csrfProtection",
        "globalErrorHandler",
        "ObsoleteSchema",
        "CacheEntry",
        "NotificationService",
        "AnalyticsService",
        "useLocalStorage",
        "useWindowSize",
        "slugify",
        "deepClone",
        "retry",
        "Nullable",
        "ReadonlyDeep",
        "SocketEvent",
        "LEGACY_API_URL",
        "FEATURE_FLAGS",
        "slackNotifyHook",
        "syncUserData",
        "purgeExpiredSessions",
        "adminOnlyEndpoint",
        "isString",
        "formatCurrency",
        "ConflictError",
        "RateLimitError",
    }

    EXPECTED_ALIVE = {
        "Request",
        "Response",
        "NextFunction",
        "createSlice",
        "PayloadAction",
        "useCallback",
        "useMemo",
        "axios",
        "z",
        "rateLimiter",
        "corsHandler",
        "requestLogger",
        "UserSchema",
        "CreatePostSchema",
        "User",
        "CreatePostInput",
        "ApiConfig",
        "PaginatedResponse",
        "AppState",
        "DeepPartial",
        "ApiResponse",
        "AppEvent",
        "PluginHook",
        "UserService",
        "PostService",
        "QueryBuilder",
        "ValidationError",
        "NotFoundError",
        "useDebounce",
        "useFetchUsers",
        "truncate",
        "toLowerCase",
        "trim",
        "pipe",
        "formatDate",
        "handleEvent",
        "registerHooks",
        "auditHook",
        "metricsHook",
        "fetchUserProfile",
        "fetchUserPosts",
        "validateAge",
        "withAuth",
        "protectedEndpoint",
        "isNonEmpty",
        "formatUserRow",
        "API_BASE_URL",
        "userSlice",
        "internalHelper",
    }

    @pytest.fixture(autouse=True)
    def _scan(self, tmp_path):
        src = _BENCHMARKS_DIR / "realistic_benchmark.ts"
        if not src.exists():
            pytest.skip("realistic_benchmark.ts not found")
        self.defs, self.refs, _, _ = _scan_ts(tmp_path, src.read_text())
        self.unused = _unused(self.defs, self.refs)

    def test_all_dead_detected(self):
        for name in self.EXPECTED_DEAD:
            assert name in self.unused, f"{name} should be flagged as dead"

    def test_no_false_positives(self):
        for name in self.EXPECTED_ALIVE:
            assert name not in self.unused, f"{name} is alive but was flagged"


# =========================================================================
# New danger rules (Step 5)
# =========================================================================


class TestNewDangerRules:
    def test_require_with_variable(self, tmp_path):
        """SKY-D245: require() with variable argument."""
        code = 'const mod = "fs";\nconst fs = require(mod);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D245" in ids

    def test_require_with_string_safe(self, tmp_path):
        """require() with string literal should NOT trigger SKY-D245."""
        code = 'const fs = require("fs");\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D245" not in ids

    def test_jwt_decode_flagged(self, tmp_path):
        """SKY-D246: jwt.decode() without verify."""
        code = 'import jwt from "jsonwebtoken";\nconst payload = jwt.decode(token);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D246" in ids

    def test_non_jwt_decode_safe(self, tmp_path):
        """base64.decode() should NOT trigger SKY-D246."""
        code = "const result = base64.decode(data);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D246" not in ids

    def test_cors_wildcard_origin(self, tmp_path):
        """SKY-D247: cors({ origin: '*' })."""
        code = "import cors from 'cors';\nconst handler = cors({ origin: '*' });\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D247" in ids

    def test_cors_specific_origin_safe(self, tmp_path):
        """cors() with specific origin should NOT trigger SKY-D247."""
        code = "import cors from 'cors';\nconst handler = cors({ origin: 'https://example.com' });\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D247" not in ids

    def test_hardcoded_localhost_url(self, tmp_path):
        """SKY-D248: Hardcoded localhost URL."""
        code = 'const API = "http://localhost:3000/api/v1";\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D248" in ids

    def test_hardcoded_127_url(self, tmp_path):
        """SKY-D248: Hardcoded 127.0.0.1 URL."""
        code = 'const API = "http://127.0.0.1:8080/health";\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D248" in ids

    def test_normal_url_safe(self, tmp_path):
        """Normal external URL should NOT trigger SKY-D248."""
        code = 'const API = "https://api.example.com/v1";\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D248" not in ids

    def test_entropy_secret_detection(self, tmp_path):
        """High-entropy strings should trigger SKY-S101."""
        code = 'const token = "aB3dEfGhIjKlMnOpQrStUvWxYz012345";\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        s101 = [f for f in danger if f["rule_id"] == "SKY-S101"]
        assert len(s101) > 0

    def test_low_entropy_safe(self, tmp_path):
        """Low-entropy string should NOT trigger entropy-based SKY-S101."""
        code = 'const msg = "aaaaaaaaaaaaaaaaaaaaaa";\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        s101 = [f for f in danger if f["rule_id"] == "SKY-S101"]
        assert len(s101) == 0


# =========================================================================
# New quality rules (Steps 6-7)
# =========================================================================


class TestNewQualityRules:
    def test_duplicate_condition_if_else(self, tmp_path):
        """SKY-Q305: Duplicate condition in if-else chain."""
        code = (
            "function check(x: number) {\n"
            "    if (x > 10) { return 1; }\n"
            "    else if (x < 0) { return -1; }\n"
            "    else if (x > 10) { return 2; }\n"
            "    return 0;\n"
            "}\n"
            "check(5);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in quality}
        assert "SKY-Q305" in ids

    def test_no_duplicate_condition(self, tmp_path):
        """No duplicate conditions should not trigger SKY-Q305."""
        code = (
            "function check(x: number) {\n"
            "    if (x > 10) { return 1; }\n"
            "    else if (x < 0) { return -1; }\n"
            "    else { return 0; }\n"
            "}\n"
            "check(5);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        q305 = [f for f in quality if f["rule_id"] == "SKY-Q305"]
        assert len(q305) == 0

    def test_await_in_for_loop(self, tmp_path):
        """SKY-Q402: await inside for loop."""
        code = (
            "async function fetchAll(urls: string[]) {\n"
            "    for (const url of urls) {\n"
            "        await fetch(url);\n"
            "    }\n"
            "}\n"
            "fetchAll([]);\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in quality}
        assert "SKY-Q402" in ids

    def test_await_in_while_loop(self, tmp_path):
        """SKY-Q402: await inside while loop."""
        code = (
            "async function poll() {\n"
            "    let done = false;\n"
            "    while (!done) {\n"
            "        done = await checkStatus();\n"
            "    }\n"
            "}\n"
            "poll();\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in quality}
        assert "SKY-Q402" in ids

    def test_await_outside_loop_safe(self, tmp_path):
        """await outside loop should NOT trigger SKY-Q402."""
        code = (
            "async function fetchOne() {\n"
            "    const result = await fetch('https://example.com');\n"
            "    return result;\n"
            "}\n"
            "fetchOne();\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        q402 = [f for f in quality if f["rule_id"] == "SKY-Q402"]
        assert len(q402) == 0

    def test_unreachable_after_return(self, tmp_path):
        """SKY-UC002: Code after return statement."""
        code = (
            "function dead() {\n"
            "    return 1;\n"
            "    console.log('unreachable');\n"
            "}\n"
            "dead();\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in quality}
        assert "SKY-UC002" in ids

    def test_unreachable_after_throw(self, tmp_path):
        """SKY-UC002: Code after throw statement."""
        code = (
            "function fail() {\n"
            "    throw new Error('fail');\n"
            "    console.log('unreachable');\n"
            "}\n"
            "fail();\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in quality}
        assert "SKY-UC002" in ids

    def test_no_unreachable_code(self, tmp_path):
        """Normal function should NOT trigger SKY-UC002."""
        code = (
            "function ok() {\n"
            "    console.log('hello');\n"
            "    return 1;\n"
            "}\n"
            "ok();\n"
        )
        _, _, quality, _ = _scan_ts(tmp_path, code)
        uc002 = [f for f in quality if f["rule_id"] == "SKY-UC002"]
        assert len(uc002) == 0


# =========================================================================
# New danger rules: D250, D251, D252, D253
# =========================================================================


class TestInsecureRandomness:
    """SKY-D250: Math.random() is not cryptographically secure."""

    def test_math_random_flagged(self, tmp_path):
        code = "const id = Math.random().toString(36);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D250" in ids

    def test_math_random_in_expression(self, tmp_path):
        code = "const roll = Math.floor(Math.random() * 6) + 1;\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D250" in ids

    def test_crypto_random_safe(self, tmp_path):
        """crypto.getRandomValues() should NOT trigger SKY-D250."""
        code = "const arr = new Uint8Array(16);\ncrypto.getRandomValues(arr);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D250" not in ids

    def test_math_floor_safe(self, tmp_path):
        """Math.floor() alone should NOT trigger SKY-D250."""
        code = "const x = Math.floor(3.7);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D250" not in ids


class TestSensitiveDataInLogs:
    """SKY-D251: Sensitive data passed to console logging methods."""

    def test_console_log_password(self, tmp_path):
        code = 'const password = "hunter2";\nconsole.log(password);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" in ids

    def test_console_error_token(self, tmp_path):
        code = "const userToken = getToken();\nconsole.error(userToken);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" in ids

    def test_console_log_property(self, tmp_path):
        """console.log(user.password) — property access with sensitive name."""
        code = "console.log(user.password);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" in ids

    def test_console_log_template_literal(self, tmp_path):
        """console.log(`Token: ${token}`) — sensitive data in template."""
        code = "const token = getToken();\nconsole.log(`Auth: ${token}`);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" in ids

    def test_console_warn_api_key(self, tmp_path):
        code = "const apiKey = process.env.KEY;\nconsole.warn(apiKey);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" in ids

    def test_console_log_string_safe(self, tmp_path):
        """console.log with string literal should NOT trigger."""
        code = 'console.log("Application started");\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" not in ids

    def test_console_log_safe_variable(self, tmp_path):
        """console.log with non-sensitive variable should NOT trigger."""
        code = "const count = 42;\nconsole.log(count);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" not in ids

    def test_console_log_username_safe(self, tmp_path):
        """'username' should NOT trigger (not a secret)."""
        code = "const username = 'admin';\nconsole.log(username);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" not in ids

    def test_console_time_safe(self, tmp_path):
        """console.time() is not a logging method — should NOT trigger."""
        code = "const token = 'abc';\nconsole.time(token);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D251" not in ids


class TestInsecureCookies:
    """SKY-D252: Cookie set without httpOnly or secure flags."""

    def test_cookie_no_options(self, tmp_path):
        """res.cookie() with no options object."""
        code = 'res.cookie("session", token);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        d252 = [f for f in danger if f["rule_id"] == "SKY-D252"]
        assert len(d252) == 1
        assert "httpOnly" in d252[0]["message"]
        assert "secure" in d252[0]["message"]

    def test_cookie_missing_httponly(self, tmp_path):
        """Options with secure but missing httpOnly."""
        code = 'res.cookie("session", token, { secure: true });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        d252 = [f for f in danger if f["rule_id"] == "SKY-D252"]
        assert len(d252) == 1
        assert "httpOnly" in d252[0]["message"]
        assert "secure" not in d252[0]["message"] or "httpOnly" in d252[0]["message"]

    def test_cookie_missing_secure(self, tmp_path):
        """Options with httpOnly but missing secure."""
        code = 'res.cookie("session", token, { httpOnly: true });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        d252 = [f for f in danger if f["rule_id"] == "SKY-D252"]
        assert len(d252) == 1
        assert "secure" in d252[0]["message"]

    def test_cookie_both_flags_safe(self, tmp_path):
        """Both httpOnly and secure present — should NOT trigger."""
        code = 'res.cookie("session", token, { httpOnly: true, secure: true });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        d252 = [f for f in danger if f["rule_id"] == "SKY-D252"]
        assert len(d252) == 0

    def test_cookie_all_flags_safe(self, tmp_path):
        """All three flags present — should NOT trigger."""
        code = 'res.cookie("sid", token, { httpOnly: true, secure: true, sameSite: "strict" });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        d252 = [f for f in danger if f["rule_id"] == "SKY-D252"]
        assert len(d252) == 0

    def test_cookie_dynamic_options_safe(self, tmp_path):
        """Variable options — can't analyze, should NOT trigger."""
        code = "res.cookie('session', token, cookieOpts);\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        d252 = [f for f in danger if f["rule_id"] == "SKY-D252"]
        assert len(d252) == 0


class TestTimingUnsafeComparison:
    """SKY-D253: Direct comparison of security-sensitive variables."""

    def test_password_triple_eq(self, tmp_path):
        code = (
            "function verify(password: string, stored: string) {\n"
            "    return password === stored;\n"
            "}\n"
            "verify('a', 'b');\n"
        )
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" in ids

    def test_token_double_eq(self, tmp_path):
        code = "if (apiToken == expectedToken) { grant(); }\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" in ids

    def test_hash_comparison(self, tmp_path):
        code = "if (computedHash === storedHash) { return true; }\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" in ids

    def test_secret_not_equal(self, tmp_path):
        """!== with secret is also timing-unsafe."""
        code = "if (secret !== expected) { throw new Error('invalid'); }\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" in ids

    def test_member_expr_password(self, tmp_path):
        """user.password === input — property access."""
        code = "if (user.password === input) { auth(); }\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" in ids

    def test_number_comparison_safe(self, tmp_path):
        """Numeric comparison should NOT trigger."""
        code = "if (count === 42) { doStuff(); }\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" not in ids

    def test_string_literal_comparison_safe(self, tmp_path):
        """String literal comparison should NOT trigger."""
        code = 'if (status === "active") { proceed(); }\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" not in ids

    def test_length_comparison_safe(self, tmp_path):
        """arr.length === 0 should NOT trigger."""
        code = "if (items.length === 0) { return; }\n"
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D253" not in ids


# ---------------------------------------------------------------------------
# SKY-D270: Sensitive data in localStorage/sessionStorage
# ---------------------------------------------------------------------------


class TestLocalStorageTokens:
    def test_localstorage_token(self, tmp_path):
        code = 'localStorage.setItem("auth_token", token);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" in ids

    def test_localstorage_jwt(self, tmp_path):
        code = 'localStorage.setItem("jwt", data.jwt);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" in ids

    def test_sessionstorage_password(self, tmp_path):
        code = 'sessionStorage.setItem("password", pw);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" in ids

    def test_localstorage_access_token(self, tmp_path):
        code = 'localStorage.setItem("accessToken", resp.token);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" in ids

    def test_localstorage_apikey(self, tmp_path):
        code = 'localStorage.setItem("api_key", key);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" in ids

    def test_sessionstorage_refresh_token(self, tmp_path):
        code = 'sessionStorage.setItem("refresh-token", rt);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" in ids

    def test_csrf_token_safe(self, tmp_path):
        """CSRF tokens in storage should NOT trigger."""
        code = 'localStorage.setItem("csrf_token", csrfToken);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" not in ids

    def test_xsrf_token_safe(self, tmp_path):
        """XSRF tokens in storage should NOT trigger."""
        code = 'localStorage.setItem("xsrf-token", token);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" not in ids

    def test_non_sensitive_key_safe(self, tmp_path):
        """Non-sensitive keys should NOT trigger."""
        code = 'localStorage.setItem("theme", "dark");\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" not in ids

    def test_locale_setting_safe(self, tmp_path):
        """Ordinary settings should NOT trigger."""
        code = 'sessionStorage.setItem("locale", "en-US");\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D270" not in ids

    def test_message_mentions_storage_type(self, tmp_path):
        """Finding message should mention the correct storage type."""
        code = 'sessionStorage.setItem("auth_token", t);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        d270 = [f for f in danger if f["rule_id"] == "SKY-D270"]
        assert len(d270) == 1
        assert "sessionStorage" in d270[0]["message"]


# ---------------------------------------------------------------------------
# SKY-D271: Error information disclosure in HTTP responses
# ---------------------------------------------------------------------------


class TestErrorDisclosure:
    def test_res_json_error_stack(self, tmp_path):
        code = 'res.json({ error: err.stack });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" in ids

    def test_res_send_error_stack(self, tmp_path):
        code = 'res.send(error.stack);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" in ids

    def test_res_json_sql_message(self, tmp_path):
        code = 'res.json({ detail: err.sqlMessage });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" in ids

    def test_res_write_sql_state(self, tmp_path):
        code = 'response.write(dbErr.sqlState);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" in ids

    def test_res_end_sql(self, tmp_path):
        code = 'res.end(JSON.stringify({ sql: err.sql }));\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" in ids

    def test_generic_error_message_safe(self, tmp_path):
        """Sending a generic message should NOT trigger."""
        code = 'res.json({ error: "Something went wrong" });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" not in ids

    def test_res_json_safe_property(self, tmp_path):
        """err.message (not stack/sql) should NOT trigger."""
        code = 'res.json({ error: err.message });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" not in ids

    def test_console_log_stack_safe(self, tmp_path):
        """Logging error.stack (not in response) should NOT trigger D271."""
        code = 'console.error(err.stack);\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        ids = {f["rule_id"] for f in danger}
        assert "SKY-D271" not in ids

    def test_finding_message_mentions_prop(self, tmp_path):
        """Finding message should name the specific dangerous property."""
        code = 'res.json({ trace: err.stack });\n'
        _, _, _, danger = _scan_ts(tmp_path, code)
        d271 = [f for f in danger if f["rule_id"] == "SKY-D271"]
        assert len(d271) == 1
        assert "stack" in d271[0]["message"]
