from pathlib import Path

from skylos.core.java_api_surface import build_java_surface_index
from skylos.rules.ai_defect.java_api_hallucination import (
    scan_java_local_api_hallucinations,
)
from skylos.verify_change import verify_change_path


def _write(root: Path, relative: str, source: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(  # skylos: ignore[SKY-D324] pytest tmp_path fixture
        source,
        encoding="utf-8",
    )
    return path


def _scan(tmp_path: Path, app_source: str, **sources: str):
    files = [_write(tmp_path, "src/demo/app/App.java", app_source)]
    files.extend(
        _write(tmp_path, relative, source) for relative, source in sources.items()
    )
    return scan_java_local_api_hallucinations(tmp_path, files)


TOKEN_VERIFIER = """package demo.security;
public final class TokenVerifier {
    public static boolean verify(String value) { return value != null; }
    public static final String VERSION = "1";
}
"""


def test_java_local_api_check_passes_explicit_local_static_references(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() {
        return TokenVerifier.verify(TokenVerifier.VERSION);
    }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 2


def test_java_local_api_check_fails_missing_static_member(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verifySession("ok"); }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert [finding["simple_name"] for finding in findings] == ["verifySession"]
    assert findings[0]["metadata"]["language"] == "java"
    assert findings[0]["metadata"]["reference_kind"] == "static_member"
    assert check["outcome"] == "fail"


def test_java_local_api_check_resolves_same_package_type(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
class App {
    boolean run() { return LocalVerifier.verify("ok"); }
}
""",
        **{
            "src/demo/app/LocalVerifier.java": """package demo.app;
class LocalVerifier {
    static boolean verify(String value) { return value != null; }
}
"""
        },
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_java_local_api_check_passes_explicit_static_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import static demo.security.TokenVerifier.verify;
class App {
    boolean run() { return verify("ok"); }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_java_local_api_check_fails_missing_explicit_static_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import static demo.security.TokenVerifier.verifySession;
class App {
    boolean run() { return verifySession("ok"); }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert [finding["simple_name"] for finding in findings] == ["verifySession"]
    assert check["outcome"] == "fail"


def test_java_local_api_check_marks_local_wildcard_import_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.*;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "wildcard_import", "count": 1}]


def test_java_local_api_check_ignores_external_type_import(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import external.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.unknown("ok"); }
}
""",
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["references"] == 0


def test_java_local_api_check_treats_overloads_as_one_member(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok", true); }
}
""",
        **{
            "src/demo/security/TokenVerifier.java": """package demo.security;
public final class TokenVerifier {
    public static boolean verify(String value) { return value != null; }
    public static boolean verify(String value, boolean strict) { return strict; }
}
"""
        },
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_java_surface_indexes_implicitly_static_nested_interface(tmp_path):
    token_verifier = _write(
        tmp_path,
        "src/demo/security/TokenVerifier.java",
        """package demo.security;
public final class TokenVerifier {
    public interface Policy {}
}
""",
    )

    index = build_java_surface_index(tmp_path, [token_verifier])

    surface = index.type_surface("demo.security.TokenVerifier")
    assert surface is not None
    assert surface.complete is True
    assert "Policy" in surface.members


def test_java_local_api_check_marks_inherited_surface_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
        **{
            "src/demo/security/BaseVerifier.java": """package demo.security;
class BaseVerifier {}
""",
            "src/demo/security/TokenVerifier.java": """package demo.security;
public final class TokenVerifier extends BaseVerifier {
    public static boolean verify(String value) { return value != null; }
}
""",
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "surface_inherited_members", "count": 1}]


def test_java_local_api_check_marks_ambiguous_duplicate_type_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
        **{
            "src/one/TokenVerifier.java": TOKEN_VERIFIER,
            "src/two/TokenVerifier.java": TOKEN_VERIFIER,
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "surface_ambiguous_type", "count": 1}]


def test_java_local_api_check_marks_parse_failed_surface_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
        **{
            "src/demo/security/TokenVerifier.java": TOKEN_VERIFIER,
            "src/demo/broken/Broken.java": "package demo.broken; class Broken {",
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "parse_error", "count": 1},
        {"code": "surface_parse_error", "count": 1},
    ]


def test_java_local_api_check_marks_local_instance_reference_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run(TokenVerifier verifier) { return verifier.verify("ok"); }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "instance_type_inference_unsupported", "count": 1}
    ]


def test_java_local_api_check_marks_shadowed_type_name_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run(Object TokenVerifier) {
        return TokenVerifier.verify("ok");
    }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "type_name_shadowed", "count": 1}]


def test_java_local_api_check_verifies_static_method_reference(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
import java.util.function.Predicate;
class App {
    Predicate<String> verifier() { return TokenVerifier::verify; }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_java_local_api_check_marks_missing_method_reference_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
import java.util.function.Predicate;
class App {
    Predicate<String> verifier() { return TokenVerifier::missing; }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "method_reference_unsupported", "count": 1}]


def test_java_local_api_check_marks_nested_type_member_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.Policy.missing(); }
}
""",
        **{
            "src/demo/security/TokenVerifier.java": """package demo.security;
public final class TokenVerifier {
    public static final class Policy {}
}
"""
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert {reason["code"] for reason in check["reasons"]} == {
        "nested_type_member_unsupported"
    }


def test_java_local_api_check_marks_var_instance_call_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() {
        var verifier = new TokenVerifier();
        return verifier.missing("ok");
    }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "instance_type_inference_unsupported", "count": 1}
    ]


def test_java_local_api_check_marks_instance_method_reference_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    Object run(TokenVerifier verifier) { return verifier::missing; }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [
        {"code": "instance_method_reference_unsupported", "count": 1}
    ]


def test_java_local_api_check_rejects_field_used_as_method(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    String run() { return TokenVerifier.VERSION(); }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert [finding["simple_name"] for finding in findings] == ["VERSION"]
    assert findings[0]["metadata"]["expected_member_kind"] == "method"
    assert findings[0]["metadata"]["actual_member_kinds"] == "field"
    assert check["outcome"] == "fail"


def test_java_local_api_check_rejects_inaccessible_private_static_method(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    void run() { TokenVerifier.hidden(); }
}
""",
        **{
            "src/demo/security/TokenVerifier.java": """package demo.security;
public final class TokenVerifier {
    private static void hidden() {}
}
"""
        },
    )

    assert [finding["simple_name"] for finding in findings] == ["hidden"]
    assert findings[0]["metadata"]["member_visibility"] == "private"
    assert check["outcome"] == "fail"


def test_java_local_api_check_marks_cross_package_protected_member_incomplete(
    tmp_path,
):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    void run() { TokenVerifier.protectedMethod(); }
}
""",
        **{
            "src/demo/security/TokenVerifier.java": """package demo.security;
public class TokenVerifier {
    protected static void protectedMethod() {}
}
"""
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "member_visibility_uncertain", "count": 1}]


def test_java_local_api_check_marks_nested_type_field_access_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    Object run() { return TokenVerifier.Policy.MISSING; }
}
""",
        **{
            "src/demo/security/TokenVerifier.java": """package demo.security;
public final class TokenVerifier {
    public static final class Policy {}
}
"""
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert "nested_type_member_unsupported" in {
        reason["code"] for reason in check["reasons"]
    }


def test_java_local_api_check_marks_nested_type_import_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier.Policy;
class App {}
""",
        **{
            "src/demo/security/TokenVerifier.java": """package demo.security;
public final class TokenVerifier {
    public static final class Policy {}
}
"""
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "nested_type_import_unsupported", "count": 1}]


def test_java_local_api_check_does_not_use_unrelated_module_surface(tmp_path):
    _write(tmp_path, "module-a/build.gradle", "")
    _write(tmp_path, "module-b/build.gradle", "")
    token_verifier = _write(
        tmp_path,
        "module-a/src/main/java/demo/security/TokenVerifier.java",
        TOKEN_VERIFIER,
    )
    app = _write(
        tmp_path,
        "module-b/src/main/java/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
    )

    findings, check = scan_java_local_api_hallucinations(
        tmp_path,
        [app, token_verifier],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "module_ownership_uncertain", "count": 1}]


def test_java_local_api_check_marks_explicit_missing_local_type_incomplete(tmp_path):
    _write(
        tmp_path,
        "src/demo/security/ExistingVerifier.java",
        "package demo.security;\nclass ExistingVerifier {}\n",
    )
    app = _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.MissingVerifier;
class App {
    boolean run() { return MissingVerifier.verify("ok"); }
}
""",
    )

    findings, check = scan_java_local_api_hallucinations(tmp_path, [app])

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "local_type_ownership_uncertain", "count": 1}]


def test_java_local_api_check_marks_fully_qualified_missing_type_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
class App {
    boolean run() { return demo.security.MissingVerifier.verify("ok"); }
}
""",
        **{
            "src/demo/security/ExistingVerifier.java": (
                "package demo.security;\nclass ExistingVerifier {}\n"
            )
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "local_type_ownership_uncertain", "count": 1}]


def test_java_local_api_check_does_not_use_test_surface_for_main_code(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.missing("ok"); }
}
""",
        **{
            "src/test/java/demo/security/TokenVerifier.java": TOKEN_VERIFIER,
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "source_set_ownership_uncertain", "count": 1}]


def test_java_local_api_check_classifies_test_fixtures_as_test_surface(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
        **{
            "src/testFixtures/java/demo/security/TokenVerifier.java": TOKEN_VERIFIER,
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "source_set_ownership_uncertain", "count": 1}]


def test_java_source_set_ignores_absolute_ancestor_named_test(tmp_path):
    root = tmp_path / "test" / "repo"
    token_verifier = _write(
        root,
        "src/main/java/demo/security/TokenVerifier.java",
        TOKEN_VERIFIER,
    )
    app = _write(
        root,
        "src/main/java/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
    )

    findings, check = scan_java_local_api_hallucinations(
        root,
        [app, token_verifier],
    )

    assert findings == []
    assert check["outcome"] == "pass"


def test_java_local_api_check_allows_test_code_to_use_main_surface(tmp_path):
    token_verifier = _write(
        tmp_path,
        "src/main/java/demo/security/TokenVerifier.java",
        TOKEN_VERIFIER,
    )
    test_app = _write(
        tmp_path,
        "src/test/java/demo/app/AppTest.java",
        """package demo.app;
import demo.security.TokenVerifier;
class AppTest {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
    )

    findings, check = scan_java_local_api_hallucinations(
        tmp_path,
        [token_verifier, test_app],
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_java_local_api_check_marks_generated_surface_incomplete(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.missing("ok"); }
}
""",
        **{
            "generated/demo/security/TokenVerifier.java": TOKEN_VERIFIER,
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "source_set_ownership_uncertain", "count": 1}]


def test_java_local_api_check_recognizes_qualified_codegen_annotation(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
        **{
            "src/demo/security/TokenVerifier.java": """package demo.security;
@lombok.Data
public final class TokenVerifier {}
"""
        },
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert check["reasons"] == [{"code": "surface_generated_members", "count": 1}]


def test_java_local_api_check_passes_fully_qualified_local_type(tmp_path):
    findings, check = _scan(
        tmp_path,
        """package demo.app;
class App {
    boolean run() { return demo.security.TokenVerifier.verify("ok"); }
}
""",
        **{"src/demo/security/TokenVerifier.java": TOKEN_VERIFIER},
    )

    assert findings == []
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_verify_change_passes_clean_java_workspace_surface(tmp_path):
    _write(tmp_path, "src/demo/security/TokenVerifier.java", TOKEN_VERIFIER)
    _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verify("ok"); }
}
""",
    )

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "pass"
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "java_workspace_api_surface"
    )
    assert check["outcome"] == "pass"
    assert check["verified_references"] == 1


def test_verify_change_fails_missing_java_workspace_member(tmp_path):
    _write(tmp_path, "src/demo/security/TokenVerifier.java", TOKEN_VERIFIER)
    _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verifySession("ok"); }
}
""",
    )

    payload = verify_change_path(tmp_path)

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["language"] == "java"
    assert finding["metadata"]["member_name"] == "verifySession"


def test_verify_change_keeps_nested_java_surface_inside_requested_scan(tmp_path):
    _write(tmp_path, "pyproject.toml", "[tool.skylos]\n")
    case_root = tmp_path / "benchmarks" / "current"
    _write(case_root, "src/demo/security/TokenVerifier.java", TOKEN_VERIFIER)
    _write(
        case_root,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verifySession("ok"); }
}
""",
    )
    _write(
        tmp_path,
        "benchmarks/sibling/src/demo/security/TokenVerifier.java",
        TOKEN_VERIFIER,
    )

    payload = verify_change_path(case_root)

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["member_name"] == "verifySession"


def test_verify_change_java_surface_respects_excluded_folders(tmp_path):
    _write(tmp_path, "src/demo/security/TokenVerifier.java", TOKEN_VERIFIER)
    _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.verifySession("ok"); }
}
""",
    )
    _write(
        tmp_path,
        "generated/demo/security/TokenVerifier.java",
        TOKEN_VERIFIER,
    )

    payload = verify_change_path(tmp_path, exclude_folders=["generated"])

    assert payload["status"] == "fail"
    finding = next(
        item for item in payload["findings"] if item["rule_id"] == "SKY-L012"
    )
    assert finding["metadata"]["member_name"] == "verifySession"


def test_java_file_scoped_workspace_discovery_respects_excluded_folders(tmp_path):
    app = _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.missing("ok"); }
}
""",
    )
    _write(
        tmp_path,
        "generated/demo/security/TokenVerifier.java",
        TOKEN_VERIFIER,
    )

    findings, check = scan_java_local_api_hallucinations(
        tmp_path,
        [app],
        discover_workspace=True,
        exclude_folders=["generated"],
    )

    assert findings == []
    assert check["outcome"] == "incomplete"
    assert "excluded_workspace_paths" in {reason["code"] for reason in check["reasons"]}


def test_verify_change_java_file_scope_carries_excluded_folders(tmp_path):
    _write(tmp_path, "pyproject.toml", "[tool.skylos]\n")
    app = _write(
        tmp_path,
        "src/demo/app/App.java",
        """package demo.app;
import demo.security.TokenVerifier;
class App {
    boolean run() { return TokenVerifier.missing("ok"); }
}
""",
    )
    _write(
        tmp_path,
        "generated/demo/security/TokenVerifier.java",
        TOKEN_VERIFIER,
    )

    payload = verify_change_path(app, exclude_folders=["generated"])

    assert payload["status"] == "incomplete"
    assert not any(
        finding.get("metadata", {}).get("language") == "java"
        for finding in payload["findings"]
    )
    check = next(
        item
        for item in payload["coverage"]["checks"]
        if item["id"] == "java_workspace_api_surface"
    )
    assert "excluded_workspace_paths" in {reason["code"] for reason in check["reasons"]}
