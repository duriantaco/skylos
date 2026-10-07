"""skylos done precision: changes that look like test tampering and are not.

Each case comes from a false alarm in a study of 450 merged AI-agent pull
requests (feature removal below module level, renamed or merged tests, a
hand-written node:assert runner, brand-new test settings, repository
tooling) or from a missed case (a test overwritten by a test of something
else). Every relaxation is paired with the lookalike that must still block.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from textwrap import dedent

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.done.base import open_comparison
from skylos.done.checks import (
    CheckContext,
    check_test_special_casing,
    check_test_tampering,
)
from skylos.done.config import DoneConfig
from skylos.done.inventory import collect_tests, compare_inventories
from skylos.done.js_inventory import collect_js_tests
from skylos.done.test_config import detect_loosened_test_config


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=root,
        check=True,
        capture_output=True,
    )


def _write(root: Path, files: dict[str, str | None]) -> None:
    for rel, text in files.items():
        path = root / rel
        if text is None:
            path.unlink()
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        assert write_text_no_symlink(path, dedent(text))


def _repo(tmp_path: Path, base: dict, head: dict) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q", "-b", "main")
    _write(root, base)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "base", "--allow-empty")
    _git(root, "switch", "-qc", "feature")
    _write(root, head)
    _git(root, "add", "-A")
    _git(root, "commit", "-qm", "head", "--allow-empty")
    return root


def _ctx(root: Path) -> CheckContext:
    return CheckContext(open_comparison(root, "main"), DoneConfig(), run_tests=False)


def _tampering(tmp_path: Path, base: dict, head: dict):
    return check_test_tampering(_ctx(_repo(tmp_path, base, head)))


def _blocking(result) -> list[str]:
    return [f.message for f in result.findings if f.blocking]


def _advice(result) -> list[str]:
    return [f.message for f in result.findings if not f.blocking]


# ---------------------------------------------------------------------------
# A110: feature removal below module level (Python)
# ---------------------------------------------------------------------------

SERVICE = """\
class IngestionService:
    def render(self, page):
        if self._is_blank_pixmap(page):
            return None
        return page.upper()

    def _is_blank_pixmap(self, page):
        return not page.strip()
"""
SERVICE_TESTS = """\
from app.service import IngestionService


def test_render_uppercases():
    assert IngestionService().render("a") == "A"


def test_blank_pixmap_detection():
    svc = IngestionService()
    assert svc._is_blank_pixmap("  ") is True
    assert svc._is_blank_pixmap("x") is False
"""
WITHOUT_BLANK_TEST = SERVICE_TESTS.split("\n\n\ndef test_blank_pixmap_detection")[0]


def test_a_test_deleted_with_the_method_it_tested_is_feature_removal(tmp_path):
    kept_blank_pages = """\
    class IngestionService:
        def render(self, page):
            return page.upper()
    """
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/service.py": SERVICE,
            "tests/test_service.py": SERVICE_TESTS,
        },
        {
            "app/service.py": kept_blank_pages,
            "tests/test_service.py": WITHOUT_BLANK_TEST + "\n",
        },
    )
    assert result.status == "pass", result.findings
    assert any(
        "feature removal: uses _is_blank_pixmap, which the change removed" in m
        for m in _advice(result)
    )


def test_a_test_deleted_while_its_method_remains_still_blocks(tmp_path):
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/service.py": SERVICE,
            "tests/test_service.py": SERVICE_TESTS,
        },
        {"tests/test_service.py": WITHOUT_BLANK_TEST + "\n"},
    )
    assert result.status == "fail"
    assert any(
        "test_blank_pixmap_detection was deleted" in m for m in _blocking(result)
    )


def test_a_renamed_method_does_not_excuse_deleting_its_test(tmp_path):
    renamed = SERVICE.replace("_is_blank_pixmap", "_is_empty_page")
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/service.py": SERVICE,
            "tests/test_service.py": SERVICE_TESTS,
        },
        {"app/service.py": renamed, "tests/test_service.py": WITHOUT_BLANK_TEST + "\n"},
    )
    assert result.status == "fail"


def test_a_method_still_named_elsewhere_at_head_is_not_removed(tmp_path):
    kept_elsewhere = """\
    class IngestionService:
        def render(self, page):
            return page.upper()
    """
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/service.py": SERVICE,
            "app/legacy.py": "def _is_blank_pixmap(page):\n    return not page\n",
            "tests/test_service.py": SERVICE_TESTS,
        },
        {
            "app/service.py": kept_elsewhere,
            "tests/test_service.py": WITHOUT_BLANK_TEST + "\n",
        },
    )
    assert result.status == "fail"


# ---------------------------------------------------------------------------
# A110: feature removal below module level (JS/TS)
# ---------------------------------------------------------------------------

DEBUG_API = """\
export const debugApi = {
  getClients: () => [],
  getLiveness: () => ({ activeClientCount: 0 }),
};
"""
DEBUG_TESTS = """\
import { debugApi } from "./debug-api";

test("exposes getClients", () => {
  expect(debugApi.getClients()).toEqual([]);
});

test("exposes getLiveness returning a snapshot", () => {
  expect(debugApi.getLiveness()).toHaveProperty("activeClientCount");
});
"""
DEBUG_TESTS_HEAD = DEBUG_TESTS.split('\ntest("exposes getLiveness')[0]


def test_a_js_test_of_a_removed_object_member_is_feature_removal(tmp_path):
    result = _tampering(
        tmp_path,
        {"src/debug-api.ts": DEBUG_API, "src/debug-api.test.ts": DEBUG_TESTS},
        {
            "src/debug-api.ts": DEBUG_API.replace(
                "  getLiveness: () => ({ activeClientCount: 0 }),\n", ""
            ),
            "src/debug-api.test.ts": DEBUG_TESTS_HEAD,
        },
    )
    assert result.status == "pass", result.findings
    assert any("uses debugApi.getLiveness" in m for m in _advice(result))


def test_a_js_test_deleted_while_the_member_remains_still_blocks(tmp_path):
    result = _tampering(
        tmp_path,
        {"src/debug-api.ts": DEBUG_API, "src/debug-api.test.ts": DEBUG_TESTS},
        {"src/debug-api.test.ts": DEBUG_TESTS_HEAD},
    )
    assert result.status == "fail"


OVERLAYS = """\
export function overlay(mode) {
  if (mode === "pressure") {
    return "## Context pressure mode\\nKeep answers short.";
  }
  return "## Default mode";
}
"""
OVERLAY_TESTS = """\
import { overlay } from "./overlays";

test("default overlay", () => {
  expect(overlay("x")).toMatch(/## Default mode/);
});

test("pressure overlay is model-visible", () => {
  expect(overlay("pressure")).toMatch(/## Context pressure mode/u);
});
"""
OVERLAY_TESTS_HEAD = OVERLAY_TESTS.split('\ntest("pressure overlay')[0]


def test_a_js_test_of_removed_text_is_feature_removal(tmp_path):
    removed = """\
    export function overlay(mode) {
      return "## Default mode";
    }
    """
    result = _tampering(
        tmp_path,
        {"src/overlays.mjs": OVERLAYS, "test/overlays.test.mjs": OVERLAY_TESTS},
        {"src/overlays.mjs": removed, "test/overlays.test.mjs": OVERLAY_TESTS_HEAD},
    )
    assert result.status == "pass", result.findings
    assert any("checks '## Context pressure mode'" in m for m in _advice(result))


def test_reworded_text_does_not_excuse_deleting_its_test(tmp_path):
    reworded = OVERLAYS.replace("## Context pressure mode", "## Tight context mode")
    result = _tampering(
        tmp_path,
        {"src/overlays.mjs": OVERLAYS, "test/overlays.test.mjs": OVERLAY_TESTS},
        {"src/overlays.mjs": reworded, "test/overlays.test.mjs": OVERLAY_TESTS_HEAD},
    )
    assert result.status == "fail"


# ---------------------------------------------------------------------------
# A110: renamed, merged and ported tests
# ---------------------------------------------------------------------------


def _js_diff(path: str, base: str, head: str):
    return compare_inventories(
        collect_js_tests(path, dedent(base)).tests,
        collect_js_tests(path, dedent(head)).tests,
    )


def test_a_renamed_test_with_a_new_expected_value_is_not_a_deletion():
    # maps2.0#103: the cap went from 10 to 3; "8 shows 8" became "8 shows 3",
    # as close to its old self as to the surviving "3 shows 3".
    base = """\
    test("3 known results: view all shows 3", () => {
      assert.equal(apply(list(3), cap()).length, 3);
    });
    test("8 known results: view all shows 8", () => {
      assert.equal(apply(list(8), cap()).length, 8);
    });
    """
    head = """\
    test("3 known results: view all shows 3", () => {
      assert.equal(apply(list(3), cap()).length, 3);
    });
    test("8 known results: now shows 3", () => {
      assert.equal(apply(list(8), cap()).length, 3);
    });
    """
    diff = _js_diff("tests/caps.test.mjs", base, head)
    assert not diff.deleted
    assert [r.how for r in diff.rewritten] == ["renamed"]


def test_two_tests_merged_into_one_with_more_assertions_are_not_deleted():
    base = """\
    describe("MarkdownMessage", () => {
      test("first", () => {
        expect(render()).toContain("a");
      });
      test("blockquotes use default styling", () => {
        const html = render("> quoted");
        expect(html).toContain("italic");
        expect(html).not.toContain("rounded");
      });
      test("blockquote previews are compact", () => {
        const html = render("> quoted", "preview");
        expect(html).toContain("rounded");
        expect(html).not.toContain(" italic ");
      });
      test("last", () => {
        expect(render()).toContain("z");
      });
    });
    """
    merged = """\
    describe("MarkdownMessage", () => {
      test("first", () => {
        expect(render()).toContain("a");
      });
      test("blockquotes render as inset blocks", () => {
        const html = render("> quoted");
        expect(html).toContain("rounded");
        expect(html).toContain("flex");
        expect(html).toContain("gap-3");
        expect(html).not.toContain("italic");
      });
      test("last", () => {
        expect(render()).toContain("z");
      });
    });
    """
    diff = _js_diff("src/md.test.tsx", base, merged)
    assert not diff.deleted
    assert sorted(r.how for r in diff.rewritten) == ["in place", "merged"]

    thin = merged.replace(
        '        expect(html).toContain("flex");\n        expect(html).toContain("gap-3");\n',
        "",
    )
    diff = _js_diff("src/md.test.tsx", base, thin)
    assert len(diff.deleted) == 1  # 2 assertions cannot replace 4


HARNESS = """\
const assert = require("node:assert");
const { classify } = require("./privacy-check");

let failed = 0;
function t(name, fn) {
  try {
    fn();
  } catch (e) {
    failed++;
  }
}

t("detects segreto professionale", () => {
  assert.strictEqual(classify("segreto professionale"), "segreto");
});

t("detects work product", () => {
  assert.strictEqual(classify("work product"), "work-product");
});

process.exit(failed === 0 ? 0 : 1);
"""


def test_a_hand_written_node_assert_runner_holds_tests():
    inventory = collect_js_tests("scripts/privacy-check.test.js", dedent(HARNESS))
    assert [t.name for t in inventory.tests] == [
        "detects segreto professionale",
        "detects work product",
    ]
    assert all(t.assertions == 1 for t in inventory.tests)


def test_a_runner_that_swallows_failures_without_an_exit_code_holds_no_tests():
    swallowing = HARNESS.replace("process.exit(failed === 0 ? 0 : 1);\n", "")
    inventory = collect_js_tests("scripts/privacy-check.test.js", dedent(swallowing))
    assert inventory.tests == []


def test_jest_tests_ported_to_a_node_assert_runner_are_not_deleted():
    jest = """\
    const { classify } = require("./privacy-check");

    describe("classify", () => {
      test("detects segreto professionale", () => {
        expect(classify("segreto professionale")).toBe("segreto");
      });
      test("detects work product", () => {
        expect(classify("work product")).toBe("work-product");
      });
    });
    """
    diff = _js_diff("scripts/privacy-check.test.js", jest, HARNESS)
    assert not diff.deleted
    assert {r.how for r in diff.rewritten} == {"moved"}


# ---------------------------------------------------------------------------
# A110: a test overwritten in place by a test of something else
# ---------------------------------------------------------------------------

CFN = """\
RESOURCES = {
    "AWS::EC2::VPCEndpoint": "vpc_endpoint",
    "AWS::AppSync::FunctionConfiguration": "appsync_function",
}


def provision(kind):
    return RESOURCES[kind]
"""
CFN_TESTS = """\
from app.cfn import provision


def test_cfn_launch_template():
    assert provision("AWS::EC2::LaunchTemplate") is None


def test_cfn_vpc_endpoint_uses_ec2_state(ec2):
    endpoint = provision("AWS::EC2::VPCEndpoint")
    assert ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint])
    assert endpoint.startswith("vpce-")


def test_cfn_stack_outputs():
    assert provision("AWS::CloudFormation::Stack") is None
"""
OVERWRITTEN = CFN_TESTS.replace(
    """def test_cfn_vpc_endpoint_uses_ec2_state(ec2):
    endpoint = provision("AWS::EC2::VPCEndpoint")
    assert ec2.describe_vpc_endpoints(VpcEndpointIds=[endpoint])
    assert endpoint.startswith("vpce-")""",
    """def test_cfn_appsync_function_configuration(appsync):
    function = provision("AWS::AppSync::FunctionConfiguration")
    assert appsync.get_function(functionId=function)
    assert function.endswith("_function")""",
)


def test_a_test_overwritten_by_a_test_of_something_else_blocks(tmp_path):
    result = _tampering(
        tmp_path,
        {"app/__init__.py": "", "app/cfn.py": CFN, "tests/test_cfn.py": CFN_TESTS},
        {"tests/test_cfn.py": OVERWRITTEN},
    )
    assert result.status == "fail"
    assert any(
        "test_cfn_vpc_endpoint_uses_ec2_state was overwritten in place" in m
        for m in _blocking(result)
    )


def test_an_overwritten_test_whose_subject_was_removed_is_advice(tmp_path):
    without_vpc = CFN.replace('    "AWS::EC2::VPCEndpoint": "vpc_endpoint",\n', "")
    result = _tampering(
        tmp_path,
        {"app/__init__.py": "", "app/cfn.py": CFN, "tests/test_cfn.py": CFN_TESTS},
        {"app/cfn.py": without_vpc, "tests/test_cfn.py": OVERWRITTEN},
    )
    assert result.status == "pass", result.findings


def test_a_test_rewritten_in_place_for_the_same_subject_is_advice(tmp_path):
    edited = CFN_TESTS.replace(
        """def test_cfn_vpc_endpoint_uses_ec2_state(ec2):
    endpoint = provision("AWS::EC2::VPCEndpoint")""",
        """def test_cfn_vpc_endpoint_keeps_its_id(ec2):
    endpoint = provision("AWS::EC2::VPCEndpoint").lower()""",
    )
    result = _tampering(
        tmp_path,
        {"app/__init__.py": "", "app/cfn.py": CFN, "tests/test_cfn.py": CFN_TESTS},
        {"tests/test_cfn.py": edited},
    )
    assert result.status == "pass", result.findings


# ---------------------------------------------------------------------------
# A112: brand-new settings, new scripts, tests moved to their own CI step
# ---------------------------------------------------------------------------


def _config_messages(tmp_path: Path, base: dict, head: dict) -> list[str]:
    root = _repo(tmp_path, base, head)
    return [
        f.message for f in detect_loosened_test_config(open_comparison(root, "main"))
    ]


NEW_PYPROJECT = """\
[project]
name = "netmon"

[tool.pytest.ini_options]
testpaths = ["tests"]
"""


def test_testpaths_in_a_new_pyproject_that_drop_no_existing_test_are_fine(tmp_path):
    base = {"tests/test_probe.py": "def test_probe():\n    assert True\n"}
    assert _config_messages(tmp_path, base, {"pyproject.toml": NEW_PYPROJECT}) == []


def test_testpaths_in_a_new_pyproject_that_drop_an_existing_test_are_reported(
    tmp_path,
):
    base = {
        "tests/test_probe.py": "def test_probe():\n    assert True\n",
        "integration/test_live.py": "def test_live():\n    assert True\n",
    }
    messages = _config_messages(tmp_path, base, {"pyproject.toml": NEW_PYPROJECT})
    assert messages == ["pytest testpaths now restrict collection to 'tests'"]


def test_testpaths_added_to_an_existing_pyproject_are_still_compared_as_lists(
    tmp_path,
):
    base = {
        "pyproject.toml": '[project]\nname = "netmon"\n',
        "tests/test_probe.py": "def test_probe():\n    assert True\n",
    }
    messages = _config_messages(tmp_path, base, {"pyproject.toml": NEW_PYPROJECT})
    assert messages == ["pytest testpaths now restrict collection to 'tests'"]


def test_a_first_test_script_is_not_a_loosening(tmp_path):
    base = {"package.json": '{"name": "x", "scripts": {"build": "tsc"}}\n'}
    head = {
        "package.json": '{"name": "x", "scripts": {"build": "tsc", '
        '"test": "node --test tests/*.test.ts"}}\n'
    }
    assert _config_messages(tmp_path, base, head) == []


INTEGRATION_BASE = {
    "package.json": '{"name": "x", "scripts": {"test": "jest"}}\n',
    "src/__tests__/env.test.ts": "test('env', () => { expect(1).toBe(1); });\n",
}
INTEGRATION_HEAD = {
    "package.json": (
        '{"name": "x", "scripts": {'
        '"test": "jest --testPathIgnorePatterns=integration", '
        '"test:integration": "jest --testPathPattern=integration"}}\n'
    ),
}
CI = """\
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: npm test
"""


def test_an_ignore_pattern_that_drops_no_existing_test_is_fine(tmp_path):
    head = {
        **INTEGRATION_HEAD,
        "src/__tests__/integration.test.ts": "test('live', () => { expect(1).toBe(1); });\n",
    }
    assert _config_messages(tmp_path, INTEGRATION_BASE, head) == []


def test_ignored_tests_that_run_in_their_own_ci_step_are_fine(tmp_path):
    base = {
        **INTEGRATION_BASE,
        "src/__tests__/integration.test.ts": "test('live', () => { expect(1).toBe(1); });\n",
        ".github/workflows/ci.yml": CI,
    }
    with_step = CI + "      - run: npm run test:integration\n"
    assert (
        _config_messages(
            tmp_path, base, {**INTEGRATION_HEAD, ".github/workflows/ci.yml": with_step}
        )
        == []
    )


def test_ignored_existing_tests_that_no_ci_step_runs_are_reported(tmp_path):
    base = {
        **INTEGRATION_BASE,
        "src/__tests__/integration.test.ts": "test('live', () => { expect(1).toBe(1); });\n",
        ".github/workflows/ci.yml": CI,
    }
    messages = _config_messages(tmp_path, base, INTEGRATION_HEAD)
    assert messages == [
        "package.json script 'test' now ignores test paths "
        "(--testPathIgnorePatterns) 'integration'"
    ]


def test_a_new_advisory_ci_step_is_not_a_loosened_test_step(tmp_path):
    base = {
        ".github/workflows/ci.yml": CI.replace("npm test", "pytest"),
    }
    added = CI.replace("npm test", "pytest") + (
        "      - name: Auto fix\n"
        "        run: python tools/self_repair.py --test-cmd 'npm run test' --dry-run\n"
        "        continue-on-error: true\n"
    )
    assert _config_messages(tmp_path, base, {".github/workflows/ci.yml": added}) == []


def test_an_existing_test_step_renamed_and_made_quiet_is_reported(tmp_path):
    base = {".github/workflows/ci.yml": CI.replace("npm test", "pytest")}
    quiet = CI.replace(
        "      - run: npm test\n",
        "      - name: Tests (flaky)\n        run: pytest\n        continue-on-error: true\n",
    )
    messages = _config_messages(tmp_path, base, {".github/workflows/ci.yml": quiet})
    assert len(messages) == 1 and "continue-on-error" in messages[0]


# ---------------------------------------------------------------------------
# A116: repository tooling that reads test files
# ---------------------------------------------------------------------------

SMOKE_TEST = """\
import test from "node:test";
test("quality gate fixture covers retries", () => {});
"""
VALIDATOR = """\
import { readFileSync } from "node:fs";
const smoke = readFileSync("tests/smoke.test.mjs", "utf8");
if (!smoke.includes("covers retries")) {
  throw new Error("FIXTURE_COVERAGE_MISSING");
}
"""


@pytest.mark.parametrize(
    "path", ["scripts/validate-workflow.mjs", "tools/check-fixtures.mjs"]
)
def test_repository_tooling_that_reads_a_test_file_is_advice(tmp_path, path):
    root = _repo(
        tmp_path,
        {"tests/smoke.test.mjs": SMOKE_TEST, "src/app.mjs": "export const x = 1;\n"},
        {path: VALIDATOR, "src/app.mjs": "export const x = 2;\n"},
    )
    result = check_test_special_casing(_ctx(root))
    reads = [f for f in result.findings if "reads the test file" in f.message]
    assert reads and not any(f.blocking for f in reads), result.findings


def test_production_code_or_imported_tooling_that_reads_a_test_file_blocks(tmp_path):
    root = _repo(
        tmp_path,
        {
            "tests/smoke.test.mjs": SMOKE_TEST,
            "src/app.mjs": "export const x = 1;\n",
            "src/answers.mjs": "export const y = 1;\n",
            "scripts/validate-workflow.mjs": "export const ok = true;\n",
        },
        {
            "scripts/validate-workflow.mjs": VALIDATOR,
            "src/app.mjs": 'import "../scripts/validate-workflow.mjs";\nexport const x = 2;\n',
            "src/answers.mjs": VALIDATOR,
        },
    )
    result = check_test_special_casing(_ctx(root))
    blocked = {f.file for f in result.findings if f.blocking}
    assert {"scripts/validate-workflow.mjs", "src/answers.mjs"} <= blocked, (
        result.findings
    )


def test_python_collect_tests_is_unchanged_for_plain_files():
    # The harness reading is JS only; Python collection is unaffected.
    assert collect_tests("tests/test_a.py", "def test_a():\n    assert 1\n")


def test_an_overwrite_whose_new_title_names_the_old_subject_is_advice(tmp_path):
    # skylos-cloud 9a0a7cb: "gates previous scan fetches" became "no longer
    # fetches previous-scan findings"; the old helper is still in the code.
    overview = """\
    def fetch_previous_scan(project):
        return project["previous"]


    def overview(project):
        return {"latest": project["latest"]}
    """
    tests = """\
    from app.overview import fetch_previous_scan, overview


    def test_overview_lists_latest():
        assert overview({"latest": 1}) == {"latest": 1}


    def test_previous_scan_fetch_is_gated():
        project = {"previous": "scan-7", "entitlement": "compare"}
        assert fetch_previous_scan(project) == "scan-7"
        assert project["entitlement"] == "compare"


    def test_overview_title():
        assert overview({"latest": 2})["latest"] == 2
    """
    rewritten = tests.replace(
        '''def test_previous_scan_fetch_is_gated():
        project = {"previous": "scan-7", "entitlement": "compare"}
        assert fetch_previous_scan(project) == "scan-7"
        assert project["entitlement"] == "compare"''',
        """def test_overview_page_never_does_a_previous_scan_fetch_at_all_now():
        for latest in range(3):
            assert overview({"latest": latest}).keys() == {"latest"}""",
    )
    result = _tampering(
        tmp_path,
        {
            "app/__init__.py": "",
            "app/overview.py": overview,
            "tests/test_overview.py": tests,
        },
        {"tests/test_overview.py": rewritten},
    )
    assert result.status == "pass", result.findings


def test_mock_assertions_with_literal_arguments_count():
    items = collect_tests(
        "tests/test_mock.py",
        dedent(
            """
            def test_sends_once(mailer):
                mailer.send.assert_called_once_with("ops@example.com", retries=3)

            def test_not_called(mailer):
                mailer.send.assert_not_called()

            class TestMailer:
                def test_self_helper_with_constants_is_not_a_check(self):
                    self.assert_called_with(1, 1)
            """
        ),
    )
    counts = {item.name: item.assertions for item in items}
    assert counts["test_sends_once"] == 1
    assert counts["test_not_called"] == 1
    assert counts["test_self_helper_with_constants_is_not_a_check"] == 0
