from __future__ import annotations

import json

import pytest

from skylos.analyzer import Skylos, analyze
from skylos.visitors.languages.php import scan_php_file
from skylos.visitors.languages.php import drupal


@pytest.fixture(params=["new-instance", "reused-instance"])
def scan_project(request):
    if request.param == "reused-instance":
        scanner = Skylos()
    else:
        scanner = None

    def scan(root, *, grep_cache):
        if scanner is not None:
            run = scanner.analyze
        else:
            run = analyze
        result = json.loads(run(str(root), grep_cache=grep_cache, trace_file=False))
        assert not result.get("analysis_errors", [])
        assert "_demo_unused" in {
            finding["simple_name"] for finding in result.get("unused_functions", [])
        }
        return result

    return scan


@pytest.mark.parametrize("grep_cache", [False, True])
@pytest.mark.parametrize("initially_registered", [False, True])
def test_changed_service_registrations_refresh_each_scan(
    tmp_path, scan_project, grep_cache, initially_registered
):
    root = tmp_path / "demo"
    (root / "src").mkdir(parents=True)
    (root / "demo.info.yml").write_text("name: Demo\ntype: module\n", encoding="utf-8")
    (root / "src" / "Thing.php").write_text(
        "<?php\nnamespace Drupal\\demo;\nclass Thing {\n"
        "  public function run(): void {}\n}\n",
        encoding="utf-8",
    )
    (root / "demo.module").write_text(
        "<?php\nfunction _demo_unused(): void {}\n", encoding="utf-8"
    )
    services = root / "demo.services.yml"
    for registered in (initially_registered, not initially_registered):
        if registered:
            service_yaml = "services:\n  demo.thing:\n    class: Drupal\\demo\\Thing\n"
        else:
            service_yaml = "services: {}\n"
        services.write_text(service_yaml, encoding="utf-8")
        result = scan_project(root, grep_cache=grep_cache)
        unused = {
            finding["simple_name"] for finding in result.get("unused_classes", [])
        }
        assert ("Thing" in unused) is not registered


@pytest.mark.parametrize("grep_cache", [False, True])
@pytest.mark.parametrize("initially_extension", [False, True])
def test_created_or_removed_extension_metadata_refreshes_each_scan(
    tmp_path, scan_project, grep_cache, initially_extension
):
    root = tmp_path / "demo"
    root.mkdir()
    (root / "demo.module").write_text(
        "<?php\nfunction demo_form_alter(&$form): void {}\n"
        "function _demo_unused(): void {}\n",
        encoding="utf-8",
    )
    info = root / "demo.info.yml"
    for is_extension in (initially_extension, not initially_extension):
        if is_extension:
            info.write_text("name: Demo\ntype: module\n", encoding="utf-8")
        elif info.exists():
            info.unlink()
        result = scan_project(root, grep_cache=grep_cache)
        unused = {
            finding["simple_name"] for finding in result.get("unused_functions", [])
        }
        assert ("demo_form_alter" in unused) is not is_extension


def _direct_roots(path):
    definitions, _, _, _, _, framework, *_ = scan_php_file(str(path), {})
    assert definitions
    roots = {
        definition.simple_name
        for definition in definitions
        if definition.line in framework.framework_decorated_lines
    }
    assert "_demo_unused" not in roots
    return roots


@pytest.mark.parametrize("initially_registered", [False, True])
def test_direct_php_scans_refresh_service_registrations(tmp_path, initially_registered):
    root = tmp_path / "demo"
    (root / "src").mkdir(parents=True)
    (root / "demo.info.yml").write_text("name: Demo\ntype: module\n", encoding="utf-8")
    path = root / "src" / "Thing.php"
    path.write_text(
        "<?php\nnamespace Drupal\\demo;\nclass Thing {\n"
        "  public function run(): void {}\n}\n"
        "function _demo_unused(): void {}\n",
        encoding="utf-8",
    )
    for registered in (initially_registered, not initially_registered):
        if registered:
            service_yaml = "services:\n  demo.thing:\n    class: Drupal\\demo\\Thing\n"
        else:
            service_yaml = "services: {}\n"
        (root / "demo.services.yml").write_text(service_yaml, encoding="utf-8")
        roots = _direct_roots(path)
        assert ("Thing" in roots) is registered
        assert ("run" in roots) is registered


@pytest.mark.parametrize("initially_extension", [False, True])
def test_direct_php_scans_refresh_extension_metadata(tmp_path, initially_extension):
    root = tmp_path / "demo"
    root.mkdir()
    path = root / "demo.module"
    path.write_text(
        "<?php\nfunction demo_form_alter(&$form): void {}\n"
        "function _demo_unused(): void {}\n",
        encoding="utf-8",
    )
    info = root / "demo.info.yml"
    for is_extension in (initially_extension, not initially_extension):
        if is_extension:
            info.write_text("name: Demo\ntype: module\n", encoding="utf-8")
        elif info.exists():
            info.unlink()
        roots = _direct_roots(path)
        assert ("demo_form_alter" in roots) is is_extension


def test_analyzer_reuses_metadata_across_files_in_one_run(tmp_path, monkeypatch):
    root = tmp_path / "demo"
    (root / "src").mkdir(parents=True)
    (root / "demo.info.yml").write_text("name: Demo\ntype: module\n", encoding="utf-8")
    service_yaml = "services:\n"
    for name in ("First", "Second"):
        service_yaml += f"  demo.{name}:\n    class: Drupal\\demo\\{name}\n"
        (root / "src" / f"{name}.php").write_text(
            f"<?php\nnamespace Drupal\\demo;\nclass {name} {{}}\n",
            encoding="utf-8",
        )
    (root / "demo.services.yml").write_text(service_yaml, encoding="utf-8")

    walks = []
    original_yaml_files = drupal._yaml_files

    def count_yaml_walks(directory):
        walks.append(directory)
        yield from original_yaml_files(directory)

    monkeypatch.setattr(drupal, "_yaml_files", count_yaml_walks)
    result = json.loads(
        analyze(str(root), grep_verify=False, grep_cache=False, trace_file=False)
    )

    assert not result.get("analysis_errors", [])
    assert result.get("unused_classes", []) == []
    assert result["analysis_summary"]["total_files"] == 2
    assert walks == [str(root)]
