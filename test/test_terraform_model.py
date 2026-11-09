import json
import sys

import pytest

from skylos.rules.config.terraform.model import Unknown, is_unknown, load_project


def _write(root, name, text):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_native_resources_preserve_types_locations_and_nested_blocks(tmp_path):
    path = _write(
        tmp_path,
        "main.tf",
        """
resource "aws_security_group" "admin" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""",
    )
    project = load_project(tmp_path)
    assert project.analysis_errors == []
    assert project.coverage["files_parsed"] == 1
    assert project.coverage["status"] == "complete"
    resource = project.resources[0]
    assert (resource.resource_type, resource.name, resource.file, resource.line) == (
        "aws_security_group",
        "admin",
        str(path),
        2,
    )
    assert project.resolve(resource.attributes["ingress"], resource) == [
        {
            "from_port": 22,
            "to_port": 22,
            "protocol": "tcp",
            "cidr_blocks": ["0.0.0.0/0"],
        }
    ]
    assert project.aws_provider_status(resource) is True


def test_cross_file_locals_and_finite_indexes_resolve_without_defaults(tmp_path):
    _write(
        tmp_path,
        "locals.tf",
        "locals { flags = { encrypted = false } ports = [22, 3389] }\n",
    )
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { storage_encrypted = local.flags.encrypted port = local.ports[1] }\n',
    )
    project = load_project(tmp_path)
    resource = project.resources[0]
    assert project.resolve(resource.attributes["storage_encrypted"], resource) is False
    assert project.resolve(resource.attributes["port"], resource) == 3389
    assert project.coverage["files_parsed"] == 2
    assert project.analysis_errors == []


@pytest.mark.parametrize(
    "expression",
    [
        "var.enabled",
        "data.aws_vpc.main.id",
        "module.db.encrypted",
        "coalesce(var.enabled, true)",
        '"prefix-${var.enabled}"',
    ],
)
def test_external_inputs_and_unsupported_expressions_are_unknown(tmp_path, expression):
    _write(
        tmp_path,
        "main.tf",
        'variable "enabled" { default = true }\nresource "aws_db_instance" "db" { storage_encrypted = '
        + expression
        + " }\n",
    )
    project = load_project(tmp_path)
    resource = project.resources[0]
    assert is_unknown(
        project.resolve(resource.attributes["storage_encrypted"], resource)
    )
    assert project.coverage["unresolved_resolution_attempts"] > 0


def test_literal_reference_lookalikes_are_not_evaluated(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        'locals { flag = false }\nresource "aws_db_instance" "db" { note = "local.flag" literal = "$${local.flag}" }\n',
    )
    project = load_project(tmp_path)
    resource = project.resources[0]
    assert project.resolve(resource.attributes["note"], resource) == "local.flag"
    assert project.resolve(resource.attributes["literal"], resource) == "${local.flag}"


def test_json_configuration_resolves_reference_and_keeps_native_values(tmp_path):
    _write(
        tmp_path,
        "main.tf.json",
        json.dumps(
            {
                "locals": {"enabled": False},
                "resource": {
                    "aws_db_instance": {"db": {"storage_encrypted": "${local.enabled}"}}
                },
            }
        ),
    )
    project = load_project(tmp_path)
    resource = project.resources[0]
    assert project.resolve(resource.attributes["storage_encrypted"], resource) is False
    assert project.coverage["files_parsed"] == 1
    assert project.analysis_errors == []


def test_nested_modules_do_not_share_local_bindings(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        'locals { enabled = false }\nresource "aws_db_instance" "root" { storage_encrypted = local.enabled }\n',
    )
    _write(
        tmp_path,
        "child/main.tf",
        'resource "aws_db_instance" "child" { storage_encrypted = local.enabled }\n',
    )
    project = load_project(tmp_path)
    root = next(r for r in project.resources if r.name == "root")
    child = next(r for r in project.resources if r.name == "child")
    assert project.resolve(root.attributes["storage_encrypted"], root) is False
    assert is_unknown(project.resolve(child.attributes["storage_encrypted"], child))
    assert project.coverage["modules"] == 2


@pytest.mark.parametrize(
    "text",
    [
        'resource "aws_db_instance" "db" {',
        "locals { flag=true flag=false }",
        'resource "aws_db_instance" "db" {}\nresource "aws_db_instance" "db" {}',
        "locals { flag=true }\nlocals { flag=false }",
    ],
)
def test_invalid_or_ambiguous_native_inputs_are_incomplete(tmp_path, text):
    _write(tmp_path, "main.tf", text)
    project = load_project(tmp_path)
    assert project.analysis_errors
    assert project.coverage["status"] == "incomplete"


@pytest.mark.parametrize(
    "text",
    ['{"locals":{"x":true,"x":false}}', '{"locals":{"x":NaN}}', '{"resource": []}'],
)
def test_ambiguous_or_invalid_json_configuration_is_incomplete(tmp_path, text):
    _write(tmp_path, "main.tf.json", text)
    project = load_project(tmp_path)
    assert project.analysis_errors
    assert project.coverage["status"] == "incomplete"


def test_missing_parser_is_not_clean_absence(tmp_path, monkeypatch):
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { storage_encrypted=false }\n',
    )
    monkeypatch.setitem(sys.modules, "hcl2", None)
    project = load_project(tmp_path)
    assert project.resources == []
    assert project.coverage["files_parsed"] == 0
    assert any(
        e["kind"] == "terraform_parser_unavailable" for e in project.analysis_errors
    )


def test_provider_source_and_alias_identity_are_not_inferred_from_prefix(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        """
terraform { required_providers { aws = { source = "example/custom" } cloud = { source = "hashicorp/aws" } } }
provider "cloud" { alias = "west" }
resource "aws_db_instance" "custom" { storage_encrypted = false }
resource "aws_db_instance" "official" { provider = cloud.west storage_encrypted = false }
resource "aws_db_instance" "missing" { provider = cloud.east storage_encrypted = false }
""",
    )
    project = load_project(tmp_path)
    resources = {r.name: r for r in project.resources}
    assert project.aws_provider_status(resources["custom"]) is False
    assert project.aws_provider_status(resources["official"]) is True
    assert project.aws_provider_status(resources["missing"]) is None


@pytest.mark.parametrize(
    ("meta", "status"),
    [
        ("", "present"),
        ("count=0", "absent"),
        ("count=2", "present"),
        ("count=var.n", "unknown"),
        ("for_each={}", "absent"),
        ('for_each={one="x"}', "present"),
        ("count=1 for_each={}", "unknown"),
    ],
)
def test_instance_presence_is_distinct_from_unknown(tmp_path, meta, status):
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { ' + meta + " storage_encrypted=false }\n",
    )
    project = load_project(tmp_path)
    assert project.instance_status(project.resources[0]) == status


def test_local_cycles_and_depth_exhaustion_are_unknown(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        'locals { a=local.b b=local.a }\nresource "aws_db_instance" "db" { storage_encrypted=local.a }\n',
    )
    project = load_project(tmp_path)
    assert is_unknown(
        project.resolve(
            project.resources[0].attributes["storage_encrypted"], project.resources[0]
        )
    )
    with pytest.raises(TypeError):
        bool(Unknown("unresolved"))


def test_excludes_downloaded_modules_and_symlinks(tmp_path):
    _write(tmp_path, "main.tf", 'resource "aws_db_instance" "visible" {}\n')
    _write(
        tmp_path,
        ".terraform/modules/main.tf",
        'resource "aws_db_instance" "downloaded" {}\n',
    )
    _write(tmp_path, "vendor/main.tf", 'resource "aws_db_instance" "vendored" {}\n')
    _write(tmp_path, "examples/main.tf", 'resource "aws_db_instance" "excluded" {}\n')
    (tmp_path / "alias.tf").symlink_to(tmp_path / "main.tf")
    project = load_project(tmp_path, exclude_folders=["examples"])
    assert [r.name for r in project.resources] == ["visible"]
    assert project.coverage["files_parsed"] == 1


def test_changed_local_file_selects_its_whole_module(tmp_path):
    locals_path = _write(tmp_path, "locals.tf", "locals { enabled=false }\n")
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { storage_encrypted=local.enabled }\n',
    )
    _write(tmp_path, "other/main.tf", 'resource "aws_db_instance" "other" {}\n')
    project = load_project(tmp_path, changed_files={str(locals_path)})
    assert [r.name for r in project.resources] == ["db"]
    assert project.coverage["files_parsed"] == 2


def test_non_terraform_file_target_does_not_select_neighbor_configuration(tmp_path):
    target = _write(tmp_path, "app.py", "pass\n")
    _write(tmp_path, "main.tf", 'resource "aws_db_instance" "db" {}\n')
    project = load_project(target)
    assert project.resources == []
    assert project.coverage["status"] == "not_applicable"


@pytest.mark.parametrize("key", ["(var.key)", '"${var.key}"'])
def test_dynamic_object_keys_cannot_prove_literal_local_field(tmp_path, key):
    _write(
        tmp_path,
        "main.tf",
        "locals { options = { encrypted=false " + key + "=true } }\n"
        'resource "aws_db_instance" "db" { storage_encrypted=local.options.encrypted }\n',
    )
    project = load_project(tmp_path)
    resource = project.resources[0]
    assert is_unknown(
        project.resolve(resource.attributes["storage_encrypted"], resource)
    )


@pytest.mark.parametrize("other", ["broken.tf", "override.tf", "main_override.tf.json"])
def test_partial_or_override_module_is_not_evaluated_as_complete(tmp_path, other):
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { storage_encrypted=false }\n',
    )
    _write(tmp_path, other, "{" if other == "broken.tf" else "{}")
    project = load_project(tmp_path)
    resource = project.resources[0]
    assert project.coverage["status"] == "incomplete"
    assert project.analysis_errors
    assert project.aws_provider_status(resource) is None
    assert project.instance_status(resource) == "unknown"
    assert is_unknown(
        project.resolve(resource.attributes["storage_encrypted"], resource)
    )


def test_excluded_configuration_file_cannot_hide_provider_binding(tmp_path):
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { storage_encrypted=false }\n',
    )
    _write(
        tmp_path,
        "providers.tf",
        'terraform { required_providers { aws={source="custom/aws"} } }\n',
    )
    project = load_project(tmp_path, exclude_folders=["providers.tf"])
    assert project.aws_provider_status(project.resources[0]) is None
    assert project.coverage["status"] == "incomplete"


def test_read_failure_does_not_leave_neighbor_module_implicitly_official(
    tmp_path, monkeypatch
):
    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { storage_encrypted=false }\n',
    )
    unreadable = _write(tmp_path, "providers.tf", "")
    import skylos.rules.config.terraform.model as model

    original = model.read_project_text_no_symlink

    def read_failure(root, path, *args, **kwargs):
        if path == unreadable:
            raise OSError("fixture unavailable")
        return original(root, path, *args, **kwargs)

    monkeypatch.setattr(model, "read_project_text_no_symlink", read_failure)
    project = load_project(tmp_path)
    assert project.aws_provider_status(project.resources[0]) is None
    assert any(
        e["kind"] == "terraform_source_read_error" for e in project.analysis_errors
    )


def test_resolution_budget_and_failed_scan_do_not_poison_next_project(
    tmp_path, monkeypatch
):
    import skylos.rules.config.terraform.model as model

    _write(
        tmp_path,
        "main.tf",
        'resource "aws_db_instance" "db" { storage_encrypted=false }\n',
    )
    project = load_project(tmp_path)
    resource = project.resources[0]
    monkeypatch.setattr(model, "MAX_RESOLVE_WORK", 1)
    assert is_unknown(project.resolve([False], resource)[0])
    assert project.resolve(False, resource) is False
    monkeypatch.setattr(model, "MAX_FILE_BYTES", 1)
    failed = load_project(tmp_path)
    assert failed.coverage["status"] == "incomplete"
    monkeypatch.setattr(model, "MAX_FILE_BYTES", 2 * 1024 * 1024)
    assert load_project(tmp_path).coverage["status"] == "complete"


def test_json_resource_location_uses_declaration_not_first_line(tmp_path):
    _write(
        tmp_path,
        "main.tf.json",
        '{\n "resource": {\n  "aws_db_instance": {\n   "db": {"storage_encrypted":false}\n  }\n }\n}\n',
    )
    project = load_project(tmp_path)
    assert project.resources[0].line == 4


@pytest.mark.parametrize(
    "text",
    [
        "invalid=true",
        'resource "aws_security_group" "sg" { ingress=[] ingress { from_port=22 } }',
    ],
)
def test_native_invalid_structure_is_explicitly_incomplete(tmp_path, text):
    _write(tmp_path, "main.tf", text)
    project = load_project(tmp_path)
    assert project.coverage["status"] == "incomplete"
    assert project.analysis_errors


def test_invalid_neighbor_module_does_not_poison_valid_module(tmp_path):
    _write(
        tmp_path, "main.tf", 'resource "aws_db_instance" "db" {storage_encrypted=false}'
    )
    _write(tmp_path, "broken/main.tf", "{")
    project = load_project(tmp_path)
    resource = project.resources[0]
    assert project.coverage["status"] == "incomplete"
    assert project.aws_provider_status(resource) is True
    assert project.resolve(resource.attributes["storage_encrypted"], resource) is False


def test_scope_selection_canonicalizes_ancestor_aliases_not_final_symlinks(tmp_path):
    module = tmp_path / "module"
    target = _write(module, "main.tf", 'resource "aws_db_instance" "db" {}\n')
    alias = tmp_path / "module_alias"
    alias.symlink_to(module, target_is_directory=True)
    project = load_project(module, scan_paths=[alias / "main.tf"])
    assert [resource.name for resource in project.resources] == ["db"]
    assert project.resources[0].file == str(target)
    assert project.coverage["files_parsed"] == 1
    assert project.analysis_errors == []
    assert load_project(alias).coverage["status"] == "incomplete"
    final_alias = tmp_path / "alias.tf"
    final_alias.symlink_to(target)
    assert load_project(final_alias).coverage["status"] == "incomplete"


@pytest.mark.parametrize("source", ["example/database/aws", "./child"])
def test_module_invocations_remain_unknown_even_with_local_declarations(
    tmp_path, source
):
    path = _write(
        tmp_path,
        "main.tf",
        '\nmodule "database" { source="' + source + '" }\n',
    )
    _write(tmp_path, "child/main.tf", 'resource "aws_db_instance" "db" {}\n')
    project = load_project(tmp_path)
    calls = project.coverage["module_calls"]
    assert len(calls) == 1
    assert calls[0]["name"] == "database"
    assert calls[0]["file"] == str(path)
    assert calls[0]["line"] == 2
    assert calls[0]["source"] == source
    assert calls[0]["source_kind"] == (
        "local" if source.startswith("./") else "external"
    )
    assert calls[0]["status"] == "unknown"
    assert calls[0]["reason"]
    assert [resource.name for resource in project.resources] == ["db"]
    assert project.analysis_errors == []


def test_json_module_invocation_has_exact_source_location_and_unknown_inputs(tmp_path):
    path = _write(
        tmp_path,
        "main.tf.json",
        '{\n "module": {\n  "database": {"source":"${var.source}"}\n }\n}\n',
    )
    project = load_project(tmp_path)
    assert project.coverage["module_calls"] == [
        {
            "name": "database",
            "file": str(path),
            "line": 3,
            "source": None,
            "source_kind": "unknown",
            "status": "unknown",
            "reason": "Module invocation, inputs and provider bindings are not evaluated",
        }
    ]
    assert project.coverage["resources"] == 0


def test_resource_only_module_has_no_unevaluated_module_calls(tmp_path):
    _write(tmp_path, "main.tf", 'resource "aws_db_instance" "db" {}\n')
    assert load_project(tmp_path).coverage["module_calls"] == []


def test_leaf_symlink_swap_after_discovery_never_reads_external_resource(
    tmp_path, monkeypatch
):
    import skylos.rules.config.terraform.model as model

    module = tmp_path / "module"
    target = _write(module, "main.tf", 'resource "aws_db_instance" "inside" {}\n')
    external = _write(
        tmp_path, "external.tf", 'resource "aws_db_instance" "outside" {}\n'
    )
    discover = model._discover

    def swapped_discovery(*args, **kwargs):
        paths = discover(*args, **kwargs)
        target.unlink()
        target.symlink_to(external)
        return paths

    monkeypatch.setattr(model, "_discover", swapped_discovery)
    project = model.load_project(module)
    assert project.resources == []
    assert project.coverage["status"] == "incomplete"
    assert any(
        e["kind"] == "terraform_source_read_error" for e in project.analysis_errors
    )


def test_fifo_source_is_rejected_without_waiting_for_writer(tmp_path):
    import os
    import subprocess
    import sys

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO fixture requires POSIX")
    os.mkfifo(tmp_path / "special.tf")
    code = (
        "import sys; from skylos.rules.config.terraform.model import load_project; "
        "project=load_project(sys.argv[1]); "
        "assert not project.resources; "
        "assert any(e['kind']=='terraform_source_read_error' for e in project.analysis_errors)"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", code, str(tmp_path)],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("Terraform FIFO input waited for a writer")
    assert result.returncode == 0, result.stderr


def test_direct_fifo_root_is_incomplete_without_opening(tmp_path):
    import os

    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFO fixture requires POSIX")
    path = tmp_path / "special.tf"
    os.mkfifo(path)
    project = load_project(path)
    assert project.resources == []
    assert any(
        e["kind"] == "terraform_source_read_error" for e in project.analysis_errors
    )


def test_symlink_loop_root_stays_explicitly_incomplete(tmp_path):
    path = tmp_path / "loop"
    path.symlink_to(path, target_is_directory=True)
    project = load_project(path)
    assert project.resources == []
    assert project.coverage["status"] == "incomplete"
    assert any(e["kind"] == "terraform_scope_error" for e in project.analysis_errors)


def test_bounded_reader_preserves_bom_and_rejects_invalid_utf8(tmp_path):
    path = tmp_path / "main.tf"
    path.write_bytes(b'\xef\xbb\xbfresource "aws_db_instance" "db" {}\r\n')
    project = load_project(tmp_path)
    assert [resource.name for resource in project.resources] == ["db"]
    assert project.analysis_errors == []
    path.write_bytes(b'\xffresource "aws_db_instance" "db" {}')
    project = load_project(tmp_path)
    assert project.resources == []
    assert any(
        e["kind"] == "terraform_source_read_error" for e in project.analysis_errors
    )


def test_optional_directory_discovery_is_partial_coverage_not_global_error(
    tmp_path, monkeypatch
):
    import skylos.rules.config.terraform.model as model

    _write(tmp_path, "app.py", "VALUE=1\n")
    hidden = tmp_path / "hidden"

    def incomplete_walk(root, *, onerror, **kwargs):
        yield str(tmp_path), ["hidden"], ["app.py"]
        onerror(PermissionError(13, "fixture denied", str(hidden)))

    monkeypatch.setattr(model.os, "walk", incomplete_walk)
    project = model.load_project(tmp_path)
    assert project.resources == []
    assert project.analysis_errors == []
    assert project.coverage["status"] == "incomplete"
    assert project.coverage["files_parsed"] == 0
    assert project.coverage["discovery_errors"][0]["file"] == str(hidden)
    assert project.coverage["discovery_errors"][0]["error_type"] == "PermissionError"
