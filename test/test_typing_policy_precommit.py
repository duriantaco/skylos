"""Source-only, provider-checked pre-commit annotation requirements."""

import ast
import json

import pytest
import yaml

from test.fixture_paths import make_fixture_directory, write_fixture

from skylos.analysis.typing_policy import AnnotationPolicy, annotation_policy, annotation_requirement
from skylos.rules.quality.practices import TypeAnnotationPracticeRule


MIRROR = "https://github.com/pre-commit/mirrors-mypy"
SOURCE = "def public(value):\n    return value\n"


def project(root, *, hook=None, provider=MIRROR, settings="strict = true\n", global_config=None):
    make_fixture_directory(root, "pkg")
    write_fixture(root, "pkg/__init__.py", "", overwrite=True)
    write_fixture(root, "pkg/core.py", SOURCE, overwrite=True)
    write_fixture(root, "pkg/other.py", SOURCE, overwrite=True)
    write_fixture(root, "pkg/core.pyi", "def public(value): ...\n", overwrite=True)
    write_fixture(root, "pyproject.toml", "[tool.mypy]\n" + settings, overwrite=True)
    write_hooks(root, hook=hook, provider=provider, global_config=global_config)
    return root


def write_hooks(root, *, hook=None, provider=MIRROR, global_config=None):
    item = {"id": "mypy", "args": []}
    item.update(hook or {})
    if provider == "local":
        item = {"name": "Typing", "entry": "mypy", "language": "system", **item}
    repository = {"repo": provider, "hooks": [item]}
    if provider != "local":
        repository["rev"] = "v2.4.0"
    config = {**(global_config or {}), "repos": [repository]}
    write_fixture(root, ".pre-commit-config.yaml", yaml.safe_dump(config), overwrite=True)


def requirement(root, relative="pkg/core.py", source=SOURCE, **kwargs):
    return annotation_policy(root / relative, root, source, **kwargs)


def test_official_mirror_proves_filename_selection_without_mypy_files(tmp_path):
    root = project(tmp_path)
    assert requirement(root) == AnnotationPolicy(True, True)
    assert annotation_requirement(root / "pkg/core.py", root, SOURCE) is True


@pytest.mark.parametrize("entry", ["mypy", "python -m mypy", "python3 -m mypy --strict"])
def test_local_direct_mypy_entry_proves_policy_without_id_guessing(tmp_path, entry):
    root = project(tmp_path, provider="local", hook={"id": "local-types", "entry": entry})
    assert requirement(root) == AnnotationPolicy(True, True)


@pytest.mark.parametrize(
    "global_config,hook,relative,expected",
    [
        ({"files": "^pkg/"}, {"files": "core"}, "pkg/core.py", True),
        ({"files": "^pkg/"}, {"files": "core"}, "pkg/other.py", False),
        ({"files": "^outside/"}, {}, "pkg/core.py", False),
        ({"exclude": "core"}, {}, "pkg/core.py", False),
        ({}, {"exclude": "core"}, "pkg/core.py", False),
        ({}, {"files": r"(?x)^pkg/ core \.py$"}, "pkg/core.py", True),
    ],
)
def test_global_and_hook_regex_filters_are_intersected(tmp_path, global_config, hook, relative, expected):
    root = project(tmp_path, hook=hook, global_config=global_config)
    assert (requirement(root, relative).require_complete is True) is expected


@pytest.mark.parametrize(
    "hook,relative,expected",
    [
        ({}, "pkg/core.pyi", False),
        ({"types": ["python"]}, "pkg/core.py", True),
        ({"types": ["python"]}, "pkg/core.pyi", False),
        ({"types": ["python", "pyi"]}, "pkg/core.py", False),
        ({"types": ["file"], "types_or": ["python", "pyi"]}, "pkg/core.pyi", True),
        ({"types_or": ["python", "pyi"]}, "pkg/core.pyi", False),
        ({"types_or": ["pyi"]}, "pkg/core.py", False),
        ({"exclude_types": ["python"]}, "pkg/core.py", False),
        ({"types": ["file"], "types_or": ["pyi"], "exclude_types": ["python"]}, "pkg/core.pyi", True),
        ({"types": ["executable"]}, "pkg/core.py", False),
        ({"types_or": ["custom-tag", "python"]}, "pkg/core.py", False),
    ],
)
def test_supported_type_filters_use_and_or_and_exclusion_semantics(tmp_path, hook, relative, expected):
    root = project(tmp_path, hook=hook)
    assert (requirement(root, relative).require_complete is True) is expected


@pytest.mark.parametrize(
    "global_config,hook,expected",
    [
        ({}, {"stages": ["pre-commit"]}, True),
        ({}, {"stages": ["push"]}, True),
        ({}, {"stages": ["manual", "pre-push"]}, True),
        ({}, {"stages": ["manual"]}, False),
        ({}, {"stages": ["post-commit"], "always_run": True}, False),
        ({}, {"stages": ["commit-msg"]}, False),
        ({}, {"stages": ["unknown", "pre-commit"]}, False),
        ({}, {"stages": None}, False),
        ({}, {"stages": False}, False),
        ({}, {"stages": ""}, False),
        ({"default_stages": ["manual"]}, {}, False),
        ({"default_stages": ["manual"]}, {"stages": []}, False),
        ({"default_stages": ["manual"]}, {"stages": ["pre-commit"]}, True),
        ({}, {"pass_filenames": False, "always_run": True}, False),
    ],
)
def test_only_proved_file_bearing_stages_and_filename_passing_are_supported(tmp_path, global_config, hook, expected):
    root = project(tmp_path, hook=hook, global_config=global_config)
    assert (requirement(root).require_complete is True) is expected


@pytest.mark.parametrize(
    "provider,hook",
    [
        ("https://example.com/custom-mypy", {"id": "mypy", "args": ["--strict"]}),
        (MIRROR + "/untrusted", {}),
        (MIRROR, {"entry": "wrapper mypy"}),
        (MIRROR, {"language": "script"}),
        (MIRROR, {"args": ["--config-file", "unknown.ini"]}),
        (MIRROR, {"args": ["--unknown-option"]}),
        (MIRROR, {"args": ["{posargs:pkg}"]}),
        (MIRROR, {"args": ["$FILES"]}),
        (MIRROR, {"custom_selection": True}),
        (MIRROR, {"pass_filenames": "true"}),
        ("local", {"entry": "mypy --strict && wrapper"}),
        ("local", {"entry": "uv run mypy"}),
    ],
)
def test_unknown_provider_entry_args_and_settings_cannot_establish_policy(tmp_path, provider, hook):
    root = project(tmp_path, provider=provider, hook=hook)
    assert requirement(root) == AnnotationPolicy()


def test_mirror_without_explicit_args_stays_unknown(tmp_path):
    root = project(tmp_path)
    config = yaml.safe_load((root / ".pre-commit-config.yaml").read_text())
    del config["repos"][0]["hooks"][0]["args"]
    (root / ".pre-commit-config.yaml").write_text(yaml.safe_dump(config))
    assert requirement(root) == AnnotationPolicy()


def test_hook_cli_flags_preserve_partial_only_requirement(tmp_path):
    root = project(tmp_path, hook={"args": ["--allow-untyped-defs"]})
    assert requirement(root) == AnnotationPolicy(False, True)


def test_supported_hook_allow_flags_override_config_without_an_invented_bare_run(tmp_path):
    root = project(
        tmp_path, settings='strict = true\nfiles = ["pkg"]\n',
        hook={"args": ["--allow-untyped-defs", "--allow-incomplete-defs"]},
    )
    assert requirement(root) == AnnotationPolicy(False, False)


def test_supported_hook_exclusion_cannot_be_bypassed_by_config_files(tmp_path):
    root = project(
        tmp_path, settings='strict = true\nfiles = ["pkg"]\n',
        hook={"exclude": "core"},
    )
    assert requirement(root) == AnnotationPolicy()
    assert requirement(root, "pkg/other.py") == AnnotationPolicy(True, True)


def test_independent_direct_command_still_requires_an_excluded_hook_file(tmp_path):
    root = project(tmp_path, hook={"exclude": "core"})
    (root / "Makefile").write_text("typing:\n\tmypy pkg\n")
    assert requirement(root) == AnnotationPolicy(True, True)


def test_local_documented_type_defaults_can_select_stubs(tmp_path):
    root = project(tmp_path, provider="local")
    assert requirement(root, "pkg/core.pyi") == AnnotationPolicy(True, True)


def test_hook_strict_flag_is_a_requirement_without_strict_config(tmp_path):
    root = project(tmp_path, settings="", hook={"args": ["--strict", "--ignore-missing-imports"]})
    assert requirement(root) == AnnotationPolicy(True, True)


def test_module_overrides_and_inline_diagnostic_opt_outs_keep_precedence(tmp_path):
    root = project(
        tmp_path,
        settings='strict = true\n[[tool.mypy.overrides]]\nmodule = "pkg.core"\nignore_errors = true\n',
    )
    assert requirement(root) == AnnotationPolicy(False, False)
    assert requirement(root, "pkg/other.py") == AnnotationPolicy(True, True)
    assert requirement(root, "pkg/other.py", "# mypy: ignore-errors\n" + SOURCE) == AnnotationPolicy(False, False)


def test_duplicate_ids_do_not_merge_unknown_provider_settings_into_official_hook(tmp_path):
    root = project(tmp_path, settings="", hook={"args": []})
    config = yaml.safe_load((root / ".pre-commit-config.yaml").read_text())
    config["repos"].append({"repo": "https://example.com/mypy", "rev": "v1.0", "hooks": [{"id": "mypy", "args": ["--strict"]}]})
    (root / ".pre-commit-config.yaml").write_text(yaml.safe_dump(config))
    assert requirement(root) == AnnotationPolicy()


@pytest.mark.parametrize("invalid", ["repos: [", "repos: wrong", "repos: []\nfiles: '['", "unknown_setting: true\nrepos: []"])
def test_unsafe_or_unknown_config_does_not_erase_independent_mypy_files(tmp_path, invalid):
    root = project(tmp_path, settings='strict = true\nfiles = ["pkg"]\n')
    (root / ".pre-commit-config.yaml").write_text(invalid)
    assert requirement(root) == AnnotationPolicy(True, True)


def test_precommit_config_cache_tracks_creation_mutation_and_removal(tmp_path):
    root = project(tmp_path)
    path = root / ".pre-commit-config.yaml"
    path.unlink()
    assert requirement(root) == AnnotationPolicy()
    write_hooks(root)
    assert requirement(root) == AnnotationPolicy(True, True)
    write_hooks(root, hook={"exclude": "core"})
    assert requirement(root) == AnnotationPolicy()
    path.unlink()
    assert requirement(root) == AnnotationPolicy()


class SnapshotReader:
    def __init__(self, root, files, revision="snapshot-one"):
        self.root = root
        self.git_root = root
        self.files = files
        self.revision = revision

    def __call__(self, relative):
        if relative.as_posix() not in self.files:
            raise FileNotFoundError(relative)
        return self.files[relative.as_posix()]

    def workflow_paths(self):
        return []


def test_historical_reader_never_uses_todays_hook_config(tmp_path):
    root = project(tmp_path)
    reader = SnapshotReader(root, {"pyproject.toml": "[tool.mypy]\nstrict=true\n"})
    assert requirement(root, reader=reader) == AnnotationPolicy()


def test_historical_hook_config_can_prove_policy_without_checkout_sources(tmp_path):
    root = project(tmp_path, hook={"exclude": ".*"})
    files = {
        "pyproject.toml": "[tool.mypy]\nstrict=true\n",
        ".pre-commit-config.yaml": yaml.safe_dump({"repos": [{"repo": MIRROR, "rev": "v2.4.0", "hooks": [{"id": "mypy", "args": []}]}]}),
        "pkg/core.py": SOURCE,
    }
    reader = SnapshotReader(root, files)
    assert requirement(root, reader=reader) == AnnotationPolicy(True, True)
    newer = SnapshotReader(root, {**files, ".pre-commit-config.yaml": "repos: []\n"}, revision="snapshot-two")
    assert requirement(root, reader=newer) == AnnotationPolicy()


def test_symlinked_hook_configuration_is_not_policy_evidence(tmp_path):
    root = project(tmp_path)
    path = root / ".pre-commit-config.yaml"
    other = root / "untrusted.yaml"
    path.rename(other)
    path.symlink_to(other)
    assert requirement(root) == AnnotationPolicy()


def test_oversized_hook_configuration_does_not_erase_independent_policy(tmp_path):
    root = project(tmp_path, settings='strict = true\nfiles = ["pkg"]\n')
    (root / ".pre-commit-config.yaml").write_text("#" + "x" * 1_000_001)
    assert requirement(root) == AnnotationPolicy(True, True)


def test_historical_unavailable_hook_config_never_falls_back_to_checkout(tmp_path):
    root = project(tmp_path)
    reader = SnapshotReader(root, {
        "pyproject.toml": "[tool.mypy]\nstrict=true\n",
        ".pre-commit-config.yaml": None,
    })
    assert requirement(root, reader=reader) == AnnotationPolicy()


@pytest.mark.parametrize("selected", [True, False])
def test_full_analyzer_and_gate_respect_hook_file_selection(tmp_path, selected):
    from skylos.analyzer import analyze
    from skylos.core.gatekeeper import check_gate

    root = project(tmp_path, hook={"files": "^pkg/core.py$" if selected else "^other/"})
    # A single own source module is enough to exercise real config/rule/output.
    (root / "pkg/other.py").unlink()
    (root / "pkg/core.pyi").unlink()
    report = json.loads(analyze(
        str(root), enable_quality=True, enable_danger=False, enable_secrets=False,
        enable_sca=False, enable_dependency_hallucinations=False,
        grep_verify=False, grep_cache=False, trace_file=False,
    ))
    findings = [row for row in report.get("quality", []) if row.get("rule_id") in {"SKY-T101", "SKY-T102"}]
    assert {row["rule_id"] for row in findings} == ({"SKY-T101", "SKY-T102"} if selected else set())
    passed, _ = check_gate({"quality": findings}, {"gate": {"max_quality": 0}})
    assert passed is not selected
    assert report["analysis_summary"]["typing_coverage"]["definitions_missing_annotations"] == 1


def test_real_rule_does_not_execute_local_hook_entry_or_source(tmp_path):
    root = project(tmp_path, provider="local", hook={"entry": "mypy"})
    source = "raise RuntimeError('must never execute target code')\n" + SOURCE
    rows = TypeAnnotationPracticeRule().visit_node(
        ast.parse(source), {"filename": str(root / "pkg/core.py"), "project_root": root, "source": source}
    )
    assert {row["rule_id"] for row in rows} == {"SKY-T101", "SKY-T102"}


def test_nested_project_hook_is_unknown_when_git_root_is_its_parent(tmp_path):
    (tmp_path / ".git").mkdir()
    nested = tmp_path / "nested"
    nested.mkdir()
    root = project(nested)
    assert requirement(root) == AnnotationPolicy()


@pytest.mark.parametrize("marker_kind", ["directory", "worktree-file"])
def test_hook_at_project_git_root_retains_required_policy(tmp_path, marker_kind):
    root = project(tmp_path)
    marker = root / ".git"
    if marker_kind == "directory":
        marker.mkdir()
    else:
        marker.write_text("gitdir: /unavailable/worktrees/project\n")
    assert requirement(root) == AnnotationPolicy(True, True)


def test_nested_hook_does_not_erase_independent_config_policy(tmp_path):
    (tmp_path / ".git").mkdir()
    nested = tmp_path / "nested"
    nested.mkdir()
    root = project(nested, settings='strict = true\nfiles = ["pkg"]\n')
    assert requirement(root) == AnnotationPolicy(True, True)


def test_git_root_relationship_cache_tracks_nearer_and_parent_marker_changes(tmp_path):
    nested = tmp_path / "nested"
    nested.mkdir()
    root = project(nested)
    assert requirement(root) == AnnotationPolicy(True, True)
    (tmp_path / ".git").mkdir()
    assert requirement(root) == AnnotationPolicy()
    (root / ".git").mkdir()
    assert requirement(root) == AnnotationPolicy(True, True)
    (root / ".git").rmdir()
    assert requirement(root) == AnnotationPolicy()
    (tmp_path / ".git").rmdir()
    assert requirement(root) == AnnotationPolicy(True, True)


def test_symlinked_git_marker_does_not_establish_hook_root(tmp_path):
    root = project(tmp_path)
    (root / "metadata").mkdir()
    (root / ".git").symlink_to(root / "metadata", target_is_directory=True)
    assert requirement(root) == AnnotationPolicy()


def snapshot_files(root):
    return {
        "pyproject.toml": (root / "pyproject.toml").read_text(),
        ".pre-commit-config.yaml": (root / ".pre-commit-config.yaml").read_text(),
        "pkg/core.py": SOURCE,
    }


@pytest.mark.parametrize("metadata", ["absent", "none", "ancestor", "relative"])
def test_historical_hook_requires_explicit_matching_git_root_context(tmp_path, metadata):
    root = project(tmp_path)
    (root / ".git").mkdir()
    reader = SnapshotReader(root, snapshot_files(root))
    if metadata == "absent":
        del reader.git_root
    else:
        reader.git_root = {"none": None, "ancestor": root.parent, "relative": "."}[metadata]
    assert requirement(root, reader=reader) == AnnotationPolicy()


def test_historical_explicit_git_root_does_not_consult_todays_parent_marker(tmp_path):
    (tmp_path / ".git").mkdir()
    nested = tmp_path / "nested"
    nested.mkdir()
    root = project(nested)
    reader = SnapshotReader(root, snapshot_files(root))
    assert requirement(root) == AnnotationPolicy()
    assert requirement(root, reader=reader) == AnnotationPolicy(True, True)


def test_historical_git_root_metadata_is_part_of_cache_validity(tmp_path):
    root = project(tmp_path)
    reader = SnapshotReader(root, snapshot_files(root))
    assert requirement(root, reader=reader) == AnnotationPolicy(True, True)
    del reader.git_root
    assert requirement(root, reader=reader) == AnnotationPolicy()
    reader.git_root = root.parent
    assert requirement(root, reader=reader) == AnnotationPolicy()
    reader.git_root = root
    assert requirement(root, reader=reader) == AnnotationPolicy(True, True)


def test_historical_missing_git_context_preserves_independent_mypy_files(tmp_path):
    root = project(tmp_path, settings='strict = true\nfiles = ["pkg"]\n')
    reader = SnapshotReader(root, snapshot_files(root))
    del reader.git_root
    assert requirement(root, reader=reader) == AnnotationPolicy(True, True)
