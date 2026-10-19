"""Context guesses cannot override shipped identity or specific copy provenance."""

import base64
import hashlib
from pathlib import Path

import pytest

from skylos.core.safe_cache_io import write_text_no_symlink
from skylos.reporting.advice_scope import advice_source_context


def _write(root, relative, source):
    root = root.resolve()
    relative = Path(relative)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("fixture path leaves root")
    path = root / relative
    path.resolve().relative_to(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    assert write_text_no_symlink(path, source)
    return path


def _context(path, root):
    return advice_source_context({"rule_id": "SKY-Q301", "file": str(path), "line": 1}, root)


def test_project_identity_protects_a_top_level_example_package(tmp_path):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "example"\n')
    _write(tmp_path, "example/__init__.py", "")
    path = _write(tmp_path, "example/service.py", "def run(): pass\n")
    assert _context(path, tmp_path) is None
    assert _context(path, path.parent) is None
    demo = _write(tmp_path, "examples/demo.py", "def run(): pass\n")
    assert _context(demo, tmp_path) == "example"


@pytest.mark.parametrize("module", ["bench", "examples", "docs_src"])
def test_regular_src_subpackages_are_shipped_even_with_sample_names(tmp_path, module):
    _write(tmp_path, "pyproject.toml", '[project]\nname = "distribution"\n')
    _write(tmp_path, f"src/shop/{module}/__init__.py", "")
    path = _write(tmp_path, f"src/shop/{module}/service.py", "def run(): pass\n")
    assert _context(path, tmp_path) is None
    standalone = _write(tmp_path, "benchmarks/time_it.py", "def run(): pass\n")
    assert _context(standalone, tmp_path) == "profiling"


@pytest.mark.parametrize(
    "declaration",
    [
        '[tool.setuptools]\npackages = ["example"]\n',
        '[tool.setuptools.packages.find]\nwhere = ["."]\ninclude = ["example*"]\n',
        '[tool.poetry]\npackages = [{include="example"}]\n',
        '[tool.hatch.build.targets.wheel]\npackages = ["example"]\n',
    ],
)
def test_explicit_package_selection_protects_namespace_packages(tmp_path, declaration):
    _write(tmp_path, "pyproject.toml", '[project]\nname="different-distribution"\n' + declaration)
    path = _write(tmp_path, "example/service.py", "def run(): pass\n")
    assert _context(path, tmp_path) is None


@pytest.mark.parametrize(
    "description",
    [
        "This package is derived from https://example.com/parser (commit 1a2b3c4d) and has since been rewritten and maintained here.\n",
        "This directory is a vendored copy of https://example.com/parser.\n\nIt is now reimplemented and maintained locally.\n",
        "This package is derived from https://example.com/parser.\n\nIt is independently maintained here as first-party code.\n",
        "This package is derived from https://example.com/parser.\n\nHistory.\n\nRelease notes.\n\nThe implementation is now rewritten and maintained here.\n",
        "Our first-party payment service. Only compat.py was copied from https://example.com/parser.\n",
    ],
)
def test_historical_provenance_does_not_hide_rewritten_or_first_party_siblings(tmp_path, description):
    path = _write(tmp_path, "package/parser/authorize.py", "def authorize(): pass\n")
    _write(tmp_path, "package/parser/README.md", description)
    _write(tmp_path, "package/parser/LICENSE", "Copyright. Permission to copy this software.\n")
    assert _context(path, tmp_path) is None


def test_copied_subset_provenance_remains_distinct_from_rewritten_forks(tmp_path):
    path = _write(tmp_path, "package/parser/core.py", "def parse(): pass\n")
    _write(tmp_path, "package/parser/README", "A subset of parser taken from Python 3.7. Commit hash: 1a2b3c4d\n")
    _write(tmp_path, "package/parser/LICENSE", "Copyright and license.\n")
    assert _context(path, tmp_path) == "vendored"


VENDOR_CONFIG = """[project]
name = "shipper"
[tool.vendoring]
destination = "src/shipper/_vendored"
requirements = "src/shipper/_vendored/vendor.txt"
protected-files = ["__init__.py", "owned.py"]
[tool.vendoring.license.directories]
renamed-distribution = "actual_module"
"""


def _inventory_vendor(root):
    _write(root, "pyproject.toml", VENDOR_CONFIG)
    _write(root, "src/shipper/_vendored/vendor.txt", "alpha-package==1.2.3\nrenamed-distribution==2.0\nsingle==3.0\n")
    path = _write(root, "src/shipper/_vendored/alpha_package/core.py", "def run(): pass\n")
    license_path = _write(root, "src/shipper/_vendored/alpha_package/LICENCE.md", "Copyright and licence.\n")
    return path, license_path


def test_authoritative_vendoring_inventory_licenses_and_name_aliases(tmp_path):
    path, license_path = _inventory_vendor(tmp_path)
    assert _context(path, tmp_path) == "vendored"
    renamed = _write(tmp_path, "src/shipper/_vendored/actual_module/core.py", "def run(): pass\n")
    _write(tmp_path, "src/shipper/_vendored/actual_module/COPYING", "Copyright and permission.\n")
    assert _context(renamed, tmp_path) == "vendored"
    unknown = _write(tmp_path, "src/shipper/_vendored/unlisted/core.py", "def run(): pass\n")
    _write(tmp_path, "src/shipper/_vendored/unlisted/LICENSE", "Copyright and license.\n")
    assert _context(unknown, tmp_path) is None
    wrapper = _write(tmp_path, "src/shipper/_vendored/__init__.py", "def wrapper(): pass\n")
    assert _context(wrapper, tmp_path) is None
    license_path.unlink()
    assert _context(path, tmp_path) is None


def test_single_file_dependency_requires_its_own_named_license(tmp_path):
    _inventory_vendor(tmp_path)
    path = _write(tmp_path, "src/shipper/_vendored/single.py", "def run(): pass\n")
    _write(tmp_path, "src/shipper/_vendored/LICENSE", "Copyright and license.\n")
    assert _context(path, tmp_path) is None
    _write(tmp_path, "src/shipper/_vendored/single.LICENSE", "Copyright and permission.\n")
    assert _context(path, tmp_path) == "vendored"
    wrapper = _write(tmp_path, "src/shipper/_vendored/owned.py", "def owned(): pass\n")
    assert _context(wrapper, tmp_path) is None


def test_declared_vendor_inventory_can_live_elsewhere_inside_project(tmp_path):
    path, _ = _inventory_vendor(tmp_path)
    _write(tmp_path, "dependency-inventories/embedded.txt", "alpha-package==1.2.3\n")
    _write(tmp_path, "pyproject.toml", VENDOR_CONFIG.replace("src/shipper/_vendored/vendor.txt", "dependency-inventories/embedded.txt"))
    assert _context(path, tmp_path) == "vendored"
    _write(tmp_path, "pyproject.toml", VENDOR_CONFIG.replace("src/shipper/_vendored/vendor.txt", "../embedded.txt"))
    assert _context(path, tmp_path) is None


def test_project_cannot_be_its_own_vendor_inventory_dependency(tmp_path):
    path, _ = _inventory_vendor(tmp_path)
    _write(tmp_path, "pyproject.toml", VENDOR_CONFIG.replace('name = "shipper"', 'name = "alpha-package"'))
    assert _context(path, tmp_path) is None


@pytest.mark.parametrize("inventory", ["alpha-package>=1.0\n", "alpha-package==1.*\n", "-r outside.txt\n", "alpha-package @ https://example.com/code.whl\n"])
def test_unpinned_or_dynamic_vendor_inventories_are_unknown(tmp_path, inventory):
    path, _ = _inventory_vendor(tmp_path)
    _write(tmp_path, "src/shipper/_vendored/vendor.txt", inventory)
    assert _context(path, tmp_path) is None


def test_first_party_declaration_overrides_parent_vendor_inventory(tmp_path):
    path, _ = _inventory_vendor(tmp_path)
    _write(tmp_path, "src/shipper/_vendored/alpha_package/README", "This package is derived from https://example.com/alpha, but rewritten and maintained here.\n")
    assert _context(path, tmp_path) is None


def _wheel_vendor(root, namespace="copy_lib", container="third_party", source="def run(): pass\n"):
    _write(root, "pyproject.toml", '[project]\nname="owner"\n')
    base = f"src/owner/{container}"
    path = _write(root, f"{base}/{namespace.replace('.', '/')}/core.py", source)
    metadata = f"{base}/{namespace.replace('.', '_')}-1.0.dist-info"
    _write(root, f"{metadata}/METADATA", f"Metadata-Version: 2.4\nName: {namespace}\nVersion: 1.0\nProject-URL: Source, https://example.com/{namespace}\nLicense-File: LICENSE\n")
    _write(root, f"{metadata}/licenses/LICENSE", "Copyright. Permission to copy.\n")
    digest = base64.urlsafe_b64encode(hashlib.sha256(source.encode()).digest()).rstrip(b"=").decode()
    record = _write(root, f"{metadata}/RECORD", f"{namespace.replace('.', '/')}/core.py,sha256={digest},{len(source.encode())}\n")
    return path, record


@pytest.mark.parametrize("container", ["_vendor", "vendor", "vendored", "_vendored", "third_party"])
@pytest.mark.parametrize("namespace", ["copy_lib", "example.namespace"])
def test_standard_distribution_records_prove_only_their_exact_current_files(tmp_path, container, namespace):
    path, _ = _wheel_vendor(tmp_path, namespace, container)
    assert _context(path, tmp_path) == "vendored"
    sibling = _write(tmp_path, str(path.parent.relative_to(tmp_path) / "authorize.py"), "def authorize(): pass\n")
    assert _context(sibling, tmp_path) is None
    assert write_text_no_symlink(path, "def rewritten(): pass\n")
    assert _context(path, tmp_path) is None


def test_wheel_inventory_hashes_preserve_original_newlines(tmp_path):
    path, _ = _wheel_vendor(tmp_path, source="def run():\r\n    pass\r\n")
    assert _context(path, tmp_path) == "vendored"


def test_wheel_license_file_metadata_can_name_a_nonstandard_license(tmp_path):
    path, record = _wheel_vendor(tmp_path)
    directory = record.parent
    (directory / "licenses/LICENSE").unlink()
    _write(tmp_path, str((directory / "licenses/CUSTOM-NOTICE").relative_to(tmp_path)), "Copyright and permission.\n")
    metadata = directory / "METADATA"
    assert write_text_no_symlink(metadata, "Metadata-Version: 2.4\nName: copy_lib\nVersion: 1.0\nProject-URL: Source, https://example.com/copy_lib\nLicense-File: CUSTOM-NOTICE\n")
    assert _context(path, tmp_path) == "vendored"


def test_symlinked_vendor_inventory_cannot_supply_proof(tmp_path):
    path, _ = _inventory_vendor(tmp_path)
    inventory = tmp_path / "src/shipper/_vendored/vendor.txt"
    inventory.unlink()
    other = _write(tmp_path, "outside.txt", "alpha-package==1.0\n")
    inventory.symlink_to(other)
    assert _context(path, tmp_path) is None


@pytest.mark.parametrize("config", ['tool = "invalid"\n', '[tool]\nvendoring = "invalid"\n', '[tool.vendoring]\ndestination = []\nrequirements = 1\n'])
def test_malformed_nested_metadata_preserves_visible_advice(tmp_path, config):
    path = _write(tmp_path, "src/owner/_vendor/copy/core.py", "def run(): pass\n")
    _write(tmp_path, "pyproject.toml", config)
    assert _context(path, tmp_path) is None


DATA = "config = sample.Structure(values=" + repr(list(range(160))) + ")\n"


@pytest.mark.parametrize(
    "config,manifest",
    [
        ('[build-system]\nbuild-backend="poetry.core.masonry.api"\n[tool.poetry]\nexclude=["profiling/**"]\n', None),
        ('[build-system]\nbuild-backend="setuptools.build_meta"\n[tool.setuptools.packages.find]\nwhere=["src"]\n', "prune profiling\n"),
        ('[build-system]\nbuild-backend="setuptools.build_meta"\n[tool.setuptools]\npackages=["owner"]\n', "prune profiling\n"),
    ],
)
def test_non_hatch_backends_need_distribution_exclusion_and_static_data(tmp_path, config, manifest):
    _write(tmp_path, "pyproject.toml", config)
    if manifest is not None:
        _write(tmp_path, "MANIFEST.in", manifest)
    path = _write(tmp_path, "profiling/data.py", DATA)
    assert _context(path, tmp_path) == "profiling"
    assert write_text_no_symlink(path, "def profile():\n    return 42\n")
    assert _context(path, tmp_path) is None


@pytest.mark.parametrize(
    "config,manifest",
    [
        ('[build-system]\nbuild-backend="unknown.backend"\n[tool.poetry]\nexclude=["profiling/**"]\n', None),
        ('[build-system]\nbuild-backend="poetry.core.masonry.api"\n[tool.poetry]\nexclude=["profiling/**"]\ninclude=["profiling/data.py"]\n', None),
        ('[build-system]\nbuild-backend="setuptools.build_meta"\n[tool.setuptools.packages.find]\nwhere=["src"]\n', "prune profiling\ninclude profiling/data.py\n"),
        ('[build-system]\nbuild-backend="setuptools.build_meta"\n[tool.setuptools.packages.find]\nwhere=["."]\n', "prune profiling\n"),
        ('[tool.hatch.build.targets.sdist]\nexclude=["profiling"]\n[tool.hatch.build.targets.wheel]\nonly-include=["src"]\nforce-include={"profiling/data.py"="owner/data.py"}\n', None),
    ],
)
def test_unknown_backend_and_inclusion_overrides_preserve_profile_advice(tmp_path, config, manifest):
    _write(tmp_path, "pyproject.toml", config)
    if manifest is not None:
        _write(tmp_path, "MANIFEST.in", manifest)
    path = _write(tmp_path, "profiling/data.py", DATA)
    assert _context(path, tmp_path) is None


def test_oversized_clone_numeric_fields_preserve_advice_without_integer_conversion(tmp_path):
    first = _write(tmp_path, "examples/a.py", "def a(): pass\n")
    second = _write(tmp_path, "examples/b.py", "def b(): pass\n")
    huge = "1" * 4500
    finding = {
        "rule_id": "SKY-C401", "file": str(first), "line": 1,
        "message": f"Clone group detected (type1, sim=0.982, members=2) examples: {first}:{huge}-{huge} (function a), {second}:1-1 (function b)",
    }
    assert advice_source_context(finding, tmp_path) is None
