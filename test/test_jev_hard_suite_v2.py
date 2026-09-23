"""Ground-truth checks for repository-style Jev fixtures, without executing them."""

import ast
import json
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 project support.
    import tomli as tomllib


BENCH_ROOT = Path(__file__).resolve().parents[1] / "benchmarks" / "dead_code"


def _labels(manifest_name):
    manifest = json.loads((BENCH_ROOT / manifest_name).read_text(encoding="utf-8"))
    case = manifest["cases"][0]
    return case, {
        label: {(item["file"], item["symbol"]) for item in case["expect"][label]}
        for label in ("used", "unused")
    }


def _functions(path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def test_v2_manifest_is_the_exact_union_of_frozen_cases():
    component_paths = (
        "jev_hard_suite_manifest.json",
        "jev_realistic_repo_manifest.json",
        "jev_package_surface_manifest.json",
        "jev_method_surface_manifest.json",
    )
    components = [
        json.loads((BENCH_ROOT / name).read_text(encoding="utf-8"))
        for name in component_paths
    ]
    combined = json.loads(
        (BENCH_ROOT / "jev_hard_suite_v2_manifest.json").read_text(encoding="utf-8")
    )
    expected_cases = [case for component in components for case in component["cases"]]
    assert combined["cases"] == expected_cases
    assert len({case["id"] for case in expected_cases}) == 8
    assert (
        sum(
            len(case["expect"][label])
            for case in expected_cases
            for label in ("unused", "used")
        )
        == 125
    )


def test_workflow_labels_are_exact_closed_world_config_targets():
    case, labels = _labels("jev_realistic_repo_manifest.json")
    root = BENCH_ROOT / case["path"]
    workflow = json.loads(
        (root / "config" / "workflows.json").read_text(encoding="utf-8")
    )
    registry_tree = ast.parse(
        (root / "atlasflow" / "registry.py").read_text(encoding="utf-8")
    )
    registry_assignment = next(
        node
        for node in registry_tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "PLUGIN_REGISTRY"
            for target in node.targets
        )
    )
    registry = ast.literal_eval(registry_assignment.value)

    selected = set()
    for item in workflow["workflows"]:
        for key in ("before", "steps", "after"):
            selected.update(item[key])
        selected.update(registry[key] for key in item["plugins"])
    selected_labels = {
        (f"atlasflow/{reference.split('.')[-2]}.py", reference.split(".")[-1])
        for reference in selected
    }
    assert selected_labels == labels["used"]

    definitions = {
        (f"atlasflow/{module}.py", symbol)
        for module in ("actions", "callbacks", "plugins")
        for symbol in _functions(root / "atlasflow" / f"{module}.py")
    }
    assert labels["used"] | labels["unused"] == definitions
    assert labels["used"].isdisjoint(labels["unused"])


def test_package_traps_are_backed_by_config_entrypoints_and_tests():
    case, labels = _labels("jev_package_surface_manifest.json")
    root = BENCH_ROOT / case["path"]
    config = json.loads(
        (root / "src" / "orchidkit" / "config" / "pipelines.json").read_text(
            encoding="utf-8"
        )
    )
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))

    dynamic_targets = {
        ("src/orchidkit/handlers.py", ref.split(":", 1)[1])
        for ref in config["profiles"].values()
    }
    dynamic_targets.add(
        (
            "src/orchidkit/cli.py",
            pyproject["project"]["scripts"]["orchid"].split(":")[1],
        )
    )
    dynamic_targets.update(
        ("src/orchidkit/backends.py", ref.split(":", 1)[1])
        for ref in pyproject["project"]["entry-points"]["orchidkit.backends"].values()
    )
    assert dynamic_targets <= labels["used"]
    assert dynamic_targets.isdisjoint(labels["unused"])

    tests = (root / "tests" / "test_transforms.py").read_text(encoding="utf-8")
    assert "from orchidkit.transforms import normalize_drift" in tests
    assert ("src/orchidkit/transforms.py", "normalize_drift") in labels["used"]
    assert ("src/orchidkit/transforms.py", "normalize_cobalt") in labels["unused"]
    assert ("src/orchidkit/handlers.py", "handle_cobalt") in labels["unused"]

    definitions = {
        (f"src/orchidkit/{module}.py", symbol)
        for module in ("cli", "handlers", "backends", "transforms")
        for symbol in _functions(root / "src" / "orchidkit" / f"{module}.py")
    }
    definitions.update(
        ("tests/test_transforms.py", symbol)
        for symbol in _functions(root / "tests" / "test_transforms.py")
    )
    assert labels["used"] | labels["unused"] == definitions
    assert labels["used"].isdisjoint(labels["unused"])


def test_async_event_labels_match_the_finite_published_topics():
    case, labels = _labels("jev_method_surface_manifest.json")
    root = BENCH_ROOT / case["path"]
    plan = json.loads((root / "topics.json").read_text(encoding="utf-8"))
    selected = {("handlers.py", f"on_{topic}") for topic in plan["published"]}
    definitions = {
        ("handlers.py", node.name)
        for node in ast.parse((root / "handlers.py").read_text(encoding="utf-8")).body
        if isinstance(node, ast.AsyncFunctionDef)
    }
    assert labels["used"] == selected
    assert labels["unused"] == definitions - selected
    assert labels["used"].isdisjoint(labels["unused"])
