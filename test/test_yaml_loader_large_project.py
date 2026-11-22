"""A safe YAML loader in a project too large for the whole-project proof.

The proof that no other module replaces ``yaml.SafeLoader`` reads every Python
file of the project. Past the source snapshot limits (2,048 files) it is
unavailable, and ``yaml.load(text, Loader=yaml.SafeLoader)`` used to become a
listed HIGH finding in every large repository. It now stays reported as a
review item that is not listed and does not block, unless the file itself
fails the proof or a project module named ``yaml`` shadows PyYAML.
"""

from skylos.reporting.listing import is_unproven_source_review
from skylos.rules.danger import project_source
from skylos.rules.danger.danger import scan_ctx

SOURCE = """import yaml


def plain(text):
    return yaml.load(text, Loader=yaml.SafeLoader)


def fast(text):
    loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)
    return yaml.load_all(text, Loader=loader)


def unsafe(text):
    return yaml.load(text, Loader=yaml.UnsafeLoader)
"""


def _project(tmp_path, *, files=3, shadow=False):
    root = tmp_path.resolve()
    for index in range(files):
        (root / f"m{index}.py").write_text(f"VALUE = {index}\n")
    (root / "load.py").write_text(SOURCE)
    if shadow:
        (root / "yaml.py").write_text("SafeLoader = None\n")
    return root


def _d206(root):
    rows = scan_ctx(root, [root / "load.py"])
    return {row["line"]: row for row in rows if row["rule_id"] == "SKY-D206"}


def test_complete_project_proves_the_safe_loaders(tmp_path):
    rows = _d206(_project(tmp_path))
    assert sorted(rows) == [14]
    assert not is_unproven_source_review(rows[14])


def test_project_past_the_snapshot_limit_keeps_safe_loaders_unlisted(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(project_source, "_MAX_FILES", 2)
    rows = _d206(_project(tmp_path))
    assert sorted(rows) == [5, 10, 14]
    for line in (5, 10):
        assert is_unproven_source_review(rows[line])
        assert rows[line]["metadata"]["yaml_loader_proof"] == "project_too_large"
        assert rows[line]["message"].startswith("Review (not listed, not blocking)")
    # A loader the file itself does not prove safe stays a listed finding.
    assert not is_unproven_source_review(rows[14])
    assert "review_item" not in rows[14]


def test_a_project_yaml_module_still_blocks_in_a_large_project(tmp_path, monkeypatch):
    monkeypatch.setattr(project_source, "_MAX_FILES", 2)
    rows = _d206(_project(tmp_path, shadow=True))
    assert sorted(rows) == [5, 10, 14]
    assert not any(is_unproven_source_review(row) for row in rows.values())
