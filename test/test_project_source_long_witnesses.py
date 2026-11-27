import pytest

from skylos.analysis.file_worker import process_file
from skylos.rules.danger.danger_fs.path_provenance import (
    _EVIDENCE_STEP_ANCHORS,
    _MAX_STEPS,
)

_READ = "urlopen('https://example.invalid/metadata').read().decode()"


def _scan(tmp_path, source):
    path = tmp_path / "app.py"
    path.write_text(source)
    row = process_file(
        str(path), "app", project_root=tmp_path, enable_quality_rules=False
    )
    assert row[25] is None
    assert _EVIDENCE_STEP_ANCHORS.get() is None
    return [finding for finding in row[7] if finding["rule_id"] == "SKY-D357"]


def _aliases(count):
    return "".join(f"part{i} = part{i - 1}\n" for i in range(1, count + 1))


@pytest.mark.parametrize("test_only", [True, False])
def test_late_test_helper_remains_on_the_same_import_chain(tmp_path, test_only):
    module = "test_shim" if test_only else "shim"
    (tmp_path / f"{module}.py").write_text(
        ("import pytest\n" if test_only else "") + "def identity(value): return value\n"
    )
    length = _MAX_STEPS + 3
    source = (
        "import importlib\nfrom urllib.request import urlopen\n"
        f"from {module} import identity\npart0 = {_READ}\n"
        + _aliases(length)
        + f"result = identity(part{length})\n"
    )
    hits = _scan(tmp_path, source + "importlib.import_module(result)\n")
    assert len(hits) == (0 if test_only else 1)
