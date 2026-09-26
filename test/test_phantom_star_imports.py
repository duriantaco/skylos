"""SKY-L012 bare-call findings must account for ``from x import *``.

agent-pr-bench real-13: ``load_key()`` comes from ``from core.utils import *``
where ``core/utils/__init__.py`` imports it (inside ``try:``). The name is
bound; reporting it as a stale/phantom call is wrong.
"""

import shutil
import tempfile
import textwrap
from pathlib import Path

from skylos.rules.ai_defect.phantom_refs import scan_repo_phantom_security_references


def _scan(files):
    tmpdir = tempfile.mkdtemp()
    try:
        root = Path(tmpdir).resolve()
        (root / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
        for rel_path, content in files.items():
            target = root / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(textwrap.dedent(content), encoding="utf-8")
        findings = scan_repo_phantom_security_references(root, sorted(root.rglob("*.py")))
        return sorted(
            (Path(f["file"]).resolve().relative_to(root).as_posix(), f["name"])
            for f in findings
            if f["rule_id"] == "SKY-L012"
        )
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


BASE = {
    "core/__init__.py": "",
    "core/utils/config_utils.py": """
        def load_key(key):
            return key

        def update_key(key, value):
            return value
    """,
}


def test_star_import_from_local_package_binds_names():
    files = dict(BASE)
    files["core/utils/__init__.py"] = """
        try:
            from .config_utils import load_key, update_key
        except ImportError:
            pass
    """
    files["core/asr.py"] = """
        from core.utils import *

        def transcribe():
            load_key("a")
            update_key("a", 1)
    """
    assert _scan(files) == []


def test_star_import_from_unknown_module_makes_names_unknown():
    files = dict(BASE)
    files["core/utils/__init__.py"] = ""
    files["core/asr.py"] = """
        from some_installed_pkg import *

        def transcribe():
            load_keys("a")
    """
    assert _scan(files) == []


def test_star_import_that_lacks_the_name_still_reports():
    files = dict(BASE)
    files["core/utils/__init__.py"] = "from .config_utils import load_key\n"
    files["core/helpers.py"] = "def unrelated():\n    return 1\n"
    files["core/asr.py"] = """
        from core.helpers import *
        from core.utils import load_key

        def transcribe():
            load_key("a")
            update_keys("a", 1)
    """
    assert _scan(files) == [("core/asr.py", "update_keys")]
