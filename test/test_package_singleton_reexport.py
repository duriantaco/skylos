import textwrap

from skylos.rules.ai_defect.phantom_refs import scan_repo_phantom_security_references

PHANTOM_RULES = {"SKY-L012", "SKY-L023"}

MANAGER = """
    import subprocess


    class Manager:
        def __init__(self):
            self.process = None

        @property
        def logs(self):
            return []

        def start(self, command):
            self.process = subprocess.Popen(command)
            return True


    manager = Manager()
"""

TOOLS = """
    def present():
        return 1
"""


def _scan(root, files):
    (root / "pyproject.toml").write_text("[tool.skylos]\n", encoding="utf-8")
    for rel_path, content in files.items():
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(content), encoding="utf-8")
    findings = scan_repo_phantom_security_references(root, sorted(root.rglob("*.py")))
    return sorted(
        (f["rule_id"], f["name"]) for f in findings if f["rule_id"] in PHANTOM_RULES
    )


def test_singleton_reexported_over_its_submodule_has_its_members(tmp_path):
    files = {
        "svc/__init__.py": (
            'from .manager import Manager, manager\n__all__ = ["Manager", "manager"]\n'
        ),
        "svc/manager.py": MANAGER,
        "app.py": """
            from svc import manager

            def run(command):
                if manager.process is None:
                    manager.start(command)
                return manager.logs
        """,
    }
    assert _scan(tmp_path, files) == []


def test_reexported_module_still_reports_a_missing_member(tmp_path):
    files = {
        "svc/__init__.py": 'from . import tools\n__all__ = ["tools"]\n',
        "svc/tools.py": TOOLS,
        "app.py": """
            from svc import tools

            def run():
                return tools.present() + tools.missing()
        """,
    }
    assert _scan(tmp_path, files) == [("SKY-L012", "tools.missing")]
