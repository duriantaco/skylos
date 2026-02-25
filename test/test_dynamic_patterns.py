import ast
import json
import tempfile
from pathlib import Path

from skylos.visitor import Visitor
from skylos.implicit_refs import ImplicitRefTracker


class TestGetAttrFStringPattern:
    def test_inline_fstring_registers_pattern(self):
        code = """
import sys

def export_csv(data):
    return ",".join(str(v) for v in data)

def export_json(data):
    import json
    return json.dumps(data)

def run_export(data, fmt):
    handler = getattr(sys.modules[__name__], f"export_{fmt}", None)
    return handler(data)
"""
        tracker = ImplicitRefTracker()
        v = Visitor("mymod", "test.py")
        v.pattern_tracker = tracker
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        patterns = [entry[2] for entry in tracker._compiled_patterns]
        assert any("export_" in p for p in patterns)

    def test_inline_fstring_marks_matching_defs(self):
        code = """
import sys

def export_csv(data):
    pass

def export_json(data):
    pass

def run_export(data, fmt):
    handler = getattr(sys.modules[__name__], f"export_{fmt}", None)
    return handler(data)
"""
        tracker = ImplicitRefTracker()
        v = Visitor("mymod", "test.py")
        v.pattern_tracker = tracker
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        for d in v.defs:
            if d.simple_name in ("export_csv", "export_json"):
                matched, _, _ = tracker.should_mark_as_used(d)
                assert matched, f"{d.simple_name} should match pattern"

    def test_non_matching_defs_not_marked(self):
        code = """
import sys

def export_csv(data):
    pass

def unrelated_func():
    pass

def run_export(data, fmt):
    handler = getattr(sys.modules[__name__], f"export_{fmt}", None)
    return handler(data)
"""
        tracker = ImplicitRefTracker()
        v = Visitor("mymod", "test.py")
        v.pattern_tracker = tracker
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        for d in v.defs:
            if d.simple_name == "unrelated_func":
                matched, _, _ = tracker.should_mark_as_used(d)
                assert not matched, "unrelated_func should not match export_* pattern"


class TestGlobalsFStringPattern:
    def test_globals_fstring_registers_pattern(self):
        code = """
def handle_create(payload):
    return {"action": "created"}

def handle_delete(payload):
    return {"action": "deleted"}

HANDLER_MAP = {a: globals()[f"handle_{a}"] for a in ("create", "delete")}
"""
        tracker = ImplicitRefTracker()
        v = Visitor("mymod", "test.py")
        v.pattern_tracker = tracker
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        patterns = [entry[2] for entry in tracker._compiled_patterns]
        assert any("handle_" in p for p in patterns)

    def test_globals_fstring_marks_matching_defs(self):
        code = """
def handle_create(payload):
    pass

def handle_update(payload):
    pass

HANDLER_MAP = {a: globals()[f"handle_{a}"] for a in ("create", "update")}
"""
        tracker = ImplicitRefTracker()
        v = Visitor("mymod", "test.py")
        v.pattern_tracker = tracker
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        for d in v.defs:
            if d.simple_name in ("handle_create", "handle_update"):
                matched, _, _ = tracker.should_mark_as_used(d)
                assert matched, f"{d.simple_name} should match pattern"


class TestInitSubclassRegistry:
    def test_base_classes_populated(self):
        code = """
class Base:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)

class Child(Base):
    pass
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        child = None
        for d in v.defs:
            if d.simple_name == "Child":
                child = d
                break

        assert child is not None
        assert "mymod.Base" in child.base_classes

    def test_subclasses_not_flagged_unused(self):
        code = """
_REGISTRY = {}

class RegisteredHandler:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        _REGISTRY[cls.name] = cls

class EmailHandler(RegisteredHandler):
    name = "email"

class SlackHandler(RegisteredHandler):
    name = "slack"

def get_handler(name):
    return _REGISTRY.get(name)
"""
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "registry.py"
            p.write_text(code)

            s = Skylos()
            result = json.loads(s.analyze(tmpdir, thr=0))
            unused_classes = {
                item["simple_name"] for item in result.get("unused_classes", [])
            }

            assert "EmailHandler" not in unused_classes
            assert "SlackHandler" not in unused_classes


class TestEnumMemberDetection:
    def _get_unused(self, code):
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "mod.py"
            p.write_text(code)
            s = Skylos()
            result = json.loads(s.analyze(tmpdir, thr=0))
            unused = set()
            for cat in ["unused_functions", "unused_classes", "unused_variables"]:
                for item in result.get(cat, []):
                    unused.add(item["simple_name"])
            return unused

    def test_basic_enum_members_not_flagged(self):
        unused = self._get_unused("""
from enum import Enum

class Color(Enum):
    RED = 1
    GREEN = 2
    BLUE = 3

c = Color.RED
""")
        assert "RED" not in unused
        assert "GREEN" not in unused
        assert "BLUE" not in unused

    def test_int_enum_members_not_flagged(self):
        unused = self._get_unused("""
from enum import IntEnum

class Status(IntEnum):
    PENDING = 0
    ACTIVE = 1

s = Status.ACTIVE
""")
        assert "PENDING" not in unused
        assert "ACTIVE" not in unused

    def test_enum_methods_not_flagged(self):
        unused = self._get_unused("""
from enum import Enum

class Color(Enum):
    RED = 1
    GREEN = 2

    def hex_code(self):
        return f"#{self.value:06x}"

c = Color.RED
""")
        assert "hex_code" not in unused

    def test_indirect_enum_inheritance(self):
        unused = self._get_unused("""
from enum import Enum

class BaseEnum(Enum):
    pass

class Priority(BaseEnum):
    LOW = 1
    HIGH = 2

p = Priority.HIGH
""")
        assert "LOW" not in unused
        assert "HIGH" not in unused

    def test_flag_enum_members_not_flagged(self):
        unused = self._get_unused("""
from enum import Flag

class Permission(Flag):
    READ = 1
    WRITE = 2
    EXECUTE = 4

p = Permission.READ | Permission.WRITE
""")
        assert "READ" not in unused
        assert "WRITE" not in unused
        assert "EXECUTE" not in unused
