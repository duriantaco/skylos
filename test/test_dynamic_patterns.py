import ast
import json
import tempfile
from pathlib import Path

from skylos.visitor import Visitor, Definition
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

    def test_transitive_subclass_not_flagged_unused(self):
        """Subclasses via intermediate base should also be suppressed."""
        code = """
_REGISTRY = {}

class Base:
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        _REGISTRY[cls.name] = cls

class Intermediate(Base):
    pass

class LeafA(Intermediate):
    name = "a"

class LeafB(Intermediate):
    name = "b"

def get(name):
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

            assert "LeafA" not in unused_classes
            assert "LeafB" not in unused_classes
            assert "Intermediate" not in unused_classes


class TestEnumMemberDetection:
    def _get_unused(self, code):
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "mod.py"
            p.write_text(code)
            s = Skylos()
            result = json.loads(s.analyze(tmpdir, thr=0, grep_verify=False))
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


class TestDefinitionReasonFields:
    def test_definition_has_new_fields(self):
        d = Definition("test.func", "function", "test.py", 1)
        assert d.heuristic_refs == {}
        assert d.dynamic_signals == []
        assert d.framework_signals == []
        assert d.why_unused == []
        assert d.why_confidence_reduced == []
        assert d._attr_name_ref_count == 0

    def test_to_dict_includes_new_fields_when_populated(self):
        d = Definition("test.func", "function", "test.py", 1)
        d.heuristic_refs = {"same_file_attr": 1.0}
        d.dynamic_signals = ["inspect_getmembers"]
        result = d.to_dict()
        assert "heuristic_refs" in result
        assert result["heuristic_refs"] == {"same_file_attr": 1.0}
        assert "dynamic_signals" in result

    def test_to_dict_excludes_empty_fields(self):
        d = Definition("test.func", "function", "test.py", 1)
        result = d.to_dict()
        assert "heuristic_refs" not in result
        assert "dynamic_signals" not in result
        assert "why_unused" not in result


class TestContextTracking:
    def test_attr_context_tracked(self):
        code = """
class Foo:
    def run(self):
        pass

obj.run()
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        assert "run" in v._used_attr_names
        contexts = [c for c in v._used_attr_names_with_context if c[0] == "run"]
        assert len(contexts) > 0
        assert contexts[0][1] == "mymod"


class TestLocalsHandling:
    def test_locals_subscript_adds_ref(self):
        code = """
def my_func():
    pass

def dispatch():
    f = locals()["my_func"]
    f()
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        refs = [r[0] for r in v.refs]
        assert "my_func" in refs or "mymod.my_func" in refs


class TestVarsAndDictHandling:
    """Phase 2B: Test vars() and __dict__ subscript handling."""

    def test_vars_subscript_adds_ref(self):
        code = """
class Foo:
    def __init__(self):
        self.name = "test"

    def get_field(self, key):
        return vars(self)["name"]
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        refs = [r[0] for r in v.refs]
        assert "name" in refs or "mymod.Foo.name" in refs

    def test_dict_subscript_adds_ref(self):
        code = """
class Bar:
    x = 10

    def get_x(self):
        return self.__dict__["x"]
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        refs = [r[0] for r in v.refs]
        assert "x" in refs or "mymod.Bar.x" in refs


class TestRightSideConcat:
    def test_right_side_concat_pattern(self):
        code = """
def load_handler():
    name = "handler"
    handler = getattr(module, name + "_impl")
"""
        tracker = ImplicitRefTracker()
        v = Visitor("mymod", "test.py")
        v.pattern_tracker = tracker
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        patterns = [entry[2] for entry in tracker._compiled_patterns]
        assert any("_impl" in p for p in patterns)


class TestFormatInGetattr:
    def test_format_pattern(self):
        code = """
def dispatch(action):
    handler = getattr(module, "handle_{}".format(action))
"""
        tracker = ImplicitRefTracker()
        v = Visitor("mymod", "test.py")
        v.pattern_tracker = tracker
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        patterns = [entry[2] for entry in tracker._compiled_patterns]
        assert any("handle_" in p for p in patterns)


class TestInspectGetmembers:
    def test_inspect_getmembers_self_marks_class_members(self):
        code = """
import inspect

class Plugin:
    def action_one(self):
        pass

    def action_two(self):
        pass

    def get_actions(self):
        return inspect.getmembers(self)
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        action_defs = [d for d in v.defs if d.simple_name.startswith("action_")]
        for d in action_defs:
            assert "inspect_getmembers" in d.dynamic_signals, (
                f"{d.simple_name} should have inspect_getmembers signal"
            )

    def test_inspect_getmembers_class_name(self):
        code = """
import inspect

class Handler:
    def process(self):
        pass

members = inspect.getmembers(Handler)
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        process_def = [d for d in v.defs if d.simple_name == "process"]
        assert len(process_def) == 1
        assert "inspect_getmembers" in process_def[0].dynamic_signals


class TestDirDetection:
    def test_dir_self_marks_class_members(self):
        code = """
class Validator:
    def check_email(self):
        pass

    def check_name(self):
        pass

    def run_checks(self):
        for name in dir(self):
            if name.startswith("check_"):
                getattr(self, name)()
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        check_defs = [d for d in v.defs if d.simple_name.startswith("check_")]
        for d in check_defs:
            assert "dir_self" in d.dynamic_signals, (
                f"{d.simple_name} should have dir_self signal"
            )

    def test_dir_class_name(self):
        code = """
class Config:
    debug = True
    verbose = False

attrs = dir(Config)
"""
        v = Visitor("mymod", "test.py")
        tree = ast.parse(code)
        v.visit(tree)
        v.finalize()

        config_members = [d for d in v.defs if "Config." in d.name]
        for d in config_members:
            assert "dir_class" in d.dynamic_signals


class TestWeightedHeuristicRefs:
    def _get_result(self, code, filename="mod.py"):
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / filename
            p.write_text(code)
            s = Skylos()
            return json.loads(s.analyze(tmpdir, thr=0))

    def test_heuristic_refs_in_json_output(self):
        code = """
class Service:
    def run(self):
        pass

obj.run()
"""
        result = self._get_result(code)
        all_items = []
        for cat in ["unused_functions", "unused_classes", "unused_variables"]:
            all_items.extend(result.get(cat, []))

        unused_names = {item["simple_name"] for item in all_items}
        assert "run" not in unused_names


class TestGetAttrScopeReduction:
    def _get_unused(self, files_dict):
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, code in files_dict.items():
                p = Path(tmpdir) / fname
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(code)
            s = Skylos()
            result = json.loads(s.analyze(tmpdir, thr=0, grep_verify=False))
            unused = set()
            for cat in ["unused_functions", "unused_classes", "unused_variables"]:
                for item in result.get(cat, []):
                    unused.add(item["simple_name"])
            return unused

    def test_common_name_cross_package_gets_lower_confidence(self):
        files = {
            "pkg/__init__.py": "",
            "pkg/service.py": """
class MyService:
    def get(self):
        '''This should be detected as unused'''
        return None
""",
            "pkg/main.py": """
data = {"key": "value"}
result = data.get("key")
""",
        }
        unused = self._get_unused(files)


class TestModuleReachabilityRefinement:
    def test_refine_removes_deep_modules(self):
        from skylos.module_reachability import ModuleReachabilityAnalyzer

        analyzer = ModuleReachabilityAnalyzer()
        analyzer.all_modules = {
            "pkg",
            "pkg.sub1",
            "pkg.sub2",
            "pkg.sub2.deep1",
            "pkg.sub2.deep2",
        }
        analyzer._getattr_packages = {"pkg"}
        analyzer.graph["pkg.sub1"].add("pkg.sub2.deep1")

        analyzer._expand_getattr_packages()

        assert "pkg.sub1" in analyzer.graph["pkg"]
        assert "pkg.sub2" in analyzer.graph["pkg"]
        assert "pkg.sub2.deep2" not in analyzer.graph["pkg"]


class TestUnderscoreVarargSuppression:
    """Regression: *_args and **_kwargs should not be flagged as unused."""

    def _get_unused_params(self, code):
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "mod.py"
            p.write_text(code)
            s = Skylos()
            result = json.loads(s.analyze(tmpdir, thr=0))
            return {item["simple_name"] for item in result.get("unused_parameters", [])}

    def test_underscore_args_not_flagged(self):
        code = """
def fail_render(*_args, **_kwargs):
    raise AssertionError("should not be called")

fail_render()
"""
        unused = self._get_unused_params(code)
        assert "_args" not in unused
        assert "_kwargs" not in unused

    def test_bare_underscore_vararg_not_flagged(self):
        code = """
def noop(*_):
    pass

noop()
"""
        unused = self._get_unused_params(code)
        assert "_" not in unused

    def test_regular_args_still_flagged(self):
        code = """
def func(used, unused_param):
    return used

func(1, 2)
"""
        unused = self._get_unused_params(code)
        assert "unused_param" in unused


class TestSameFileVariableUsage:
    def _get_unused(self, code):
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            p = Path(tmpdir) / "mod.py"
            p.write_text(code)
            s = Skylos()
            result = json.loads(s.analyze(tmpdir, thr=0, grep_verify=False))
            unused = set()
            for cat in ["unused_functions", "unused_classes", "unused_variables"]:
                for item in result.get(cat, []):
                    unused.add(item["simple_name"])
            return unused

    def test_variable_in_fstring_not_flagged(self):
        code = """
BASE_URL = "https://example.com/"

def build_url(slug):
    return f"{BASE_URL}{slug}/"

build_url("test")
"""
        unused = self._get_unused(code)
        assert "BASE_URL" not in unused

    def test_string_only_mention_does_not_suppress(self):
        """A name appearing only inside a string literal must NOT keep it alive."""
        code = """
def entry():
    pass

NAME = "entry"
"""
        unused = self._get_unused(code)
        assert "entry" in unused


class TestRelativeImportResolution:
    def _get_unused(self, files_dict):
        from skylos.analyzer import Skylos

        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, code in files_dict.items():
                p = Path(tmpdir) / fname
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(code)
            s = Skylos()
            result = json.loads(s.analyze(tmpdir, thr=0, grep_verify=False))
            unused = set()
            for cat in ["unused_functions", "unused_classes", "unused_variables"]:
                for item in result.get(cat, []):
                    unused.add(item["simple_name"])
            return unused

    def test_relative_import_keeps_constant_alive(self):
        files = {
            "pkg/__init__.py": "",
            "pkg/rules.py": 'BASE_URL = "https://example.com/"\n',
            "pkg/main.py": """
from .rules import BASE_URL

def build_url(slug):
    return f"{BASE_URL}{slug}/"

build_url("test")
""",
        }
        unused = self._get_unused(files)
        assert "BASE_URL" not in unused
