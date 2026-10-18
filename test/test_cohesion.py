import ast
import json

import pytest

from skylos.analyzer import analyze
from skylos.rules.quality.cohesion import LCOMRule, analyze_cohesion, _UnionFind


def _parse(code: str) -> ast.ClassDef:
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            return node
    raise ValueError("No class found")


def _run_lcom_rule(
    code: str, *, filename="test.py", project_root=None, **rule_kwargs
) -> list[dict]:
    tree = ast.parse(code)
    rule = LCOMRule(**rule_kwargs)
    context = {"filename": filename, "project_root": project_root}
    rule.visit_node(tree, context)

    findings = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            findings.extend(rule.visit_node(node, context) or [])
    return findings


class TestUnionFind:
    def test_basic_union(self):
        uf = _UnionFind()
        uf.make_set("a")
        uf.make_set("b")
        uf.make_set("c")
        uf.union("a", "b")
        assert uf.find("a") == uf.find("b")
        assert uf.find("a") != uf.find("c")

    def test_components(self):
        uf = _UnionFind()
        for x in "abcde":
            uf.make_set(x)
        uf.union("a", "b")
        uf.union("c", "d")
        comps = uf.components()
        assert len(comps) == 3

    def test_path_compression(self):
        uf = _UnionFind()
        for x in "abcd":
            uf.make_set(x)
        uf.union("a", "b")
        uf.union("b", "c")
        uf.union("c", "d")
        root = uf.find("d")
        assert uf.find("a") == root
        assert uf.find("b") == root
        assert uf.find("c") == root


class TestAnalyzeCohesion:
    def test_single_method_returns_none(self):
        node = _parse("""
class Foo:
    def bar(self):
        self.x = 1
""")
        result = analyze_cohesion(node)
        assert result is None

    def test_perfectly_cohesive(self):
        node = _parse("""
class Foo:
    def __init__(self):
        self.x = 0
        self.y = 0

    def update(self):
        owner = self
        owner.x += 1
        owner.y += 1

    def reset(self):
        owner = self
        owner.x = 0
        owner.y = 0
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 1

    def test_completely_uncohesive(self):
        node = _parse("""
class Foo:
    def method_a(self):
        def nested(self):
            return self.shared
        self.x = 1

    def method_b(self):
        def nested(self):
            return self.shared
        self.y = 2

    def method_c(self):
        def nested(self):
            return self.shared
        self.z = 3
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 3

    def test_self_calls_connect_methods(self):
        node = _parse("""
class Foo:
    def method_a(self):
        self.x = 1

    def method_b(self):
        self.y = 2
        owner = self
        owner.method_a()
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 1

    def test_static_methods_excluded(self):
        node = _parse("""
class Foo:
    def instance_a(self):
        self.x = 1

    def instance_b(self):
        self.x = 2

    @staticmethod
    def static_one():
        return 42

    @custom
    def unknown_binding(this):
        return this.unrelated
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["method_count_range"] == [2, 3]
        assert result["lcom4_lower_bound"] == 1
        assert result["lcom4_upper_bound"] == 2
        assert result["lcom5"] is None

    def test_classmethod_cls_attrs(self):
        node = _parse("""
class Foo:
    @classmethod
    def create(owner, /):
        owner.count = 0

    @classmethod
    def increment(owner, /):
        owner.count += 1
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 1  # Both access the same class receiver field.

    def test_property_backing_attribute(self):
        node = _parse("""
class Foo:
    def __init__(self):
        self._value = 0

    @property
    def value(self):
        return self._value

    def set_value(self, v):
        self._value = v
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 1

    def test_dataclass_exemption(self):
        node = _parse("""
@dataclass
class Config:
    host: str
    port: int

    def url(self):
        return f"http://{self.host}:{self.port}"

    def is_secure(self):
        return self.port == 443
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["is_dataclass"] is True

    def test_lcom5_normalized(self):
        node = _parse("""
class Foo:
    def a(self):
        self.x = 1

    def b(self):
        self.y = 2
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert 0.0 <= result["lcom5"] <= 1.0

    def test_cohesion_groups_reported(self):
        node = _parse("""
class Foo:
    def group1_a(self):
        self.x = 1
        class Callback:
            def invoke(callback):
                return self.y

    def group1_b(self):
        self.x = 2

    def group2_a(self):
        self.y = 3

    def group2_b(self):
        self.y = 4

    def optional_hook(self):
        pass
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 2  # Raw declared graph remains available.
        assert len(result["cohesion_groups"]) == 2
        assert result["implementation_lcom4_lower_bound"] == 1
        assert result["implementation_lcom4_upper_bound"] == 1
        assert result["declaration_only_methods"][0]["name"] == "optional_hook"

    def test_init_groups_dunders(self):
        node = _parse("""
class Foo:
    def __init__(self):
        self.name = ""
        self.value = 0

    def __str__(self):
        return self.name

    def unrelated(self):
        self.other = True
""")
        result = analyze_cohesion(node)
        assert result is not None
        assert result["lcom4"] == 2


class TestLCOMRule:
    def test_cohesive_class_no_finding(self):
        code = """
class Cohesive:
    def __init__(self):
        self.x = 0

    def get(self):
        return self.x

    def set(self, v):
        self.x = v

    def on_open(self):
        '''Optional lifecycle hook.'''

    def on_close(self):
        pass

    def abstract_operation(self):
        raise NotImplementedError
"""
        assert _run_lcom_rule(code, filename="service.py") == []

    def test_uncohesive_class_generates_finding(self):
        code = """
class Uncohesive:
    def a(self):
        self.x = 1

    def b(self):
        self.y = 2

    def c(self):
        self.z = 3
"""
        rule = LCOMRule(low_threshold=2)
        node = _parse(code)
        result = rule.visit_node(node, {"filename": "test.py"})
        assert result is not None
        assert len(result) == 1
        finding = result[0]
        assert finding["rule_id"] == "SKY-Q702"
        assert finding["lcom4"] == 3
        assert finding["declared_lcom4"] == 3
        assert finding["implementation_lcom4_lower_bound"] == 3
        assert finding["declaration_only_methods"] == []
        assert "cohesion_groups" in finding

    @pytest.mark.parametrize(
        ("filename", "expected_count"),
        [
            ("pkg/service.py", 1),
            ("pkg/tests/test_service.py", 0),
            ("tests/test_service.py", 0),
            ("examples/split.py", 0),
            # A test_ name without a test framework import is application code.
            ("pkg/test_service.py", 1),
        ],
    )
    def test_test_classes_do_not_get_cohesion_warnings(self, filename, expected_count):
        code = """
class IndependentCases:
    def a(self):
        self.x = 1

    def b(self):
        self.y = 2

    def c(self):
        self.z = 3
"""
        findings = _run_lcom_rule(code, filename=filename)
        assert len(findings) == expected_count

    def test_checkout_under_tests_folder_is_production(self, tmp_path):
        root = tmp_path / "tests" / "checkout"
        code = """
class IndependentCases:
    def a(self):
        self.x = 1

    def b(self):
        self.y = 2

    def c(self):
        self.z = 3
"""
        findings = _run_lcom_rule(
            code, filename=str(root / "pkg" / "service.py"), project_root=str(root)
        )
        assert [finding["name"] for finding in findings] == ["IndependentCases"]

    def test_dataclass_exempted(self):
        code = """
@dataclass
class Config:
    a: int
    b: str
    c: float

    def method_a(self):
        return self.a

    def method_b(self):
        return self.b

    def method_c(self):
        return self.c
"""
        rule = LCOMRule(low_threshold=2, high_threshold=4)
        node = _parse(code)
        result = rule.visit_node(node, {"filename": "test.py"})
        assert result is None

    @pytest.mark.parametrize(
        ("import_statement", "protocol_base"),
        [
            ("from typing import Protocol", "Protocol"),
            ("import typing", "typing.Protocol"),
            (
                "from typing_extensions import Protocol as Interface",
                "Interface",
            ),
            (
                "import typing_extensions as typing_ext",
                "typing_ext.Protocol",
            ),
            (
                "from typing import Protocol",
                "Protocol[int]",
            ),
        ],
    )
    def test_protocol_classes_exempted(self, import_statement, protocol_base):
        code = f"""
{import_statement}

class ParentCall({protocol_base}):
    def operation1(self) -> int: ...
    def operation2(self) -> int: ...
    def operation3(self) -> int: ...
"""
        assert _run_lcom_rule(code) == []

    def test_runtime_checkable_protocol_exempted(self):
        code = """
from typing import Protocol, runtime_checkable

@runtime_checkable
class ParentCall(Protocol):
    def operation1(self) -> int: ...
    def operation2(self) -> int: ...
    def operation3(self) -> int: ...
    def operation4(self) -> int: ...
    def operation5(self) -> int: ...
    def operation6(self) -> int: ...
"""
        assert _run_lcom_rule(code) == []

    def test_analyzer_exempts_runtime_checkable_protocol(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SKYLOS_JOBS", "1")
        (tmp_path / "skylos_cohesion.py").write_text(
            "from typing import Protocol, runtime_checkable\n"
            "\n"
            "@runtime_checkable\n"
            "class ParentCall(Protocol):\n"
            "    def operation1(self) -> int: ...\n"
            "    def operation2(self) -> int: ...\n"
            "    def operation3(self) -> int: ...\n"
            "    def operation4(self) -> int: ...\n"
            "    def operation5(self) -> int: ...\n"
            "    def operation6(self) -> int: ...\n",
            encoding="utf-8",
        )

        payload = json.loads(
            analyze(str(tmp_path), enable_quality=True, grep_verify=False)
        )
        findings = [
            finding
            for finding in payload.get("quality", [])
            if finding.get("rule_id") == "SKY-Q702"
        ]

        assert findings == []

    def test_unrelated_protocol_named_base_not_exempted(self):
        code = """
class Protocol:
    pass

class ParentCall(Protocol):
    def operation1(self):
        self.a = 1

    def operation2(self):
        self.b = 2

    def operation3(self):
        self.c = 3
"""
        findings = _run_lcom_rule(code)
        assert [finding["name"] for finding in findings] == ["ParentCall"]

    def test_protocol_subclass_not_exempted(self):
        code = """
from typing import Protocol

class ParentCall(Protocol):
    def operation1(self) -> int:
        return self.a

    def operation2(self) -> int:
        return self.b

    def operation3(self) -> int:
        return self.c

class ConcreteParentCall(ParentCall):
    def operation1(self):
        self.a = 1

    def operation2(self):
        self.b = 2

    def operation3(self):
        self.c = 3
"""
        findings = _run_lcom_rule(code)
        assert [finding["name"] for finding in findings] == ["ConcreteParentCall"]


SPLIT_TAIL = """
    def cache_put(self, key, value):
        self._cache[key] = value

    def cache_reset(self):
        self._cache = {}

    def record(self, name):
        self._metrics[name] = 1

    def reset_metrics(self):
        self._metrics = {}
"""


def _names(code: str) -> list[str]:
    return [finding["name"] for finding in _run_lcom_rule(code, filename="svc.py")]


class TestLCOMEdges:
    def test_all_abstract_class_exempted(self):
        code = """
from abc import ABC, abstractmethod

class Exporter(ABC):
    @abstractmethod
    def start(self):
        self.started = True

    @abstractmethod
    def export(self, item):
        self.exported += 1

    @abstractmethod
    def finish(self):
        self.finished = True

class PartlyAbstract(ABC):
    @abstractmethod
    def export(self, item): ...

    def start(self):
        self.started = True

    def count(self):
        self.n += 1

    def finish(self):
        self.finished = True
"""
        assert _names(code) == ["PartlyAbstract"]

    def test_property_getter_and_setter_attributes_merge(self):
        code = """
class Thermostat:
    @property
    def target(self):
        return self._target_c * self._unit_factor

    @target.setter
    def target(self, value):
        self._target_c = value

    def set_units(self, factor):
        self._unit_factor = factor

    def log_reading(self, value):
        self._readings.append(value)

    def clear_readings(self):
        self._readings = []
"""
        result = analyze_cohesion(_parse(code))
        assert result["implementation_lcom4_lower_bound"] == 2
        assert _names(code) == []

    def test_bound_method_reference_and_property_read_link(self):
        code = """
from functools import cached_property

class Ticker:
    def __init__(self, loop):
        self.loop = loop

    def start(self):
        self.loop.call_later(1.0, self._on_tick)
        self.loop.set_exception_handler(self._on_error)

    def _on_tick(self):
        self.ticks += 1

    def _on_error(self, loop, context):
        self.last_error = context

class Zone:
    def __init__(self, tz):
        self._tz = tz

    @cached_property
    def offset(self):
        return compute(self._tz)

    def shift(self, value):
        return value + self.offset

    def unshift(self, value):
        return value - self.offset

    def rename(self, label):
        self.label = label
"""
        assert _names(code) == []

    @pytest.mark.parametrize(
        "constructor",
        ["cls()", "type(self)()", "self.__class__()"],
    )
    def test_constructor_through_receiver_links_init(self, constructor):
        decorator = "@classmethod\n    " if constructor == "cls()" else ""
        receiver = "cls" if constructor == "cls()" else "self"
        code = f"""
class Ledger:
    def __init__(self):
        self.entries = []

    def add(self, entry):
        self.entries.append(entry)

    {decorator}def fork({receiver}):
        child = {constructor}
        child.parent_marker = {receiver}.marker
        return child

    def mark(self, label):
        self.marker = label

    def audit(self):
        self.audit_log = []

    def audit_report(self):
        return list(self.audit_log)
"""
        assert analyze_cohesion(_parse(code))["implementation_lcom4_lower_bound"] == 2

    def test_implicit_dunder_use_links_dunder(self):
        code = """
class Inventory:
    def __init__(self):
        self._items = {}

    def __len__(self):
        return len(self._items)

    def __getitem__(self, key):
        return self._items[key]

    def __setitem__(self, key, value):
        self._items[key] = value

    def __delitem__(self, key):
        del self._items[key]

    def __contains__(self, key):
        return key in self._items

    def __iter__(self):
        return iter(self._items)

    def __bool__(self):
        return bool(self._items)

    def __str__(self):
        return str(self._items)

    def __repr__(self):
        return repr(self._items)

    def summarize(self):
        self.last_count = len(self)

    def lookup(self, key):
        self.last_key = key
        return self[key]

    def store(self, key, value):
        self.stored = key
        self[key] = value

    def drop(self, key):
        self.dropped = key
        del self[key]

    def check(self, key):
        self.checks += 1
        return key in self

    def listing(self):
        self.listed = [key for key in self]

    def guard(self):
        if self:
            self.guarded = True

    def render(self):
        self.rendered = f"{self}"

    def debug(self):
        self.debug_text = repr(self)
"""
        assert analyze_cohesion(_parse(code))["implementation_lcom4_lower_bound"] == 1

    def test_escaping_receiver_is_not_a_group_by_itself(self):
        code = (
            """
class Report:
    def __init__(self, rows):
        self.rows = rows

    def total(self):
        return sum(row.amount for row in self.rows)

    def render(self, template):
        self.render_count += 1
        return template.render(report=self)

    def publish(self, bus):
        self.published = True
        bus.send(self)

    def chain(self):
        self.chained = True
        return self

class EscapeStillSplit:
    def register(self, registry):
        self.registered = True
        registry.add(self)

    def issue(self, user):
        self._tokens[user] = object()

    def revoke_all(self):
        self._tokens = {}
"""
            + SPLIT_TAIL
        )
        assert _names(code) == ["EscapeStillSplit"]
        finding = _run_lcom_rule(code, filename="svc.py")[0]
        assert finding["value"] == 3
        assert finding["receiver_escapes"] == ["register"]

    def test_unnamed_attribute_writes_reach_unassigned_fields(self):
        code = """
class ConfigView:
    def __init__(self, changes, defaults, prefix=None):
        self.__dict__.update(changes=changes, defaults=defaults, prefix=prefix)

    def get(self, key):
        return self.changes.get(key)

    def lookup_default(self, key):
        return self.defaults[key]

    def with_prefix(self, key):
        return f"{self.prefix}{key}"

class DynamicBag:
    def configure(self, **options):
        for name, value in options.items():
            setattr(self, name, value)

    def size(self):
        self.sized = len(self.items)

    def color(self):
        self.colored = self.tint

    def shape(self):
        self.shaped = self.form
"""
        assert _names(code) == []

    def test_stateless_methods_are_not_groups(self):
        code = """
class StatsMiddleware:
    def __init__(self, stats):
        self.stats = stats

    def process_request(self, request, spider):
        return None

    def process_exception(self, request, exception, spider):
        print("failed", request)

    def process_response(self, request, response, spider):
        self.stats.inc_value("responses")
        return response
"""
        result = analyze_cohesion(_parse(code))
        assert result["implementation_lcom4_lower_bound"] == 1
        assert result["excluded_stateless_methods"] == [
            "process_exception",
            "process_request",
        ]
        assert _names(code) == []

    def test_groups_on_inherited_state_only_are_not_reported(self):
        code = """
class Command(BaseCommand):
    def syntax(self):
        return "<name>"

    def run(self, args, opts):
        self.settings.set("FORCE", opts.force)

    def show_help(self):
        self.logger.info("help")

    def close(self):
        self.process.stop()
"""
        result = analyze_cohesion(_parse(code))
        assert result["implementation_lcom4_lower_bound"] == 3
        assert result["implementation_state_groups"] == 0
        assert _names(code) == []

    def test_two_own_state_clusters_plus_inherited_group_reported(self):
        code = (
            "class Helper(Base):"
            + SPLIT_TAIL
            + """
    def shutdown(self):
        self.engine.stop()
"""
        )
        findings = _run_lcom_rule(code, filename="svc.py")
        assert [(f["name"], f["value"]) for f in findings] == [("Helper", 3)]
        assert _names("class TwoClustersOnly:" + SPLIT_TAIL) == []
