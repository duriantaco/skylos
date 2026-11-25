import ast

import pytest

from skylos.rules.danger.django_registry_defaults import django_defaults_for
from skylos.rules.danger.oslo_config_options import ConfigProject

REGISTRY = """\
class Store:
    def __init__(self):
        self.by_scope = {"service": {}, "other": {}}
    def register(self, group, panel):
        self.by_scope[group][panel.section] = {"schema": panel, "values": {}}
    def refresh(self, group):
        for section, entry in self.by_scope[group].items():
            panel = entry["schema"](saved=False)
            for name, field in panel.fields.items():
                entry["values"][name] = field.initial
    def default(self, group, section, name):
        return self.by_scope[group][section]["values"][name]
store = Store()
spare = Store()

class Preferences:
    def __init__(self, layer, persisted):
        self.layer = layer
        self.persisted = persisted
        store.refresh(layer)
    def value(self, name, section=None):
        name = name.lower()
        try:
            initial = store.default(self.layer, section, name)
        except KeyError:
            raise
        if section in self.persisted:
            return self.persisted[section].get(name, initial)
        return initial
"""
MODEL = """\
from django.db import models
from pkg import registry
class Profile(models.Model):
    overrides = models.JSONField(default={})
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.policy = registry.Preferences("service", self.overrides)
"""
FACADE = r"""from pkg import models
import inspect
import re

def namespace():
    module = inspect.getmodule(inspect.stack()[2][0]).__name__
    matched = re.match(r"(?:pkg\.)?([^.]+)", module)
    if matched is not None:
        return matched.group(1)
    return None

def active():
    return models.Profile.objects.first()
def find(name, section=None, **kwargs):
    if section is None:
        section = namespace()
    return active().policy.value(name, section=section, **kwargs)
"""
FORM = """\
from django import forms
from pkg import registry
class Panel(forms.Form):
    section = "mail"
    width = forms.ChoiceField(choices=[(1024, 'Small'), (2048, 'Large')], initial=1024)
    def __init__(self, *args, **kwargs):
        restore = kwargs.pop("saved", True)
        super().__init__(*args, **kwargs)
        if not args and restore:
            self.restore()
    def restore(self):
        self.fields["width"].initial = 4096
def start():
    registry.store.register("service", Panel)
"""
APP = """\
from django.apps import AppConfig
from pkg.panels import start
class PreferencesApp(AppConfig):
    def ready(self):
        start()
"""
READER = """\
from pkg.api import find
def build():
    return find("WIDTH")
"""
FILES = {
    "pkg/registry.py": REGISTRY,
    "pkg/models.py": MODEL,
    "pkg/api.py": FACADE,
    "pkg/panels.py": FORM,
    "pkg/apps.py": APP,
    "pkg/mail/job.py": READER,
}


def results(tmp_path, modify=None):
    sources = FILES.copy()
    if modify:
        file, before, after = modify
        assert before in sources[file]
        sources[file] = sources[file].replace(before, after)
    project = ConfigProject(tmp_path, True)
    for name, code in sources.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(code)
        project._add_python(path, code)
    project._index()
    reader = project.by_path[tmp_path / "pkg/mail/job.py"]
    lookup = next(c for c, _ in reader.calls if isinstance(c.func, ast.Name))
    return [
        (path.name, call.lineno, name, size)
        for path, call, name, size in django_defaults_for(project, reader, lookup)
    ]


@pytest.mark.parametrize("bits", [1024, 2048])
def test_only_registered_initial_reaches_the_lookup(tmp_path, bits):
    assert results(tmp_path, ("pkg/panels.py", "initial=1024", f"initial={bits}")) == [
        ("panels.py", 5, "mail.width", bits)
    ]


@pytest.mark.parametrize(
    ("file", "before", "after"),
    [
        ("pkg/panels.py", "registry.store.register", "registry.spare.register"),
        ("pkg/apps.py", "start()", "pass"),
        ("pkg/apps.py", "PreferencesApp(AppConfig)", "PreferencesApp(object)"),
        (
            "pkg/registry.py",
            'entry["values"][name] = field.initial',
            'entry["values"][name] = 4096',
        ),
        ("pkg/registry.py", "self.persisted[section].get", "{name: 4096}.get"),
        ("pkg/registry.py", "if section in self.persisted:", "if True:"),
        ("pkg/registry.py", "saved=False", "saved=True"),
        (
            "pkg/registry.py",
            'self.by_scope[group][section]["values"][name]',
            'self.by_scope[group][section]["values"]["always"]',
        ),
        ("pkg/models.py", '"service", self.overrides', '"other", self.overrides'),
        (
            "pkg/models.py",
            '"service", self.overrides',
            '"service", {"mail": {"width": 4096}}',
        ),
        ("pkg/models.py", "default={}", 'default={"mail": {"width": 4096}}'),
        (
            "pkg/models.py",
            "self.policy =",
            'self.overrides = {"mail": {"width": 4096}}\n        self.policy =',
        ),
        (
            "pkg/models.py",
            "overrides = models.JSONField",
            "objects = OtherManager()\n    overrides = models.JSONField",
        ),
        (
            "pkg/registry.py",
            "store.refresh(layer)",
            'store.refresh(layer)\n        self.persisted["mail"] = {"width": 4096}',
        ),
        ("pkg/panels.py", "Panel(forms.Form)", "Panel(object)"),
        ("pkg/panels.py", 'section = "mail"', 'section = "frontend"'),
        ("pkg/api.py", "stack()[2]", "stack()[1]"),
        ("pkg/api.py", "(?:pkg", "(?:other"),
        ("pkg/api.py", "def find(name, section=None", 'def find(name, section="other"'),
        ("pkg/mail/job.py", 'find("WIDTH")', 'find("WIDTH", runtime_namespace())'),
        ("pkg/mail/job.py", 'find("WIDTH")', 'find("WIDTH", "unused")'),
        ("pkg/panels.py", "if not args and restore:", "if True:"),
        ("pkg/panels.py", "forms.ChoiceField(", "unknown.ChoiceField("),
        (
            "pkg/panels.py",
            "def start():",
            (
                'class Other(forms.Form):\n    section = "mail"\n'
                'def start():\n    registry.store.register("service", Other)'
            ),
        ),
    ],
)
def test_abstains_on_disconnected_or_replaced_defaults(tmp_path, file, before, after):
    assert not results(tmp_path, (file, before, after))


def test_explicit_scope_can_select_another_module(tmp_path):
    assert results(
        tmp_path, ("pkg/mail/job.py", 'find("WIDTH")', 'find("width", section="mail")')
    ) == [("panels.py", 5, "mail.width", 1024)]


NATIVE_FORM = """\
from django import forms as controls
class Preferences(controls.Form):
    key_size = controls.ChoiceField(choices=[(1024, "Small"), (2048, "Large")], initial=1024)
"""
NATIVE_API = """\
from prefs import Preferences as Options
def read(key):
    return Options.base_fields[key].initial
"""
NATIVE_CONSUMER = """\
from api import read
import subprocess
def create():
    subprocess.run(["openssl", "genrsa", str(read("key_size"))])
"""


def native_findings(
    root, form=NATIVE_FORM, getter=NATIVE_API, extra="", source=NATIVE_CONSUMER
):
    from skylos.rules.danger.danger import scan_ctx

    files = {
        "prefs.py": form,
        "api.py": getter,
        "consumer.py": source,
        "customize.py": extra,
    }
    for name, code in files.items():
        (root / name).write_text(code)
    return [
        (f["line"], f["message"])
        for f in scan_ctx(root, [root / name for name in files])
        if f["rule_id"] == "SKY-D383"
    ]


def test_native_form_class_field_feeds_rsa_operand(tmp_path):
    [(line, message)] = native_findings(tmp_path)
    assert line == 3
    assert "Preferences.key_size" in message and "1024" in message
    assert not native_findings(
        tmp_path, form=NATIVE_FORM.replace("initial=1024", "initial=2048")
    )


@pytest.mark.parametrize(
    ("source", "before", "after"),
    [
        ("form", "controls.Form", "object"),
        ("form", "controls.ChoiceField", "UnrelatedField"),
        ("form", "class Preferences(", "@replace\nclass Preferences("),
        (
            "form",
            "class Preferences(controls.Form)",
            "class Preferences(controls.Form, metaclass=Meta)",
        ),
        ("form", "initial=1024", "initial=runtime_default()"),
        ("getter", "Options.base_fields[key]", 'Options.base_fields["different"]'),
        ("getter", "return Options.", 'key = "other"\n    return Options.'),
        ("getter", "def read(", "async def read("),
        ("form", "initial=1024)", "initial=1024)\n    key_size.initial = 4096"),
        ("source", 'read("key_size")', 'read("other")'),
    ],
)
def test_native_reader_requires_genuine_field_and_matching_lookup(
    tmp_path, source, before, after
):
    files = {"form": NATIVE_FORM, "getter": NATIVE_API, "source": NATIVE_CONSUMER}
    files[source] = files[source].replace(before, after)
    assert not native_findings(tmp_path, **files)


@pytest.mark.parametrize(
    "replacement",
    [
        'Alias.base_fields["key_size"].initial = 4096',
        'Alias.declared_fields["key_size"] = other',
        "table = Alias.base_fields\ntable.clear()",
        'entry = Alias.base_fields["key_size"]\nentry.initial = 4096',
        'setattr(Alias, "base_fields", {})',
        "def adjust(cls): cls.base_fields.clear()\nadjust(Alias)",
        'class Child(Alias): pass\nChild.base_fields["key_size"].initial = 4096',
        "import prefs\nprefs.Preferences = OtherClass",
        'import prefs\nsetattr(prefs, "Preferences", OtherClass)',
    ],
)
def test_native_reader_rejects_replaced_or_escaped_field(tmp_path, replacement):
    assert not native_findings(
        tmp_path, extra="from prefs import Preferences as Alias\n" + replacement
    )


def test_native_form_inheritance_and_independent_field_table(tmp_path):
    getter = NATIVE_API.replace("Preferences as Options", "Options")
    form = NATIVE_FORM + "\nclass Options(Preferences): pass\n"
    separate = """
from django import forms
class Other(forms.Form):
    key_size = forms.IntegerField(initial=2048)
Other.base_fields["key_size"].initial = 4096
"""
    [(line, message)] = native_findings(
        tmp_path, form=form, getter=getter, extra=separate
    )
    assert line == 3 and "Options.key_size" in message


TYPED_FORM = NATIVE_FORM.replace(
    "controls.ChoiceField(", "controls.TypedChoiceField(coerce=int, "
)
MAPPING_API = """\
from prefs import Preferences
def setting(policy, feature):
    if feature in policy:
        return int(policy[feature])
    return int(Preferences.base_fields[feature].initial)
"""
MAPPING_SOURCE = """\
from api import setting
import subprocess
def create(policy: dict[str, int]):
    bits = setting(policy, "key_size")
    subprocess.run(["openssl", "genrsa", str(bits)])
"""


def mapping_findings(
    root, form=TYPED_FORM, getter=MAPPING_API, source=MAPPING_SOURCE, extra=""
):
    return native_findings(root, form=form, getter=getter, source=source, extra=extra)


def test_typed_choice_and_unconstrained_override_map(tmp_path):
    [(line, message)] = mapping_findings(tmp_path)
    assert line == 3 and "Preferences.key_size" in message and "1024" in message
    assert not mapping_findings(
        tmp_path, form=TYPED_FORM.replace("initial=1024", "initial=2048")
    )


@pytest.mark.parametrize(
    ("label", "old", "new"),
    [
        ("form", "coerce=int", "coerce=str"),
        ("form", "class Preferences", "int = str\nclass Preferences"),
        (
            "getter",
            "def setting(",
            "import builtins\nbuiltins.int = fixed\ndef setting(",
        ),
        ("getter", "def setting(", "int = lambda value: 4096\ndef setting("),
        ("getter", "return int(Preferences", "return 4096 + int(Preferences"),
        ("getter", "if feature in policy:", "if feature not in policy:"),
        ("getter", "return int(policy[feature])", 'return int(policy["another"])'),
        ("getter", "return int(Preferences", "return 4096\n    return int(Preferences"),
        (
            "getter",
            "def setting(policy, feature)",
            'def setting(policy, feature="other")',
        ),
        (
            "source",
            'setting(policy, "key_size")',
            'setting({"key_size": 4096}, "key_size")',
        ),
        ("source", 'setting(policy, "key_size")', 'setting(policy.copy(), "key_size")'),
        (
            "source",
            'setting(policy, "key_size")',
            'setting({"unrelated": compute()}, "key_size")',
        ),
        ("source", "bits = setting", 'policy["key_size"] = 4096\n    bits = setting'),
        (
            "source",
            "bits = setting",
            'if "key_size" not in policy: return\n    bits = setting',
        ),
        ("source", "bits = setting", "fixed = policy\n    bits = setting"),
        ("source", "str(bits)])", 'str(bits)])\ncreate({"key_size": 4096})'),
        ("source", "policy: dict[str, int]", "policy: KnownNonemptyPolicy"),
    ],
)
def test_override_requires_verified_conversion_and_reachable_missing_key(
    tmp_path, label, old, new
):
    inputs = {"form": TYPED_FORM, "getter": MAPPING_API, "source": MAPPING_SOURCE}
    assert old in inputs[label]
    inputs[label] = inputs[label].replace(old, new)
    assert not mapping_findings(tmp_path, **inputs)


def test_literal_missing_key_and_swapped_arguments(tmp_path):
    source = MAPPING_SOURCE.replace(
        'setting(policy, "key_size")', 'setting("key_size", {})'
    )
    getter = MAPPING_API.replace("setting(policy, feature)", "setting(feature, policy)")
    assert len(mapping_findings(tmp_path, getter=getter, source=source)) == 1
    assert (
        len(
            mapping_findings(
                tmp_path, source=MAPPING_SOURCE + '\ncreate({"unrelated": 1})\n'
            )
        )
        == 1
    )


@pytest.mark.parametrize("test", ["feature in policy", "feature not in policy"])
@pytest.mark.parametrize("layout", ["early", "else", "expression"])
def test_native_getter_reads_the_default_only_on_the_missing_branch(
    tmp_path, test, layout
):
    stored = "int(policy[feature])"
    default = "Preferences.base_fields[feature].initial"
    yes, no = (default, stored) if "not in" in test else (stored, default)
    if layout == "expression":
        branch = f"return {yes} if {test} else {no}"
    elif layout == "else":
        branch = f"if {test}:\n        return {yes}\n    else:\n        return {no}"
    else:
        branch = f"if {test}:\n        return {yes}\n    return {no}"
    getter = (
        "from prefs import Preferences\ndef setting(policy, feature):\n    " + branch
    )
    [(line, message)] = mapping_findings(tmp_path, getter=getter)
    assert line == 3 and "Preferences.key_size" in message
    assert not mapping_findings(
        tmp_path,
        getter=getter,
        source=MAPPING_SOURCE + '\ncreate({"key_size": 4096})\n',
    )


@pytest.mark.parametrize(
    "body",
    [
        "if feature not in policy:\n        return Preferences.base_fields[feature].initial\n    return policy['unrelated']",
        "if feature not in policy:\n        return policy[feature]\n    return Preferences.base_fields[feature].initial",
        "return Preferences.base_fields[feature].initial if feature in policy else policy[feature]",
        "if feature not in policy:\n        return Preferences.base_fields[feature].initial\n    else:\n        policy.clear()\n        return policy[feature]",
        "if feature not in policy:\n        return Preferences.base_fields[feature].initial\n    return policy[feature]\n    return 4096",
    ],
)
def test_malformed_or_inverted_getters_remain_quiet(tmp_path, body):
    getter = "from prefs import Preferences\ndef setting(policy, feature):\n    " + body
    assert not mapping_findings(tmp_path, getter=getter)


@pytest.mark.parametrize(
    ("supplied", "before_call", "entry_call", "bits"),
    [
        ("{}", "", "", [1024]),
        ('{"key_size": 4096}', "", "", []),
        ("preferences", "", "", [1024]),
        ("preferences", 'preferences["key_size"] = 4096', "", []),
        ("preferences", 'if "key_size" not in preferences: return', "", []),
        ("preferences", "", 'issue(obj, {"key_size": 4096})', []),
    ],
)
def test_method_forwards_its_callers_mapping(
    tmp_path, supplied, before_call, entry_call, bits
):
    getter = MAPPING_API.replace(
        "if feature in policy:\n        return int(policy[feature])\n    return int(Preferences.base_fields[feature].initial)",
        "if feature not in policy:\n        return Preferences.base_fields[feature].initial\n    return policy[feature]",
    )
    sources = {
        "prefs.py": TYPED_FORM,
        "settings_api.py": getter,
        "policy.py": "from settings_api import setting\nclass Policy:\n    def size(self, saved):\n        return setting(saved, 'key_size')\n",
        "issue.py": f"def issue(obj, preferences):\n    {before_call}\n    return obj.size({supplied})\n{entry_call}\n",
    }
    project = ConfigProject(tmp_path, True)
    for filename, source in sources.items():
        path = tmp_path / filename
        path.write_text(source)
        project._add_python(path, source)
    project._index()
    policy = project.by_path[tmp_path / "policy.py"]
    caller = project.by_path[tmp_path / "issue.py"]
    getter_call = next(c for c, _ in policy.calls if isinstance(c.func, ast.Name))
    method_call = next(c for c, _ in caller.calls if isinstance(c.func, ast.Attribute))
    forwarded = (caller, method_call, {"saved": method_call.args[0]})
    assert [
        size
        for _, _, _, size in django_defaults_for(
            project, policy, getter_call, forwarded=forwarded
        )
    ] == bits
