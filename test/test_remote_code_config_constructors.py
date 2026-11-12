"""Inert settings containers do not load remote code; unknown callees may."""

import ast
import textwrap

import pytest

from skylos.rules.danger.danger import scan_file_with_tree
from skylos.rules.danger.danger_ml import model_deserialization
from test.fixture_paths import write_fixture


ISSUE_SOURCE = '''"""Records a user's choice; loads nothing."""

import argparse
from dataclasses import dataclass


@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool


def recorded() -> tuple[argparse.Namespace, RunSettings]:
    args = argparse.Namespace(trust_remote_code=True)
    settings = RunSettings(model="org/m", trust_remote_code=True)
    return args, settings
'''


def _assert_d213(
    tmp_path, source, expected, *, source_prefilter=True, extra_files=None
):
    source = textwrap.dedent(source).lstrip("\n")
    for name, content in (extra_files or {}).items():
        write_fixture(tmp_path, name, textwrap.dedent(content).lstrip("\n"))
    path = write_fixture(tmp_path, "settings.py", source)
    findings = []
    scan_file_with_tree(
        ast.parse(source, filename=str(path)),
        path,
        findings,
        source=source if source_prefilter else None,
        project_root=tmp_path,
    )
    rows = [row for row in findings if row["rule_id"] == "SKY-D213"]
    assert [(row["line"], row["severity"]) for row in rows] == expected
    assert all(row["file"] == str(path) for row in rows)


def _assert_last_call_retained(tmp_path, source, *, extra_files=None):
    source = textwrap.dedent(source).lstrip("\n")
    _assert_d213(
        tmp_path,
        source,
        [(len(source.splitlines()), "HIGH")],
        extra_files=extra_files,
    )


@pytest.mark.parametrize("source_prefilter", [True, False])
def test_issue_1215_namespace_and_frozen_record_only_store_settings(
    tmp_path, source_prefilter
):
    assert "argparse.Namespace(" in ISSUE_SOURCE.splitlines()[13]
    assert "RunSettings(" in ISSUE_SOURCE.splitlines()[14]
    _assert_d213(tmp_path, ISSUE_SOURCE, [], source_prefilter=source_prefilter)


@pytest.mark.parametrize(
    ("imports", "call"),
    [
        ("import argparse as ap", "ap.Namespace(trust_remote_code=True)"),
        (
            "from argparse import Namespace as Options",
            "Options(trust_remote_code=True)",
        ),
    ],
    ids=["module-alias", "constructor-import-alias"],
)
def test_proven_namespace_import_aliases_only_store_settings(tmp_path, imports, call):
    _assert_d213(tmp_path, imports + "\nconfig = " + call + "\n", [])


@pytest.mark.parametrize(
    ("imports", "decorator"),
    [
        ("import dataclasses as records", "records.dataclass(frozen=True)"),
        ("from dataclasses import dataclass as record", "record(frozen=True)"),
    ],
    ids=["module-alias", "decorator-import-alias"],
)
def test_proven_frozen_dataclass_aliases_only_store_settings(
    tmp_path, imports, decorator
):
    source = (
        imports + "\n@" + decorator + "\nclass RunSettings:\n"
        "    model: str\n"
        "    trust_remote_code: bool\n"
        'config = RunSettings(model="org/m", trust_remote_code=True)\n'
    )
    _assert_d213(tmp_path, source, [])


def test_frozen_record_with_literal_defaults_only_stores_settings(tmp_path):
    source = """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    model: str = "org/m"
    trust_remote_code: bool = False
config = RunSettings(model="org/other", trust_remote_code=True)
"""
    _assert_d213(tmp_path, source, [])


@pytest.mark.parametrize(
    "source",
    [
        "from transformers import AutoModel as Model\n"
        'Model.from_pretrained("org/m", trust_remote_code=True)\n',
        "from datasets import load_dataset as read_dataset\n"
        'read_dataset("org/data", trust_remote_code=True)\n',
        "from langchain_huggingface import HuggingFaceEmbeddings as Embeddings\n"
        'Embeddings(model_name="org/m", model_kwargs={"trust_remote_code": True})\n',
        "import mlx_lm as models\n"
        'models.load("org/m", tokenizer_config={"trust_remote_code": True})\n',
        'configure_model("org/m", trust_remote_code=True)\n',
        'UnknownSettings(model="org/m", trust_remote_code=True)\n',
    ],
    ids=[
        "transformers-loader-alias",
        "datasets-loader-alias",
        "langchain-options",
        "mlx-tokenizer-options",
        "unresolved-function",
        "unresolved-constructor",
    ],
)
def test_model_loaders_and_unresolved_calls_keep_remote_code_finding(tmp_path, source):
    _assert_last_call_retained(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
    def __init__(self, model, trust_remote_code):
        load_model(model, trust_remote_code=trust_remote_code)
config = RunSettings(model="org/m", trust_remote_code=True)
""",
        """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
    def __post_init__(self):
        load_model(self.model, trust_remote_code=self.trust_remote_code)
config = RunSettings(model="org/m", trust_remote_code=True)
""",
        """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
    def __new__(cls, model, trust_remote_code):
        return load_model(model, trust_remote_code=trust_remote_code)
config = RunSettings(model="org/m", trust_remote_code=True)
""",
        """from dataclasses import dataclass
from external_settings import Base
@dataclass(frozen=True)
class RunSettings(Base):
    model: str
    trust_remote_code: bool
config = RunSettings(model="org/m", trust_remote_code=True)
""",
        """from dataclasses import dataclass
from external_settings import wrap
@wrap
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
config = RunSettings(model="org/m", trust_remote_code=True)
""",
        """from dataclasses import dataclass, field
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
    model: str = field(default_factory=load_model)
config = RunSettings(trust_remote_code=True)
""",
        """from dataclasses import dataclass
class ModelDescriptor:
    def __get__(self, instance, owner):
        return "org/m"
    def __set__(self, instance, value):
        load_model(value, trust_remote_code=instance.trust_remote_code)
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
    model: str = ModelDescriptor()
config = RunSettings(model="org/m", trust_remote_code=True)
""",
        """from dataclasses import dataclass
@dataclass(frozen=False)
class RunSettings:
    model: str
    trust_remote_code: bool
config = RunSettings(model="org/m", trust_remote_code=True)
""",
    ],
    ids=[
        "custom-init",
        "post-init",
        "custom-new",
        "inherited-behavior",
        "extra-decorator",
        "default-factory",
        "descriptor-default",
        "outside-frozen-proof-scope",
    ],
)
def test_unsupported_record_construction_is_not_assumed_inert(tmp_path, source):
    _assert_last_call_retained(tmp_path, source)


def test_record_name_rebound_to_loader_is_not_assumed_inert(tmp_path):
    source = """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
RunSettings = load_model
config = RunSettings(model="org/m", trust_remote_code=True)
"""
    _assert_last_call_retained(tmp_path, source)


def test_replaced_dataclass_decorator_does_not_prove_inert_construction(tmp_path):
    source = """from dataclasses import dataclass
dataclass = make_model_loader
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
config = RunSettings(model="org/m", trust_remote_code=True)
"""
    _assert_last_call_retained(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        """import argparse
argparse.Namespace = load_model
config = argparse.Namespace(trust_remote_code=True)
""",
        """import argparse
argparse.Namespace.__init__ = load_model
config = argparse.Namespace(trust_remote_code=True)
""",
        """import argparse
def recorded(argparse):
    return argparse.Namespace(trust_remote_code=True)
""",
        """from argparse import Namespace as Options
def recorded(Options):
    return Options(trust_remote_code=True)
""",
        """import argparse
recorded = lambda argparse: argparse.Namespace(trust_remote_code=True)
""",
        """import argparse
def recorded(providers):
    return [argparse.Namespace(trust_remote_code=True) for argparse in providers]
""",
        """import argparse
provider = argparse
provider.Namespace = load_model
config = argparse.Namespace(trust_remote_code=True)
""",
        """from argparse import Namespace as Options
change_constructor(Options)
config = Options(trust_remote_code=True)
""",
    ],
    ids=[
        "namespace-replaced",
        "constructor-init-replaced",
        "module-name-parameter",
        "constructor-name-parameter",
        "lambda-shadow",
        "comprehension-shadow",
        "provider-alias-mutation",
        "constructor-escape",
    ],
)
def test_namespace_spelling_without_provider_proof_keeps_finding(tmp_path, source):
    _assert_last_call_retained(tmp_path, source)


@pytest.mark.parametrize("provider", ["argparse", "dataclasses"])
def test_project_owned_lookalike_provider_is_not_the_standard_library(
    tmp_path, provider
):
    if provider == "argparse":
        source = """import argparse
config = argparse.Namespace(trust_remote_code=True)
"""
        implementation = """def Namespace(**kwargs):
    return load_model(**kwargs)
"""
    else:
        source = """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
config = RunSettings(model="org/m", trust_remote_code=True)
"""
        implementation = """def dataclass(**options):
    def decorate(cls):
        return load_model
    return decorate
"""
    _assert_last_call_retained(
        tmp_path, source, extra_files={provider + ".py": implementation}
    )


def test_namespace_exemption_still_visits_nested_model_loader(tmp_path):
    source = """import argparse
from transformers import AutoModel
config = argparse.Namespace(
    model=AutoModel.from_pretrained("org/m", trust_remote_code=True),
    trust_remote_code=True,
)
"""
    _assert_d213(tmp_path, source, [(4, "HIGH")])


def test_frozen_record_exemption_still_visits_nested_model_loader(tmp_path):
    source = """from dataclasses import dataclass
from transformers import AutoModel
@dataclass(frozen=True)
class RunSettings:
    model: str
    trust_remote_code: bool
config = RunSettings(
    model=AutoModel.from_pretrained("org/m", trust_remote_code=True),
    trust_remote_code=True,
)
"""
    _assert_d213(tmp_path, source, [(8, "HIGH")])


@pytest.mark.parametrize(
    "source",
    [
        """import argparse
def recorded(factory, choose):
    if choose:
        factory = argparse.Namespace
    return factory(trust_remote_code=True)
""",
        """from argparse import Namespace
def recorded(factory=Namespace):
    return factory(trust_remote_code=True)
""",
        """import argparse
config = argparse.Namespace(__class__=ModelLoader, trust_remote_code=True)
""",
        """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
RunSettings.__init__ = load_model
config = RunSettings(trust_remote_code=True)
""",
        """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
change_constructor(RunSettings)
config = RunSettings(trust_remote_code=True)
""",
        """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
def callback():
    return None
configure(callback)
config = RunSettings(trust_remote_code=True)
""",
    ],
    ids=[
        "conditional-parameter-alias",
        "default-parameter-alias",
        "namespace-dunder-key",
        "record-init-replaced",
        "record-capability-escape",
        "callback-globals-escape",
    ],
)
def test_ambiguous_or_escaped_constructor_cannot_supply_safety_proof(tmp_path, source):
    _assert_last_call_retained(tmp_path, source)


@pytest.mark.parametrize("during_construction", [True, False])
def test_optional_constructor_proof_failure_keeps_real_finding(
    tmp_path, monkeypatch, during_construction
):
    class BrokenProof:
        def __init__(self, *args, **kwargs):
            if during_construction:
                raise RuntimeError("proof unavailable")

        def is_data_call(self, node):
            raise RuntimeError("proof unavailable")

    # The unchanged baseline has no proof hook; its ordinary detection remains
    # the expected control when this optional attribute is unused.
    monkeypatch.setattr(
        model_deserialization, "DataConstructorProof", BrokenProof, raising=False
    )
    _assert_last_call_retained(
        tmp_path,
        "from transformers import AutoModel\n"
        'AutoModel.from_pretrained("org/m", trust_remote_code=True)\n',
    )


@pytest.mark.parametrize(
    "source",
    [
        """import argparse
import builtins
builtins.setattr = load_model
config = argparse.Namespace(trust_remote_code=True)
""",
        """import builtins
from dataclasses import dataclass
builtins.object = ObjectLoader
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
config = RunSettings(trust_remote_code=True)
""",
    ],
    ids=["namespace-builtin-setattr-replaced", "record-builtin-object-replaced"],
)
def test_constructor_builtin_dependencies_must_remain_native(tmp_path, source):
    _assert_last_call_retained(tmp_path, source)


@pytest.mark.parametrize(
    "patcher",
    [
        """from settings import RunSettings, recorded
from unknown_backend import load_model
RunSettings.__init__ = load_model
recorded()
""",
        """import settings
configure(settings)
settings.recorded()
""",
    ],
    ids=["imported-class-patched", "owner-module-escaped"],
)
def test_project_record_identity_is_protected_across_other_source_files(
    tmp_path, patcher
):
    source = """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
def recorded():
    return RunSettings(trust_remote_code=True)
"""
    _assert_last_call_retained(tmp_path, source, extra_files={"patcher.py": patcher})


def test_namespace_identity_is_protected_from_other_source_files(tmp_path):
    _assert_last_call_retained(
        tmp_path,
        "import argparse\nconfig = argparse.Namespace(trust_remote_code=True)\n",
        extra_files={
            "patcher.py": "import argparse\nargparse.Namespace.__init__ = load_model\n"
        },
    )


def test_stale_tree_cannot_prove_the_current_provider_is_safe(tmp_path):
    source = "import argparse\nconfig = argparse.Namespace(trust_remote_code=True)\n"
    path = write_fixture(
        tmp_path,
        "settings.py",
        "import argparse\nargparse.Namespace = load_model\n"
        "config = argparse.Namespace(trust_remote_code=True)\n",
    )
    findings = []
    scan_file_with_tree(
        ast.parse(source, filename=str(path)),
        path,
        findings,
        source=source,
        project_root=tmp_path,
    )
    assert [
        (row["line"], row["severity"])
        for row in findings
        if row["rule_id"] == "SKY-D213"
    ] == [(2, "HIGH")]


@pytest.mark.parametrize(
    "source",
    [
        """import argparse
prior = argparse.Namespace()
configure(prior)
config = argparse.Namespace(trust_remote_code=True)
""",
        """from dataclasses import dataclass
@dataclass(frozen=True)
class RunSettings:
    trust_remote_code: bool
prior = RunSettings(trust_remote_code=False)
configure(prior)
config = RunSettings(trust_remote_code=True)
""",
        """import argparse
prior = argparse.Namespace()
prior.__class__.__init__ = load_model
config = argparse.Namespace(trust_remote_code=True)
""",
    ],
    ids=["namespace-result-escape", "record-result-escape", "instance-class-mutation"],
)
def test_constructor_results_cannot_expose_a_mutable_constructor(tmp_path, source):
    _assert_last_call_retained(tmp_path, source)


def test_fake_dataclass_cannot_launder_a_namespace_instance(tmp_path):
    source = """import argparse
from dataclasses import dataclass
@dataclass(frozen=True)
class Holder:
    value: str
prior = argparse.Namespace()
Holder(value=prior)
config = argparse.Namespace(trust_remote_code=True)
"""
    _assert_last_call_retained(
        tmp_path,
        source,
        extra_files={
            "dataclasses.py": """from unknown_backend import replace_with_loader
def dataclass(**options):
    return replace_with_loader
"""
        },
    )


@pytest.mark.parametrize("default", ["prior", "argparse.Namespace()"])
def test_default_captured_instance_cannot_hide_constructor_mutation(tmp_path, default):
    source = (
        "import argparse\nprior = argparse.Namespace()\n"
        f"def poison(value={default}):\n"
        "    value.__class__.__init__ = load_model\n"
        "poison()\n"
        "config = argparse.Namespace(trust_remote_code=True)\n"
    )
    _assert_last_call_retained(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        """import argparse
from unknown_backend import TypeThatLoads, payload
prior = argparse.Namespace(__class__=TypeThatLoads, value=payload)
config = argparse.Namespace(trust_remote_code=True)
""",
        """import argparse
from dataclasses import dataclass
from unknown_backend import TypeThatLoads
dataclass(TypeThatLoads)
config = argparse.Namespace(trust_remote_code=True)
""",
    ],
    ids=["intermediate-namespace-class-change", "dataclass-on-unknown-class"],
)
def test_intermediate_calls_need_the_same_data_only_argument_shape(tmp_path, source):
    _assert_last_call_retained(tmp_path, source)
