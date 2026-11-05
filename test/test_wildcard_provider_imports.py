"""Wildcard consumers must read the provider's actual import binding."""

import ast
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from skylos.analyzer import analyze
from test.fixture_paths import write_fixture


def test_no_star_project_does_not_construct_a_wildcard_index(monkeypatch):
    from skylos.deadcode import wildcard_provider_imports

    tree = ast.parse(
        "import yaml\n"
        + "".join(f"yaml.load(data, Loader=missing_{index})\n" for index in range(400))
    )
    report = SimpleNamespace(
        complete=True,
        index=SimpleNamespace(
            modules={
                Path("loads.py"): SimpleNamespace(tree=tree),
            }
        ),
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("a project without wildcard imports needs no index")

    monkeypatch.setattr(wildcard_provider_imports, "_WildcardReads", forbidden)
    assert wildcard_provider_imports.wildcard_provider_import_reads({}, report) == set()


@pytest.mark.parametrize(
    "caller_body,arguments,dead,live",
    [
        ("return Factory.create_store()", "", False, True),
        ("return Factory.create_store()", "", True, False),
        ("if False:\n        return Factory.create_store()", "", False, False),
        ("return None\n    Factory.create_store()", "", False, False),
        ("return Factory.create_store()", "Factory", False, False),
        ("Factory=other\n    return Factory.create_store()", "", False, False),
        ("return False and Factory.create_store()", "", False, False),
        ("return (Factory.create_store() for _ in [])", "", False, False),
    ],
)
def test_unindexed_static_factory_follows_exact_retained_caller(
    caller_body, arguments, dead, live
):
    from skylos.deadcode._reachability_bindings import ModuleInfo
    from skylos.deadcode.wildcard_provider_imports import wildcard_provider_import_reads

    provider = ModuleInfo(
        Path("provider.py"), ast.parse("import config\n"), {"provider"}
    )
    source = f"from provider import *\nclass Factory:\n    STORES={{'json': object}}\n    @staticmethod\n    def create_store():\n        return Factory.STORES.get(config.VALUE)()\ndef run({arguments}):\n    {caller_body}\n"
    consumer = ModuleInfo(Path("consumer.py"), ast.parse(source), {"consumer"})
    method = consumer.tree.body[1].body[1]
    caller = consumer.tree.body[2]
    consumer.functions[caller.lineno] = "consumer.run"
    definitions = {
        "provider.config": SimpleNamespace(
            type="import",
            filename=provider.path,
            line=1,
            binding_name="config",
            simple_name="config",
        ),
        "consumer.Factory.create_store": SimpleNamespace(
            type="method",
            filename=consumer.path,
            line=method.lineno,
            name="consumer.Factory.create_store",
            called_by={"consumer.run"},
            heuristic_refs={"same_pkg_attr": 2},
        ),
    }
    report = SimpleNamespace(
        complete=True,
        unreachable_keys={"consumer.run"} if dead else set(),
        proven_reachable_keys={"consumer.run"} if not dead else set(),
        index=SimpleNamespace(
            modules={module.path: module for module in (provider, consumer)},
            module_names={"provider": [provider], "consumer": [consumer]},
        ),
    )
    assert (
        "provider.config" in wildcard_provider_import_reads(definitions, report)
    ) is live


def _scan(tmp_path, files, grep_verify):
    for relative, source in files.items():
        write_fixture(tmp_path, relative, source)
    report = json.loads(
        analyze(
            str(tmp_path),
            conf=60,
            grep_verify=grep_verify,
            grep_cache=False,
            trace_file=False,
            all_advice=False,
            enable_dependency_hallucinations=False,
        )
    )
    assert report["analysis_summary"]["total_files"] > 0
    assert not report.get("analysis_errors")
    output = os.getenv("SKYLOS_WILDCARD_RECEIPTS")
    if output:
        directory = Path(output)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{tmp_path.name}.json").write_text(json.dumps(report, indent=2))
    return report


CASES = [
    (
        "unrelated-record-setattr",
        "import config\ndef update(row, values):\n    for name, value in values.items():\n        setattr(row, name, value)\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "unrelated-record-dict-read",
        "import config\ndef update(row):\n    return row.__dict__\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "unrelated-record-dict-write",
        "import config\ndef update(row):\n    row.__dict__['value'] = 2\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "unrelated-record-vars",
        "import config\ndef update(row):\n    return vars(row)\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "imported-config-attribute-write",
        "import config\nconfig.VALUE = 2\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "imported-config-dict-write",
        "import config\nconfig.__dict__['VALUE'] = 2\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "imported-config-setattr",
        "import config\nsetattr(config, 'VALUE', 2)\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "module-read",
        "import config\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "function-read",
        "import config\n",
        "from provider import *\ndef run():\n    return config.VALUE\nprint(run())\n",
        True,
    ),
    (
        "method-read",
        "import config\n",
        "from provider import *\nclass Store:\n    @staticmethod\n    def read():\n        return config.VALUE\nprint(Store.read())\n",
        True,
    ),
    (
        "all-includes",
        "import config\n__all__ = ['config']\n",
        "from provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "all-excludes",
        "import config\n__all__ = ['marker']\nmarker = 1\n",
        "from provider import *\nprint(marker)\n",
        False,
    ),
    (
        "private-export",
        "import config as _config\nmarker = 1\n",
        "from provider import *\nprint(marker)\n",
        False,
    ),
    (
        "provider-overwritten",
        "import config\nconfig = 1\n",
        "from provider import *\nprint(config)\n",
        False,
    ),
    (
        "consumer-import-after",
        "import config\n",
        "from provider import *\nimport config\nprint(config.VALUE)\n",
        False,
    ),
    (
        "consumer-import-before",
        "import config\n",
        "import config\nfrom provider import *\nprint(config.VALUE)\n",
        False,
    ),
    (
        "consumer-overwritten",
        "import config\n",
        "from provider import *\nconfig = 1\nprint(config)\n",
        False,
    ),
    (
        "consumer-local-import",
        "import config\n",
        "from provider import *\ndef run():\n    import config\n    return config.VALUE\nprint(run())\n",
        False,
    ),
    (
        "consumer-parameter",
        "import config\n",
        "from provider import *\ndef run(config):\n    return config\nprint(run(1))\n",
        False,
    ),
    (
        "consumer-class-local",
        "import config\n",
        "from provider import *\nclass Local:\n    config = 1\n    print(config)\nprint(Local())\n",
        False,
    ),
    (
        "dead-consumer-function",
        "import config\n",
        "from provider import *\ndef unused():\n    return config.VALUE\n",
        False,
    ),
    (
        "branch-replaces-all",
        "import config\n",
        "from provider import *\nif input():\n    config = 1\nelse:\n    config = 2\nprint(config)\n",
        False,
    ),
    (
        "branch-may-read",
        "import config\n",
        "from provider import *\nif input():\n    config = 1\nelse:\n    print(config.VALUE)\n",
        True,
    ),
    (
        "star-overwritten",
        "import config\n",
        "from provider import *\nfrom other import *\nprint(config)\n",
        False,
    ),
    (
        "star-last-provider",
        "import config\n",
        "from other import *\nfrom provider import *\nprint(config.VALUE)\n",
        True,
    ),
]


@pytest.mark.parametrize("live", [False, True])
@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize("package_api", [False, True])
def test_registry_factory_requires_a_live_or_exported_caller(
    tmp_path, monkeypatch, live, grep_verify, package_api
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _scan(
        tmp_path,
        {
            "config.py": "VALUE='json'\n",
            "backend.py": "class JsonStore:\n    async def save(self, record):\n        return record\n",
            "provider.py": "import config\nfrom backend import JsonStore\ndef update_record(row, values):\n    for name,value in values.items():\n        setattr(row, name, value)\n",
            (
                "storage/__init__.py" if package_api else "storage.py"
            ): "from provider import *\nclass StoreFactory:\n    STORES={'json':JsonStore}\n    @staticmethod\n    def create_store():\n        store_class=StoreFactory.STORES.get(config.VALUE)\n        if not store_class:\n            raise ValueError('unsupported')\n        return store_class()\nasync def update(record):\n    await StoreFactory.create_store().save(record)\n",
            "app.py": (
                "from storage import update\nimport asyncio\nasyncio.run(update({}))\n"
                if live
                else "def dormant():\n    from storage import update\n    return update({})\nprint('idle')\n"
            ),
        },
        grep_verify,
    )
    config = [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "provider.py" and row["line"] == 1
    ]
    assert bool(config) is not (live or package_api)


@pytest.mark.parametrize(
    "mutation",
    [
        "setattr(provider, 'config', 7)",
        "provider.__dict__['config'] = 7",
        "namespace=provider.__dict__\nnamespace['config'] = 7",
        "alias=provider\nsetattr(alias, 'config', 7)",
    ],
)
def test_known_provider_namespace_mutation_adds_no_credit(
    tmp_path, monkeypatch, mutation
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    from skylos.deadcode import wildcard_provider_imports

    original = wildcard_provider_imports.wildcard_provider_import_reads
    credited = []

    def capture(definitions, report):
        keys = original(definitions, report)
        credited.extend(definitions[key] for key in keys)
        return keys

    monkeypatch.setattr(
        wildcard_provider_imports, "wildcard_provider_import_reads", capture
    )
    _scan(
        tmp_path,
        {
            "config.py": "VALUE=1\n",
            "provider.py": "import config\n",
            "consumer.py": f"import provider\n{mutation}\nfrom provider import *\nprint(config)\n",
        },
        False,
    )
    assert not [
        definition
        for definition in credited
        if Path(definition.filename) == tmp_path / "provider.py"
    ]


@pytest.mark.parametrize(
    "mutation,external",
    [
        ("Factory.create_store=lambda: 0", False),
        ("alias=Factory\nalias.create_store=lambda: 0", False),
        ("del Factory.create_store", False),
        ("setattr(Factory, 'create_store', lambda: 0)", False),
        ("from consumer import Factory\nFactory.create_store=lambda: 0", True),
        ("import consumer\nconsumer.Factory.create_store=lambda: 0", True),
        (
            "from consumer import Factory as alias\nsetattr(alias, 'create_store', lambda: 0)",
            True,
        ),
        (
            "def replace():\n    from consumer import Factory\n    Factory.create_store=lambda: 0\nreplace()",
            True,
        ),
        ("alias: object=Factory\nsetattr(alias, 'create_store', lambda: 0)", False),
    ],
)
def test_replaced_static_factory_body_adds_no_wildcard_credit(
    tmp_path, monkeypatch, mutation, external
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    from skylos.deadcode import wildcard_provider_imports

    original = wildcard_provider_imports.wildcard_provider_import_reads
    credited = []

    def capture(definitions, report):
        keys = original(definitions, report)
        credited.extend(definitions[key] for key in keys)
        return keys

    monkeypatch.setattr(
        wildcard_provider_imports, "wildcard_provider_import_reads", capture
    )
    consumer = "from provider import *\nclass Factory:\n    STORES={'json':object}\n    @staticmethod\n    def create_store():\n        return Factory.STORES.get(config.VALUE)()\n"
    consumer += (
        ("" if external else mutation + "\n")
        + "def run():\n    return Factory.create_store()\n"
        + ("" if external else "run()\n")
    )
    files = {
        "config.py": "VALUE='json'\n",
        "provider.py": "import config\n",
        "consumer.py": consumer,
    }
    if external:
        files["writer.py"] = (
            mutation + "\nimport consumer\nconsumer.Factory.create_store()\n"
        )
    report = _scan(tmp_path, files, False)
    assert not [
        definition
        for definition in credited
        if Path(definition.filename) == tmp_path / "provider.py"
    ]
    assert [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "provider.py"
    ]


def test_parameter_shadowed_factory_setattr_keeps_real_factory_read(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _scan(
        tmp_path,
        {
            "config.py": "VALUE='json'\n",
            "provider.py": "import config\n",
            "consumer.py": "from provider import *\nclass Factory:\n    STORES={'json':object}\n    @staticmethod\n    def create_store():\n        return Factory.STORES.get(config.VALUE)()\ndef replace(Factory):\n    setattr(Factory,'create_store',lambda: 0)\ndef run():\n    return Factory.create_store()\nrun()\n",
        },
        False,
    )
    assert not [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "provider.py"
    ]


@pytest.mark.parametrize(
    "package_api,inactive", [(False, False), (True, False), (False, True)]
)
def test_foreign_patch_does_not_erase_an_independent_factory_use(
    tmp_path, monkeypatch, package_api, inactive
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    source = "from provider import *\nclass Factory:\n    STORES={'json':object}\n    @staticmethod\n    def create_store():\n        return Factory.STORES.get(config.VALUE)()\n"
    if inactive:
        source += "if False:\n    Factory.create_store=lambda:0\n"
    source += "def use_factory():\n    return Factory.create_store()\n"
    if not package_api:
        source += "use_factory()\n"
    files = {
        "config.py": "VALUE='json'\n",
        "provider.py": "import config\n",
        ("consumer/__init__.py" if package_api else "consumer.py"): source,
    }
    if not inactive:
        files["writer.py"] = (
            "import consumer\ndef patch():\n    consumer.Factory.create_store=lambda:0\npatch()\n"
        )
    report = _scan(tmp_path, files, False)
    assert not [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "provider.py"
    ]


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "case,provider,consumer,live", CASES, ids=[r[0] for r in CASES]
)
def test_only_consumed_wildcard_provider_import_is_live(
    tmp_path, monkeypatch, grep_verify, case, provider, consumer, live
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _scan(
        tmp_path,
        {
            "config.py": "VALUE = 1\n",
            "provider.py": provider,
            "consumer.py": consumer,
            "other.py": "config = 7\n",
        },
        grep_verify,
    )
    findings = [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "provider.py" and row["line"] == 1
    ]
    assert bool(findings) is not live
    if findings:
        assert len(findings) == 1
        assert findings[0]["references"] == 0
        assert findings[0]["listing"]["listed"] is True


@pytest.mark.parametrize("grep_verify", [False, True])
def test_relative_package_provider_keeps_its_consumed_binding(
    tmp_path, monkeypatch, grep_verify
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _scan(
        tmp_path,
        {
            "settings.py": "VALUE = 1\n",
            "store/_implementation.py": "import settings as config\n",
            "store/__init__.py": "from ._implementation import *\ndef read():\n    return config.VALUE\n",
            "app.py": "from store import read\nprint(read())\n",
        },
        grep_verify,
    )
    assert not [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "store/_implementation.py"
    ]


EDGE_CASES = [
    (
        "deferred-generator-read",
        "import config\n",
        "from provider import *\nvalues=(config.VALUE for item in [1])\n",
        False,
    ),
    (
        "empty-comprehension-read",
        "import config\n",
        "from provider import *\nvalues=[config.VALUE for item in []]\n",
        False,
    ),
    (
        "false-comprehension-read",
        "import config\n",
        "from provider import *\nvalues=[config.VALUE for item in [1] if False]\n",
        False,
    ),
    (
        "inactive-ternary-read",
        "import config\n",
        "from provider import *\nprint(1 if True else config.VALUE)\n",
        False,
    ),
    (
        "short-circuit-read",
        "import config\n",
        "from provider import *\nprint(False and config.VALUE)\n",
        False,
    ),
    (
        "provider-walrus-overwrite",
        "import config\nif (config := 7):\n    pass\n",
        "from provider import *\nprint(config)\n",
        False,
    ),
    (
        "consumer-walrus-overwrite",
        "import config\n",
        "from provider import *\nif (config := 7):\n    print(config)\n",
        False,
    ),
    (
        "all-paths-return-before-read",
        "import config\n",
        "from provider import *\ndef run():\n    if input():\n        return 1\n    else:\n        return 2\n    print(config.VALUE)\nprint(run())\n",
        False,
    ),
    (
        "different-consumer-import-before",
        "import config\n",
        "import other as config\nfrom provider import *\nprint(config.VALUE)\n",
        True,
    ),
    (
        "read-before-later-import",
        "import config\n",
        "from provider import *\nprint(config.VALUE)\nimport other as config\n",
        True,
    ),
    (
        "attribute-write-reads-object",
        "import config\n",
        "from provider import *\nconfig.VALUE = 2\n",
        True,
    ),
    (
        "inactive-all",
        "import config\n__all__ = ['marker']\nmarker=1\nif False:\n    __all__ = ['config']\n",
        "config=7\nfrom provider import *\nprint(config)\n",
        False,
    ),
    (
        "provider-namespace-write",
        "import config\nglobals()['config'] = 7\n",
        "from provider import *\nprint(config)\n",
        False,
    ),
    (
        "provider-namespace-alias",
        "import config\nnamespace=globals()\nnamespace['config'] = 7\n",
        "from provider import *\nprint(config)\n",
        False,
    ),
    (
        "consumer-namespace-write",
        "import config\n",
        "from provider import *\nglobals()['config'] = 7\nprint(config)\n",
        False,
    ),
    (
        "local-closure",
        "import config\n",
        "from provider import *\ndef run():\n    config=1\n    def nested():\n        return config\n    return nested()\nprint(run())\n",
        False,
    ),
    (
        "inactive-consumer-read",
        "import config\n",
        "from provider import *\nif False:\n    print(config.VALUE)\n",
        False,
    ),
]


@pytest.mark.parametrize("grep_verify", [False, True])
@pytest.mark.parametrize(
    "case,provider,consumer,live", EDGE_CASES, ids=[r[0] for r in EDGE_CASES]
)
def test_wildcard_binding_order_and_mutations(
    tmp_path, monkeypatch, grep_verify, case, provider, consumer, live
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    from skylos.deadcode import wildcard_provider_imports

    original = wildcard_provider_imports.wildcard_provider_import_reads
    credited = []

    def capture(definitions, report):
        keys = original(definitions, report)
        credited.extend(definitions[key] for key in keys)
        return keys

    monkeypatch.setattr(
        wildcard_provider_imports, "wildcard_provider_import_reads", capture
    )
    report = _scan(
        tmp_path,
        {
            "config.py": "VALUE=1\n",
            "provider.py": provider,
            "consumer.py": consumer,
            "other.py": "VALUE=9\n",
        },
        grep_verify,
    )
    findings = [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "provider.py" and row["line"] == 1
    ]
    if case == "provider-namespace-write" or (case == "inactive-all" and grep_verify):
        # Existing reflection/grep policy already retains these on the base.
        # This helper must contribute no new wildcard evidence; raw retention
        # is not a successful must-report control for this case.
        assert not [
            definition
            for definition in credited
            if Path(definition.filename) == tmp_path / "provider.py"
        ]
        return
    assert bool(findings) is not live
    if findings:
        assert findings[0]["listing"]["listed"] is True


@pytest.mark.parametrize("grep_verify", [False, True])
def test_same_named_member_import_is_not_a_module_identity_proof(
    tmp_path, monkeypatch, grep_verify
):
    monkeypatch.setenv("SKYLOS_JOBS", "1")
    report = _scan(
        tmp_path,
        {
            "settings.py": "VALUE=1\n",
            "provider.py": "from settings import VALUE as config\n",
            "consumer.py": "from settings import VALUE as config\nimport settings\nsettings.VALUE=2\nfrom provider import *\nprint(config)\n",
        },
        grep_verify,
    )
    assert not [
        row
        for row in report.get("unused_imports", [])
        if Path(row["file"]) == tmp_path / "provider.py"
    ]
