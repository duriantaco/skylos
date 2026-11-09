"""Cosmos query text requires a source-backed SDK receiver and tainted data."""

import textwrap
import json

import pytest

from skylos.rules.danger.danger import scan_ctx
from test.fixture_paths import write_fixture


def _scan(tmp_path, source, extra=None):
    source = textwrap.dedent(source).lstrip()
    path = write_fixture(tmp_path, "app.py", source, overwrite=True)
    for name, body in (extra or {}).items():
        write_fixture(tmp_path, name, body, overwrite=True)
    findings = scan_ctx(tmp_path, [path])
    return [finding for finding in findings if finding["rule_id"] == "SKY-D211"]


@pytest.mark.parametrize(
    ("imports", "constructor", "header"),
    [
        ("from azure.cosmos import CosmosClient", "CosmosClient('https://db')", "def"),
        ("import azure.cosmos as sdk", "sdk.CosmosClient('https://db')", "def"),
        (
            "from azure.cosmos import CosmosClient as Client",
            "Client.from_connection_string('connection')",
            "def",
        ),
        (
            "from azure.cosmos.aio import CosmosClient",
            "CosmosClient('https://db')",
            "async def",
        ),
    ],
)
def test_actual_cosmos_factory_chain_keeps_tainted_sql(
    tmp_path, imports, constructor, header
):
    findings = _scan(
        tmp_path,
        f"""
        {imports}

        {header} search(value):
            client = {constructor}
            database = client.get_database_client('db')
            container = database.get_container_client('items')
            return container.query_items(query=f"SELECT * FROM c WHERE c.value = '{{value}}'")
        """,
    )

    assert len(findings) == 1
    assert findings[0]["line"] == 7
    assert findings[0]["metadata"]["cosmos_receiver"]["provider"].endswith(
        "ContainerProxy"
    )


def test_cosmos_class_field_factory_chain_and_partial_parameters(tmp_path):
    findings = _scan(
        tmp_path,
        """
        from azure.cosmos import ContainerProxy, CosmosClient

        class Store:
            container: ContainerProxy

            def connect(self):
                self.client = CosmosClient('https://db')
                self.database = self.client.get_database_client('db')
                self.container = self.database.get_container_client('items')

            def search(self, value, embedding):
                where_clause = f" WHERE c.name = '{value}'"
                query = f'SELECT * FROM c{where_clause} ORDER BY VectorDistance(c.vector, @embedding)'
                return self.container.query_items(
                    query=query,
                    parameters=[{'name': '@embedding', 'value': embedding}],
                )
        """,
    )

    assert len(findings) == 1
    assert findings[0]["line"] == 14


@pytest.mark.parametrize(
    "query",
    [
        "container.query_items(query='SELECT VALUE COUNT(1) FROM c')",
        "container.query_items(query='SELECT * FROM c WHERE c.name = @name', parameters=[{'name': '@name', 'value': value}])",
    ],
)
def test_actual_cosmos_literal_or_bound_query_is_quiet(tmp_path, query):
    assert not _scan(
        tmp_path,
        f"""
        from azure.cosmos import CosmosClient
        def search(value):
            container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            return {query}
        """,
    )


@pytest.mark.parametrize(
    "source",
    [
        """
        from azure.cosmos import CosmosClient
        def search(client, value):
            return client.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        from azure.cosmos import ContainerProxy
        def search(client: ContainerProxy, value):
            return client.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        from azure.cosmos import CosmosClient
        class Renderer:
            def query_items(self, query):
                return query
        def search(value):
            return Renderer().query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        from azure.cosmos import CosmosClient
        def search(value, other):
            container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            container = other
            return container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        import azure.cosmos as sdk
        def search(sdk, value):
            container = sdk.CosmosClient('https://db').get_database_client('db').get_container_client('items')
            return container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        from azure.cosmos import CosmosClient
        class Store:
            def connect(self):
                self.container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            def replace(self, other):
                self.container = other
            def search(self, value):
                return self.container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        import builtins
        from azure.cosmos import CosmosClient
        class Store:
            def connect(self):
                self.container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            @builtins.staticmethod
            def search(self, value):
                return self.container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        from azure.cosmos import CosmosClient
        class Renderer:
            def query_items(self, query):
                return query
        class Base:
            def __getattribute__(self, name):
                if name == 'container':
                    return Renderer()
                return object.__getattribute__(self, name)
        class Store(Base):
            def connect(self):
                self.container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            def search(self, value):
                return self.container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        """
        from azure.cosmos import CosmosClient
        CosmosClient.get_database_client = lambda self, name: object()
        def search(value):
            container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            return container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
    ],
)
def test_sdk_import_or_annotation_does_not_prove_an_arbitrary_receiver(
    tmp_path, source
):
    assert not _scan(tmp_path, source)


def test_project_shadow_cannot_supply_the_cosmos_sdk_provider(tmp_path):
    assert not _scan(
        tmp_path,
        """
        from azure.cosmos import CosmosClient
        def search(value):
            container = CosmosClient().get_database_client('db').get_container_client('items')
            return container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        extra={
            "azure/__init__.py": "",
            "azure/cosmos.py": "class CosmosClient:\n    pass\n",
        },
    )


def test_unavailable_cosmos_proof_keeps_existing_sql_detection(tmp_path, monkeypatch):
    from skylos.rules.danger.danger_sql.cosmos_provenance import CosmosQueryProvenance

    def unavailable(*args, **kwargs):
        raise RuntimeError("source proof unavailable")

    monkeypatch.setattr(CosmosQueryProvenance, "query_receiver", unavailable)
    findings = _scan(
        tmp_path,
        """
        from azure.cosmos import CosmosClient
        def search(conn, value):
            container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
            conn.execute(f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
    )

    assert len(findings) == 1
    assert findings[0]["line"] == 5


def test_cosmos_sink_survives_full_json_output(tmp_path):
    from skylos.analyzer import analyze

    write_fixture(
        tmp_path,
        "app.py",
        "from azure.cosmos import CosmosClient\n"
        "value = input()\n"
        "container = CosmosClient('https://db').get_database_client('db').get_container_client('items')\n"
        "container.query_items(query=f\"SELECT * FROM c WHERE c.name = '{value}'\")\n",
        overwrite=True,
    )
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    findings = [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D211"]
    assert len(findings) == 1
    assert findings[0]["line"] == 4
    assert findings[0].get("listing", {}).get("listed", True)
    assert (
        findings[0]["metadata"]["cosmos_receiver"]["proof_kind"]
        == "stable_sdk_factory_chain"
    )


def test_cosmos_helper_without_an_input_source_remains_a_diagnostic(tmp_path):
    from skylos.analyzer import analyze

    write_fixture(
        tmp_path,
        "app.py",
        "from azure.cosmos import CosmosClient\n"
        "def search(value):\n"
        "    container = CosmosClient('https://db').get_database_client('db').get_container_client('items')\n"
        "    return container.query_items(query=f\"SELECT * FROM c WHERE c.name = '{value}'\")\n",
        overwrite=True,
    )
    result = json.loads(
        analyze(
            str(tmp_path),
            enable_danger=True,
            enable_dependency_hallucinations=False,
            grep_verify=False,
            all_advice=False,
        )
    )
    assert not result.get("analysis_errors")
    assert not [row for row in result.get("danger", []) if row["rule_id"] == "SKY-D211"]
    rows = [row for row in result.get("suppressed", []) if row["rule_id"] == "SKY-D211"]
    assert len(rows) == 1
    assert rows[0]["line"] == 4
    assert rows[0]["metadata"]["sql_provenance"]["status"] == "unknown"
    assert rows[0]["metadata"]["sql_provenance"]["safety_proven"] is False
    assert (
        rows[0]["metadata"]["cosmos_receiver"]["proof_kind"]
        == "stable_sdk_factory_chain"
    )


def test_inherited_class_body_property_cannot_supply_sdk_storage(tmp_path):
    assert not _scan(
        tmp_path,
        """
        from azure.cosmos import CosmosClient
        class Renderer:
            def query_items(self, query):
                return query
        class Base:
            def ignore(self, value):
                pass
            container = property(lambda self: Renderer(), ignore)
        class Store(Base):
            def connect(self):
                self.container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            def search(self, value):
                return self.container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
    )


@pytest.mark.parametrize(
    "replacement",
    [
        "container.__dict__['query_items'] = Renderer().query_items",
        "object.__setattr__(container, 'query_items', Renderer().query_items)",
        "replace_attribute(container, 'query_items', Renderer().query_items)",
    ],
)
def test_replaced_sdk_instance_method_is_not_a_native_query_sink(tmp_path, replacement):
    assert not _scan(
        tmp_path,
        f"""
        from azure.cosmos import CosmosClient
        from builtins import setattr as replace_attribute
        class Renderer:
            def query_items(self, query):
                return query
        def search(value):
            container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            {replacement}
            return container.query_items(query=f"SELECT * FROM c WHERE c.name = '{{value}}'")
        """,
    )


@pytest.mark.parametrize(
    "replacement",
    [
        "setattr(self, 'container', Renderer())",
        "self.__dict__['container'] = Renderer()",
    ],
)
def test_reflective_instance_storage_does_not_supply_a_native_receiver(
    tmp_path, replacement
):
    assert not _scan(
        tmp_path,
        f"""
        from azure.cosmos import CosmosClient
        class Renderer:
            def query_items(self, query):
                return query
        class Store:
            def search(self, value):
                self.container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
                {replacement}
                return self.container.query_items(query=f"SELECT * FROM c WHERE c.name = '{{value}}'")
        """,
    )


def test_modified_abc_provider_cannot_prove_plain_storage(tmp_path):
    assert not _scan(
        tmp_path,
        """
        from azure.cosmos import CosmosClient
        import abc
        class Renderer:
            def query_items(self, query):
                return query
        class Replacement:
            def __getattribute__(self, name):
                if name == 'container':
                    return Renderer()
                return object.__getattribute__(self, name)
        abc.ABC = Replacement
        from abc import ABC
        class Store(ABC):
            def search(self, value):
                self.container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
                return self.container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
    )


@pytest.mark.parametrize("proof_kind", ["sdk", "abc"])
def test_optional_cosmos_proof_preserves_existing_provider_budget(tmp_path, proof_kind):
    import ast

    from skylos.rules.danger.danger_sql.cosmos_provenance import CosmosQueryProvenance
    from skylos.rules.danger.import_proof import _effects, provider_binding_is_stable
    from skylos.rules.danger.project_imports import project_import_context
    from skylos.security.receiver_resolution import ReceiverResolver

    source = (
        "import json\n"
        "from abc import ABC\n"
        "from azure.cosmos import CosmosClient\n"
        "class Store(ABC):\n"
        "    pass\n"
        "def search(value):\n"
        "    container = CosmosClient('https://db').get_database_client('db').get_container_client('items')\n"
        "    return container.query_items(query=f\"SELECT * FROM c WHERE c.name = '{value}'\")\n"
    )
    path = write_fixture(tmp_path, "app.py", source, overwrite=True)
    tree = ast.parse(source, filename=str(path))
    assert provider_binding_is_stable("json.loads", tree, path, tmp_path)
    context = project_import_context(tree, path, tmp_path)
    assert context is not None
    effects = [_effects(parsed) for _, parsed in context.entries]
    for effect in effects:
        assert effect.complete
        effect.ref_work = 65536
    before = [(effect.complete, effect.ref_work) for effect in effects]

    if proof_kind == "sdk":
        proof = CosmosQueryProvenance(tree, path, tmp_path)
        call = next(
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "query_items"
        )
        proven = proof.query_receiver(call) is not None
    else:
        resolver = ReceiverResolver(tree, path, tmp_path)
        base = next(node for node in tree.body if isinstance(node, ast.ClassDef)).bases[
            0
        ]
        proof = object.__new__(CosmosQueryProvenance)
        proof.root = tmp_path
        proven = proof._plain_abc(resolver.main, base)

    assert [(effect.complete, effect.ref_work) for effect in effects] == before
    assert provider_binding_is_stable("json.loads", tree, path, tmp_path)
    assert proven


def test_unrelated_string_target_patch_does_not_hide_the_sdk_sink(tmp_path):
    findings = _scan(
        tmp_path,
        """
        from azure.cosmos import CosmosClient
        def search(value):
            container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            return container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        extra={
            "other.py": "def test_cache(monkeypatch, replacement):\n    monkeypatch.setattr('cache.to_thread', replacement)\n"
        },
    )
    assert len(findings) == 1


def test_project_sdk_patch_revokes_the_factory_proof(tmp_path):
    assert not _scan(
        tmp_path,
        """
        from azure.cosmos import CosmosClient
        def search(value):
            container = CosmosClient('https://db').get_database_client('db').get_container_client('items')
            return container.query_items(query=f"SELECT * FROM c WHERE c.name = '{value}'")
        """,
        extra={
            "patcher.py": "from azure.cosmos import CosmosClient\nCosmosClient.get_database_client = replacement\n"
        },
    )


@pytest.mark.parametrize("future", ["", "from __future__ import annotations\n"])
@pytest.mark.parametrize("alias", ["DatabaseProxy", "DatabaseProxy as Proxy"])
def test_unrelated_sdk_type_union_does_not_hide_a_query(tmp_path, future, alias):
    typename = alias.split(" as ")[-1]
    findings = _scan(
        tmp_path,
        "from azure.cosmos import CosmosClient\n"
        "def search(value):\n"
        "    container = CosmosClient('https://db').get_database_client('db').get_container_client('items')\n"
        "    return container.query_items(query=f'SELECT {value}')\n",
        extra={
            "types.py": future
            + f"from azure.cosmos import {alias}\nclient: {typename} | None = None\n"
        },
    )
    assert [(finding["line"], finding["col"]) for finding in findings] == [(4, 11)]


@pytest.mark.parametrize(
    "effect",
    [
        "CosmosClient.get_database_client = replacement",
        "configure(CosmosClient)",
        "other: mutate(CosmosClient) | None = None",
        "other: DatabaseProxy | project_type = None",
    ],
)
def test_sdk_type_annotations_do_not_hide_mutations_or_effects(tmp_path, effect):
    assert not _scan(
        tmp_path,
        "from azure.cosmos import CosmosClient\n"
        "def search(value):\n"
        "    container = CosmosClient('https://db').get_database_client('db').get_container_client('items')\n"
        "    return container.query_items(query=f'SELECT {value}')\n",
        extra={
            "types.py": "from azure.cosmos import DatabaseProxy, CosmosClient\n"
            "client: DatabaseProxy | None = None\n" + effect + "\n"
        },
    )


def test_monorepo_package_base_keeps_the_project_wide_sdk_proof(tmp_path):
    from skylos.rules.danger.danger_sql.sql_flow import scan
    import ast

    write_fixture(
        tmp_path, "packages/vector-store/pyproject.toml", "[project]\nname='vectors'\n"
    )
    write_fixture(tmp_path, "packages/vector-store/vectors/__init__.py", "")
    write_fixture(
        tmp_path,
        "packages/vector-store/vectors/base.py",
        "from abc import ABC\nclass Store(ABC): pass\n",
    )
    source = (
        "from azure.cosmos import CosmosClient\nfrom vectors.base import Store\n"
        "class VectorStore(Store):\n"
        "    def connect(self):\n"
        "        self.container = CosmosClient('https://db').get_database_client('db').get_container_client('items')\n"
        "    def search(self, value):\n"
        "        return self.container.query_items(query=f'SELECT {value}')\n"
    )
    path = write_fixture(tmp_path, "packages/vector-store/vectors/cosmos.py", source)
    findings = []
    scan(ast.parse(source), path, findings, project_root=tmp_path)
    assert [(finding["rule_id"], finding["line"]) for finding in findings] == [
        ("SKY-D211", 7)
    ]
    write_fixture(
        tmp_path,
        "patcher.py",
        "from azure.cosmos import CosmosClient\nCosmosClient.get_database_client = replacement\n",
    )
    findings = []
    scan(ast.parse(source), path, findings, project_root=tmp_path)
    assert findings == []
