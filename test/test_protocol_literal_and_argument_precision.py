"""Source-proven protocol declarations retain unrelated application findings."""

import ast
import textwrap

import pytest

from skylos.rules.quality.logic_maintainability import DuplicateStringLiteralRule
from skylos.rules.quality.structure import ArgCountRule


def _scan(rule, source, *, filename="app.py", root=None):
    source = textwrap.dedent(source)
    context = {
        "filename": str(filename),
        "project_root": str(root) if root is not None else None,
        "precision_exclusions": [],
    }
    tree = ast.parse(source)
    findings = []
    for node in ast.walk(tree):
        findings.extend(rule.visit_node(node, context) or [])
    return findings, context["precision_exclusions"]


def _destinations(receiver="parser"):
    return "\n".join(
        f"def configure_{index}(): {receiver}.add_argument('--flag{index}', dest='request_type')"
        for index in range(3)
    )


@pytest.mark.parametrize(
    "prefix, receiver",
    [
        ("import argparse\nparser = argparse.ArgumentParser()\n", "parser"),
        (
            "from argparse import ArgumentParser as Parser\nparser = Parser()\n",
            "parser",
        ),
        (
            "import argparse as cli\nparser = cli.ArgumentParser()\n"
            "group = parser.add_argument_group('content')\n",
            "group",
        ),
    ],
)
def test_proven_argparse_namespace_destinations_are_contract_fields(prefix, receiver):
    findings, evidence = _scan(
        DuplicateStringLiteralRule(), prefix + _destinations(receiver)
    )
    assert findings == []
    assert evidence[0]["evidence"]["before_occurrences"] == 3
    assert evidence[0]["evidence"]["after_occurrences"] == 0
    assert {row["role"] for row in evidence[0]["evidence"]["excluded"]} == {
        "argparse_namespace_destination"
    }


@pytest.mark.parametrize(
    "mutation",
    ["parser = custom", "parser.add_argument = replacement", "mutate(parser)"],
)
def test_changed_argparse_receiver_does_not_authorize_destination_exclusion(mutation):
    findings, evidence = _scan(
        DuplicateStringLiteralRule(),
        "import argparse\nparser = argparse.ArgumentParser()\n"
        + mutation
        + "\n"
        + _destinations(),
    )
    assert findings[0]["value"] == 3
    assert evidence == []


def test_project_local_argparse_provider_is_not_an_external_contract(tmp_path):
    (tmp_path / "argparse.py").write_text("ArgumentParser = custom\n")
    findings, evidence = _scan(
        DuplicateStringLiteralRule(),
        "import argparse\nparser = argparse.ArgumentParser()\n" + _destinations(),
        filename=tmp_path / "app.py",
        root=tmp_path,
    )
    assert findings[0]["value"] == 3
    assert evidence == []


def test_argparse_destination_proof_keeps_other_roles_of_the_same_value():
    source = "import argparse\nparser = argparse.ArgumentParser()\n" + _destinations()
    source += "\n" + "\n".join(
        f"def consume_{index}(): return emit('request_type')" for index in range(3)
    )
    findings, evidence = _scan(DuplicateStringLiteralRule(), source)
    assert findings[0]["value"] == 3
    assert not evidence[0]["evidence"]["finding_removed"]
    assert evidence[0]["evidence"]["before_occurrences"] == 6


def _asgi_sends(annotation="Send", *, body="", value="http.response.body"):
    return "\n".join(
        f"async def respond_{index}(send: {annotation}):\n"
        + textwrap.indent(body + "\n", "    ")
        + f"    await send({{'type': {value!r}, 'body': b'data'}})"
        for index in range(3)
    )


@pytest.mark.parametrize(
    "prefix, annotation",
    [
        ("from starlette.types import Send\n", "Send"),
        ("from starlette.types import Send as Output\n", "Output"),
        ("from asgiref.typing import ASGISendCallable\n", "ASGISendCallable"),
    ],
)
def test_import_proven_asgi_event_types_are_protocol_discriminators(prefix, annotation):
    findings, evidence = _scan(
        DuplicateStringLiteralRule(), prefix + _asgi_sends(annotation)
    )
    assert findings == []
    assert evidence[0]["evidence"]["finding_removed"]
    assert {row["role"] for row in evidence[0]["evidence"]["excluded"]} == {
        "typed_asgi_event_discriminator"
    }


@pytest.mark.parametrize(
    "prefix, annotation, body",
    [
        ("from application import Send\n", "Send", ""),
        ("from starlette.types import Send\nSend = custom\n", "Send", ""),
        ("from starlette.types import Send\n", "Send", "send = custom"),
    ],
)
def test_unproved_or_rebound_asgi_callables_keep_repeated_values(
    prefix, annotation, body
):
    findings, evidence = _scan(
        DuplicateStringLiteralRule(), prefix + _asgi_sends(annotation, body=body)
    )
    assert findings[0]["value"] == 3
    assert evidence == []


def test_asgi_protocol_proof_keeps_unknown_events_and_ordinary_business_messages():
    source = "from starlette.types import Send\n" + _asgi_sends(value="order.completed")
    source += "\n" + "\n".join(
        f"def handler_{index}(): return emit('Shared business failure: retry later.')"
        for index in range(9)
    )
    findings, _ = _scan(DuplicateStringLiteralRule(), source)
    assert {row["name"]: row["value"] for row in findings} == {
        "order.completed": 3,
        "Shared business failure: retry later.": 9,
    }


def test_local_asgi_provider_must_supply_the_actual_alias_contract(tmp_path):
    provider = tmp_path / "starlette"
    provider.mkdir()
    (provider / "__init__.py").write_text("")
    (provider / "types.py").write_text("Send = custom\nMessage = dict\n")
    findings, evidence = _scan(
        DuplicateStringLiteralRule(),
        "from starlette.types import Send\n" + _asgi_sends(),
        filename=tmp_path / "app.py",
        root=tmp_path,
    )
    assert findings[0]["value"] == 3
    assert evidence == []
    (provider / "types.py").write_text(
        "from collections.abc import Awaitable, Callable, MutableMapping\n"
        "from typing import Any\n"
        "Message = MutableMapping[str, Any]\n"
        "Send = Callable[[Message], Awaitable[None]]\n"
    )
    findings, evidence = _scan(
        DuplicateStringLiteralRule(),
        "from starlette.types import Send\n" + _asgi_sends(),
        filename=tmp_path / "app.py",
        root=tmp_path,
    )
    assert findings == []
    assert evidence[0]["evidence"]["finding_removed"]


def _optional_overloads(
    prefix="from typing import overload", marker="overload", metadata=""
):
    parameters = ", ".join(f"option_{index}: int = ..." for index in range(11))
    return (
        prefix
        + "\n"
        + "\n".join(
            f"@{marker}\n{metadata}def configure({parameters}) -> {result}: ..."
            for result in ("int", "str")
        )
    )


@pytest.mark.parametrize(
    "prefix, marker, metadata",
    [
        ("from typing import overload", "overload", ""),
        ("import typing as t", "t.overload", ""),
        (
            "from typing_extensions import overload, dataclass_transform",
            "overload",
            "@dataclass_transform()\n",
        ),
    ],
)
def test_optional_pyi_overload_contracts_do_not_ask_to_redesign_declarations(
    prefix, marker, metadata
):
    findings, evidence = _scan(
        ArgCountRule(),
        _optional_overloads(prefix, marker, metadata),
        filename="package/api.pyi",
    )
    assert findings == []
    assert {row["reason"] for row in evidence} == {"optional_overload_declaration"}


@pytest.mark.parametrize(
    "prefix, metadata",
    [
        ("def overload(fn): return fn", ""),
        ("from typing import overload\noverload = custom", ""),
        ("from typing import overload", "@unknown\n"),
    ],
)
def test_unknown_pyi_overload_providers_and_decorators_keep_wide_signatures(
    prefix, metadata
):
    findings, evidence = _scan(
        ArgCountRule(),
        _optional_overloads(prefix, metadata=metadata),
        filename="api.pyi",
    )
    assert findings
    assert evidence == []


@pytest.mark.parametrize(
    "prefix, expected_findings",
    [
        ("from typing import overload\noverload = custom", 2),
        ("def overload(fn): return fn", 2),
        ("from typing import overload", 0),
    ],
)
def test_stub_preprocessing_ignores_security_parent_links_on_shared_parser_contexts(
    monkeypatch, prefix, expected_findings
):
    from skylos.rules.danger.calls import DangerousCallsRule

    previous = ast.parse("holder = root" + ".field" * 250 + "\n")
    # Save/restore attributes of shared parser contexts so this paired-rule
    # regression does not leave its own parent links behind for other tests.
    shared_contexts = {
        node for node in ast.walk(previous) if isinstance(node, ast.expr_context)
    }
    for context in shared_contexts:
        monkeypatch.setattr(context, "parent", None, raising=False)
    DangerousCallsRule()._annotate_parents(previous)
    source = _optional_overloads(prefix)
    parsed = ast.parse(source)
    shared_store = previous.body[0].targets[0].ctx
    assert shared_contexts.intersection(ast.walk(parsed))
    assert getattr(shared_store, "parent") is previous.body[0].targets[0]

    findings, _ = _scan(ArgCountRule(), source, filename="api.pyi")

    assert len(findings) == expected_findings
    assert all(row["value"] == 11 for row in findings)


def test_pyi_required_positional_overloads_and_plain_declarations_stay_visible():
    source = "from typing import overload\n" + "\n".join(
        f"@overload\ndef invoke(a,b,c,d,e,f,g,h,i) -> {result}: ..."
        for result in ("int", "str")
    )
    source += "\ndef plain(a,b,c,d,e,f,g,h,i): ...\n"
    findings, evidence = _scan(ArgCountRule(), source, filename="api.pyi")
    assert len(findings) == 2
    assert all(row["argument_evidence"]["required_positional"] == 9 for row in findings)
    assert evidence == []


def _record_forwarder(value="{name}", *, extra="", marker="@dataclass", prefix=""):
    fields = "\n".join(f"    option_{index}: int = 0" for index in range(11))
    parameters = ", ".join(f"option_{index}=0" for index in range(11))
    keywords = ", ".join(
        f"option_{index}=" + value.format(name=f"option_{index}") for index in range(11)
    )
    return (
        "from dataclasses import dataclass\n"
        + prefix
        + "\n"
        + marker
        + "\nclass Record:\n"
        + fields
        + "\nclass Surface:\n"
        + f"    def add(self, *, {parameters}):\n"
        + textwrap.indent(extra + "\n", "        ")
        + f"        return Record({keywords})\n"
    )


@pytest.mark.parametrize(
    "value",
    ["{name}", "{name} or ''", "{name} if {name} is not None else self.default"],
)
def test_optional_named_options_only_forwarded_to_one_proven_record_are_cohesive(value):
    findings, evidence = _scan(ArgCountRule(), _record_forwarder(value))
    assert findings == []
    assert evidence[0]["reason"] == "named_record_option_forwarding"
    assert len(evidence[0]["evidence"]["keyword_only_parameters"]) == 11


@pytest.mark.parametrize(
    "arguments",
    [
        {"extra": "validate(option_0)"},
        {"extra": "Record = custom"},
        {"marker": "@unknown"},
        {"prefix": "dataclass = custom"},
    ],
)
def test_options_with_independent_uses_or_unproved_records_keep_argument_finding(
    arguments,
):
    findings, evidence = _scan(ArgCountRule(), _record_forwarder(**arguments))
    assert len(findings) == 1
    assert evidence == []


@pytest.mark.parametrize(
    "record_body",
    [
        "    option_0 = descriptor\n",
        "    option_0 = 7\n",
        "    def __post_init__(self):\n        validate(self.option_0)\n",
    ],
)
def test_redefined_fields_and_behavioral_record_construction_keep_argument_finding(
    record_body,
):
    source = _record_forwarder().replace(
        "class Surface:\n", record_body + "class Surface:\n"
    )
    findings, evidence = _scan(ArgCountRule(), source)
    assert len(findings) == 1
    assert evidence == []


def test_record_field_excluded_from_constructor_does_not_prove_option_forwarding():
    source = (
        _record_forwarder()
        .replace(
            "from dataclasses import dataclass",
            "from dataclasses import dataclass, field",
        )
        .replace("option_0: int = 0", "option_0: int = field(init=False)")
    )
    findings, evidence = _scan(ArgCountRule(), source)
    assert len(findings) == 1
    assert evidence == []


def test_real_nine_required_positional_arguments_remain_reported():
    findings, evidence = _scan(
        ArgCountRule(),
        "def invoke(a,b,c,d,e,f,g,h,i):\n    return call(a,b,c,d,e,f,g,h,i)\n",
    )
    assert findings[0]["value"] == 9
    assert findings[0]["argument_evidence"]["metric"] == "required_positional"
    assert evidence == []
