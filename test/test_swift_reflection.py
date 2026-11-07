"""Stored fields observed by real reflection; methods/lookalikes remain separate."""

import pytest

from skylos.visitors.languages.swift.core import SwiftCore


PAYLOAD = "public struct Payload { private var detail = 1; private func spare() {} }\n"


@pytest.mark.parametrize(
    "body",
    [
        "public func inspect<T>(_ value: T) -> Mirror { Mirror(reflecting: value) }\n"
        "public func entry(_ value: Payload) -> Mirror { inspect(value) }\n",
        "public func inspect(_ value: Any) -> Mirror { Mirror(reflecting: value) }\n"
        "public func entry(_ value: Payload) -> Mirror { inspect(value) }\n",
        "public func entry(_ value: Payload) -> Mirror { let reflect: (Payload) -> Mirror = Mirror.init(reflecting:); return reflect(value) }\n",
        "public func entry(_ value: Payload) -> String { let render: (Payload) -> String = String.init(reflecting:); return render(value) }\n",
        "public func entry(_ value: Payload) -> Mirror { let reflect = Mirror.init(reflecting:); let alias = reflect; return alias(value) }\n",
    ],
)
def test_reflection_through_generics_and_function_values_preserves_stored_fields(body):
    core = SwiftCore("Probe.swift", (PAYLOAD + body).encode())
    core.scan()
    assert not core.root_node.has_error
    definitions = {d.name: d for d in core.defs}
    assert definitions["Payload.detail"].references > 0
    assert definitions["Payload.spare"].references == 0
    assert not definitions["Payload.spare"].is_exported


@pytest.mark.parametrize(
    "body",
    [
        "public struct Mirror { public init(reflecting value: Payload) {} }\n"
        "public func entry(_ value: Payload) -> Mirror { Mirror(reflecting: value) }\n",
        "public enum Swift { public struct Mirror { public init(reflecting value: Payload) {} } }\n"
        "public func entry(_ value: Payload) -> Swift.Mirror { Swift.Mirror(reflecting: value) }\n",
        "public enum Swift { public static func Mirror(reflecting value: Payload) -> Int { 0 } }\n"
        "public func entry(_ value: Payload) -> Int { Swift.Mirror(reflecting: value) }\n",
        'public func entry() -> Mirror { Mirror(reflecting: "literal") }\n',
        "private func inspect<T>(_ value: T) -> Mirror { Mirror(reflecting: value) }\n"
        "public func entry() {}\n",
    ],
)
def test_unread_reflection_and_standard_name_lookalikes_do_not_read_fields(body):
    core = SwiftCore("Probe.swift", (PAYLOAD + body).encode())
    core.scan()
    assert not core.root_node.has_error
    definitions = {d.name: d for d in core.defs}
    assert definitions["Payload.detail"].references == 0
    assert definitions["Payload.spare"].references == 0


def test_reflection_reads_stored_fields_but_not_computed_or_static_properties():
    source = (
        "public struct Payload { private var stored = 1; private var computed: Int { 2 }; "
        "private static var global = 3; private func spare() {} }\n"
        "public func entry(_ value: Payload) -> Mirror { Mirror(reflecting: value) }\n"
    )
    core = SwiftCore("Probe.swift", source.encode())
    core.scan()
    assert not core.root_node.has_error
    definitions = {d.name: d for d in core.defs}
    assert definitions["Payload.stored"].references > 0
    for name in ("Payload.computed", "Payload.global", "Payload.spare"):
        assert definitions[name].references == 0
