"""Swift source reachability contracts, frozen and natively reviewed before detection."""

import pytest

from skylos.visitors.languages.swift.core import SwiftCore


CASES = [
    (
        "private-functions",
        "private func retired() {}\n"
        "private func format() -> Int { 3 }\n"
        "public func entry() -> Int { format() }\n",
        ["retired"],
        ["format", "entry"],
    ),
    (
        "callback",
        "private func handler() {}\n"
        "public func register(_ callback: () -> Void) { callback() }\n"
        "public func entry() { register(handler) }\n"
        "private func spare() {}\n",
        ["spare"],
        ["handler", "register", "entry"],
    ),
    (
        "dead-cycle",
        "private func first() { second() }\n"
        "private func second() { first() }\n"
        "private func leaf() {}\n"
        "public func entry() {}\n",
        ["first", "second", "leaf"],
        ["entry"],
    ),
    (
        "live-cycle",
        "private func first(_ n: Int) { if n > 0 { second(n-1) } }\n"
        "private func second(_ n: Int) { first(n) }\n"
        "public func entry() { first(2) }\n"
        "private func spare() {}\n",
        ["spare"],
        ["first", "second", "entry"],
    ),
    (
        "parameter-shadow",
        "private func action() {}\npublic func entry(action: () -> Void) { action() }\n",
        ["action"],
        ["entry"],
    ),
    (
        "local-shadow",
        "private func action() {}\npublic func entry() { let action = { print(1) }; action() }\n",
        ["action"],
        ["entry"],
    ),
    (
        "initializer-before-binding",
        "private func action() -> Int { 1 }\n"
        "public func entry() -> Int { let action = action(); return action }\n",
        [],
        ["action", "entry"],
    ),
    (
        "owner-identity",
        "public struct First { private func render() {}; public func entry() {} }\n"
        "public struct Second { private func render() {}; public func entry() { render() } }\n",
        ["First.render"],
        ["First", "First.entry", "Second", "Second.render", "Second.entry"],
    ),
    (
        "extension",
        "public struct Worker { private func work() {} }\n"
        "extension Worker { public func entry() { work() } }\n"
        "private func spare() {}\n",
        ["spare"],
        ["Worker", "Worker.work", "Worker.entry"],
    ),
    (
        "fileprivate",
        "fileprivate func work() {}\npublic func entry() { work() }\nfileprivate func spare() {}\n",
        ["spare"],
        ["work", "entry"],
    ),
    (
        "function-value",
        "private func work() {}\npublic func entry() -> () -> Void { work }\nprivate func spare() {}\n",
        ["spare"],
        ["work", "entry"],
    ),
    (
        "keypath",
        "public struct Worker { private var value: Int = 1; public func entry() -> Int { self[keyPath: "
        "\\Worker.value] } }\n",
        [],
        ["Worker", "Worker.value", "Worker.entry"],
    ),
    (
        "property-read",
        "public struct Worker { private var value = 1; private var spare = 2; public func entry() -> Int "
        "{ value } }\n",
        ["Worker.spare"],
        ["Worker", "Worker.value", "Worker.entry"],
    ),
    (
        "string-not-use",
        'private func retired() {}\npublic func entry() -> String { "retired" }\n',
        ["retired"],
        ["entry"],
    ),
    (
        "comment-not-use",
        "private func retired() {}\n// retired() is old\npublic func entry() {}\n",
        ["retired"],
        ["entry"],
    ),
    (
        "overload-labels",
        "private func convert(text: String) {}\n"
        "private func convert(number: Int) {}\n"
        'public func entry() { convert(text: "ok") }\n',
        ["convert(number:)"],
        ["convert(text:)", "entry"],
    ),
    (
        "default-argument",
        "private func helper() -> Int { 1 }\n"
        "private func entry(value: Int = helper()) -> Int { value }\n"
        "public func run() -> Int { entry() }\n",
        [],
        ["helper", "entry", "run"],
    ),
    (
        "raw-identifiers",
        "private func `repeat`() {}\npublic func entry() { `repeat`() }\nprivate func spare() {}\n",
        ["spare"],
        ["repeat", "entry"],
    ),
    (
        "protocol-witness",
        "private protocol Render { func render() }\n"
        "private struct Worker: Render { func render() {} }\n"
        "public func entry() { let worker: any Render = Worker(); worker.render() }\n",
        [],
        ["Render", "Worker", "Worker.render", "entry"],
    ),
    (
        "codable",
        'import Foundation\npublic struct Payload: Codable { private var secret: String = "" }\n',
        [],
        ["Payload", "Payload.secret"],
    ),
    (
        "equatable",
        "public struct Payload: Equatable { private var value = 1 }\n",
        [],
        ["Payload", "Payload.value"],
    ),
    (
        "reflection",
        "public struct Payload { private var value = 1 }\n"
        "public func entry(_ value: Payload) -> String { String(reflecting: Mirror(reflecting: value)) "
        "}\n",
        [],
        ["Payload", "Payload.value", "entry"],
    ),
    (
        "objc-selector",
        "import Foundation\n"
        "public class Window: NSObject { @objc private func clicked() {}; public func entry() -> "
        "Selector { #selector(clicked) } }\n",
        [],
        ["Window", "Window.clicked", "Window.entry"],
    ),
    (
        "conditional",
        "public func entry() {}\n"
        "#if DEBUG\n"
        "private func hook() {}\n"
        "public func debugEntry() { hook() }\n"
        "#endif\n",
        [],
        ["hook", "entry", "debugEntry"],
    ),
    (
        "closure-capture",
        "private func work() {}\n"
        "public func entry() -> () -> Void { { work() } }\n"
        "private func spare() {}\n",
        ["spare"],
        ["work", "entry"],
    ),
    (
        "private-type",
        "private struct Retired {}\n"
        "private struct Worker { func run() {} }\n"
        "public func entry() { Worker().run() }\n",
        ["Retired"],
        ["Worker", "Worker.run", "entry"],
    ),
    (
        "member-cycle",
        "public struct Worker { private func first(){ second() }; private func second(){ first() }; "
        "public func entry(){} }\n",
        ["Worker.first", "Worker.second"],
        ["Worker", "Worker.entry"],
    ),
    (
        "property-wrapper",
        "@propertyWrapper public struct Box { public var wrappedValue: Int; public init(wrappedValue: "
        "Int) { self.wrappedValue = wrappedValue } }\n"
        "public struct Worker { @Box private var value = 1; public func entry() -> Int { value } }\n",
        [],
        ["Box", "Box.wrappedValue", "Worker", "Worker.value", "Worker.entry"],
    ),
]


@pytest.mark.parametrize(
    "case_id,source,unused,used", CASES, ids=[row[0] for row in CASES]
)
def test_source_defined_swift_contract(case_id, source, unused, used):
    core = SwiftCore("Probe.swift", source.encode("utf-8"))
    core.scan()
    assert core.root_node is not None and not core.root_node.has_error
    definitions = {definition.name: definition for definition in core.defs}
    assert set(unused) <= definitions.keys()
    assert set(used) <= definitions.keys()
    assert {
        d.name for d in core.defs if d.references == 0 and not d.is_exported
    } == set(unused)
    for name in used:
        assert definitions[name].references > 0, (case_id, name)
        assert definitions[name].framework_signals, (case_id, name)
