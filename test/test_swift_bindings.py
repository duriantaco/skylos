"""Lexical Swift binders must retain their declaration and type owners."""

import pytest

from skylos.visitors.languages.swift.core import SwiftCore


@pytest.mark.parametrize(
    "source,unused,used",
    [
        (
            "private func action() -> Int { 1 }\n"
            "public func entry() -> Int { let (action, number) = ({ 2 }, 3); return action() + number }\n",
            {"action"},
            {"entry"},
        ),
        (
            "private func handler() -> Int { 1 }\n"
            "public func entry() -> Int { let handler = { [handler] in handler() }; return handler() }\n"
            "private func spare() {}\n",
            {"spare"},
            {"handler", "entry"},
        ),
        (
            "private struct T {}\nprivate struct U {}\n"
            "private typealias Mapper<T> = (T) -> T\n"
            "public func entry() { _ = T() }\n",
            {"U"},
            {"T", "entry"},
        ),
        (
            "public struct First { fileprivate func render() {} }\n"
            "public struct Second { fileprivate func render() {} }\n"
            "public func entry() { typealias Alias = Second; let value: Alias = Second(); value.render() }\n",
            {"First.render"},
            {"First", "Second", "Second.render", "entry"},
        ),
        (
            "private func action() {}\nprivate func helper() {}\n"
            "public func entry() -> () -> Void { { [action = helper] in action() } }\n",
            {"action"},
            {"helper", "entry"},
        ),
        (
            "private struct T {}\npublic func identity<T>(_ value: T) -> T { value }\n",
            {"T"},
            {"identity"},
        ),
        (
            "fileprivate protocol Run { func run() }\n"
            "fileprivate struct Worker: Run { fileprivate func run() {} }\n"
            "public func entry() { let worker: any Run = Worker(); worker.run() }\n",
            set(),
            {"Run", "Worker", "Worker.run", "entry"},
        ),
    ],
)
def test_binding_identity(source, unused, used):
    core = SwiftCore("Probe.swift", source.encode())
    core.scan()
    assert not core.root_node.has_error
    definitions = {d.name: d for d in core.defs}
    assert set(unused) | set(used) <= definitions.keys()
    assert {
        d.name for d in core.defs if not d.is_exported and not d.references
    } == unused
    for name in used:
        assert definitions[name].references > 0
