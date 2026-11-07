"""Lazy and eager initialization have different reachability effects."""

from skylos.visitors.languages.swift.core import SwiftCore


def test_unread_lazy_factory_is_dead_but_eager_factory_still_runs():
    source = (
        'private func unusedFactory() -> Int { print("lazy-called"); return 1 }\n'
        "public struct LazyWorker { private lazy var cache = unusedFactory(); public init() {} }\n"
        'private func requiredFactory() -> Int { print("stored-called"); return 1 }\n'
        "public struct EagerWorker { private var cache = requiredFactory(); public init() {} }\n"
        "public func entry() { _ = LazyWorker(); _ = EagerWorker() }\n"
    )
    core = SwiftCore("Probe.swift", source.encode())
    core.scan()
    assert not core.root_node.has_error
    definitions = {d.name: d for d in core.defs}
    assert definitions["unusedFactory"].references == 0
    assert definitions["requiredFactory"].references > 0
    assert definitions["entry"].references > 0


def test_read_lazy_property_keeps_its_factory_used():
    source = (
        "private func makeValue() -> Int { 1 }\n"
        "public class Worker { private lazy var cache = makeValue(); public func entry() -> Int { cache } }\n"
    )
    core = SwiftCore("Probe.swift", source.encode())
    core.scan()
    assert not core.root_node.has_error
    definitions = {d.name: d for d in core.defs}
    assert definitions["makeValue"].references > 0
    assert definitions["Worker.cache"].references > 0
