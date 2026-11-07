public struct Payload { private var value = 1 }
public func entry(_ value: Payload) -> String { String(reflecting: Mirror(reflecting: value)) }
