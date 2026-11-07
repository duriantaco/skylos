@propertyWrapper public struct Box { public var wrappedValue: Int; public init(wrappedValue: Int) { self.wrappedValue = wrappedValue } }
public struct Worker { @Box private var value = 1; public func entry() -> Int { value } }
