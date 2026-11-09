public struct Worker { private var value: Int = 1; public func entry() -> Int { self[keyPath: \Worker.value] } }
