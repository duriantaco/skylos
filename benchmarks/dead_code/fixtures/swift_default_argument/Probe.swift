private func helper() -> Int { 1 }
private func entry(value: Int = helper()) -> Int { value }
public func run() -> Int { entry() }
