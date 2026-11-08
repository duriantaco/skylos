private func handler() {}
public func register(_ callback: () -> Void) { callback() }
public func entry() { register(handler) }
private func spare() {}
