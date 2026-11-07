public func entry() {}
#if DEBUG
private func hook() {}
public func debugEntry() { hook() }
#endif
