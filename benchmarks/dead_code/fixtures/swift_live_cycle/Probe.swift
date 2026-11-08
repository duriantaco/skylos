private func first(_ n: Int) { if n > 0 { second(n-1) } }
private func second(_ n: Int) { first(n) }
public func entry() { first(2) }
private func spare() {}
