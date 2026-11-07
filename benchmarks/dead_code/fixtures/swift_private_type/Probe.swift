private struct Retired {}
private struct Worker { func run() {} }
public func entry() { Worker().run() }
