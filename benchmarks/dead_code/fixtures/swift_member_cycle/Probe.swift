public struct Worker { private func first(){ second() }; private func second(){ first() }; public func entry(){} }
