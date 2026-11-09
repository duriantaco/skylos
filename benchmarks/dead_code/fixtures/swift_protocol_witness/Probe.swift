private protocol Render { func render() }
private struct Worker: Render { func render() {} }
public func entry() { let worker: any Render = Worker(); worker.render() }
