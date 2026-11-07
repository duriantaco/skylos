package demo

func Public() func() { rooted(); return callback }
func rooted() {}
func callback() {}
func init() { initialized() }
func initialized() {}
var startup = startupHook()
func startupHook() int { return 1 }
func staleA() { staleB() }
func staleB() { staleA() }
func self() { self() }
func unusedOwner() func() { return deadValue }
func deadValue() {}
func testOnly() {}
func generatedOnly() {}
