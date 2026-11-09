package main
import bridge "example.com/provider/bridge"
func main() { bridge.Invoke(callback) }
func callback() {  }
func alpha() { beta() }
func beta() { alpha() }
func orphan() {}
