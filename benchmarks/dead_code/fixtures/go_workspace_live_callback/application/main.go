package main
import bridge "example.com/provider/bridge"
func main() { var value bridge.Box[int]; invoke := value.Invoke; invoke(callback) }
func callback() { alpha() }
func alpha() { beta() }
func beta() { alpha() }
func orphan() {}
