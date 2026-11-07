package main
import "example.com/provider"
func main() { actual.Invoke(callback) }
func callback() { alpha() }
func alpha() { beta() }
func beta() { alpha() }
func orphan() {}
