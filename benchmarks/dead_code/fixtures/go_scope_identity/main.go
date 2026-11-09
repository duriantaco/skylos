package main

type state struct { retired int }
func main() {
 stale := func() {}
 stale()
 consume := func(parameterOnly int) { _ = parameterOnly }
 consume(1)
 value := state{}
 println(value.retired)
 selected()
}
func stale() {}
func retired() {}
func parameterOnly() {}
func selected() {}
