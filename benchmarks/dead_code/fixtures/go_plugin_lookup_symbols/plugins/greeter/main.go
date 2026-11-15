package main

var Settings = map[string]string{"greeting": "hello"}

func Describe() string { return Settings["greeting"] }

func describe() string { return "lowercase names are never plugin symbols" }

func Orphan() string { return "named only by a lookup on a project type" }

func Unnamed() string { return "no lookup names this function" }

func main() {}
