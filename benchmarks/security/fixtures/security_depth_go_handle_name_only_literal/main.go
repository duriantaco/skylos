package main

import "os"

type entry struct {
	name string
	fd   uintptr
}

var seen []entry

func record(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	seen = append(seen, entry{name: f.Name(), fd: f.Fd()})
	return nil
}

func main() {
	_ = record("a.txt")
}
