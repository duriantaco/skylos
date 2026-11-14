package main

import "os"

type source struct {
	file *os.File
	name string
}

var current *source

var all []source

func remember(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	current = &source{f, path}
	return nil
}

func collect(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	all = append(all, source{file: f, name: path})
	return nil
}

func main() {
	_ = remember("a.txt")
	_ = collect("b.txt")
	for _, s := range all {
		s.file.Close()
	}
	current.file.Close()
}
