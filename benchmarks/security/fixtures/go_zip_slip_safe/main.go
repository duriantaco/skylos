package main

import (
	"archive/zip"
	"os"
	"path/filepath"
)

func unzip(path string, dest string) error {
	reader, _ := zip.OpenReader(path)
	for _, file := range reader.File {
		if !filepath.IsLocal(file.Name) {
			continue
		}
		target := filepath.Join(dest, file.Name)
		out, _ := os.Create(target)
		_ = out
	}
	return nil
}
