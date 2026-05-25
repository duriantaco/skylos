package main

import (
	"archive/tar"
	"os"
	"path/filepath"
)

func untar(reader *tar.Reader, dest string) error {
	for {
		header, err := reader.Next()
		if err != nil {
			return err
		}
		if header.Typeflag != tar.TypeSymlink {
			continue
		}
		target := filepath.Join(dest, header.Name)
		if err := os.Symlink(header.Linkname, target); err != nil {
			return err
		}
	}
}
