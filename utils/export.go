package utils

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func compress(src string, buf io.Writer) error {
	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	// is file a folder?
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}
	mode := fi.Mode()
	if mode.IsRegular() {
		// get header
		header, err := tar.FileInfoHeader(fi, src)
		if err != nil {
			return err
		}
		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// get content
		data, err := os.Open(src)
		if err != nil {
			return err
		}
		if _, err := io.Copy(tw, data); err != nil {
			return err
		}
	} else if mode.IsDir() { // folder

		// walk through every file in the folder
		filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
			// generate tar header
			header, e := tar.FileInfoHeader(fi, file)
			if e != nil {
				return err
			}

			// must provide real name
			// (see https://golang.org/src/archive/tar/common.go?#L626)
			header.Name = filepath.ToSlash(strings.ReplaceAll(file, src, ""))
			if header.Name == "" {
				return nil
			}

			// write header
			if e := tw.WriteHeader(header); err != nil {
				return e
			}
			// if not a dir, write file content
			if !fi.IsDir() {
				data, e := os.Open(file)
				if e != nil {
					return e
				}
				if _, e := io.Copy(tw, data); e != nil {
					return e
				}
			}
			return nil
		})
	} else {
		return fmt.Errorf("error: file type not supported")
	}

	// produce tar
	if err := tw.Close(); err != nil {
		return err
	}
	// produce gzip
	if err := zr.Close(); err != nil {
		return err
	}
	//
	return nil
}

func decompress(src io.Reader, dst string) error {
	// ungzip
	zr, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	// untar
	tr := tar.NewReader(zr)

	// uncompress each element
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}

		// add dst + re-format slashes according to system
		target := filepath.Join(dst, header.Name)
		// if no join is needed, replace with ToSlash:
		// target = filepath.ToSlash(header.Name)

		// check the type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it (with 0755 permission)
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		// if it's a file create it (with same permission)
		case tar.TypeReg:
			fileToWrite, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents
			if _, err := io.Copy(fileToWrite, tr); err != nil {
				return err
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			fileToWrite.Close()
		}
	}

	//
	return nil
}

func ExportConfigs(outputFile string) int {
	// TODO: get all db entries
	configHome := GuardianConfigHome()
	var buf bytes.Buffer
	err := compress(configHome, &buf)
	if err != nil {
		log.Fatalf("Compression failed: %s\n", err)
		return -1
	}
	// TODO: optional AES encryption
	fileToWrite, err := os.OpenFile(outputFile, os.O_CREATE|os.O_RDWR, os.FileMode(0700))
	if err != nil {
		log.Fatalf("Failed to open backup file: %s\n", err)
		return -1
	}
	_, err = io.Copy(fileToWrite, &buf)
	if err != nil {
		log.Fatalf("Failed export: %s\n", err)
		return -1
	}
	log.Println("Export successful")
	return 0
}

func ImportConfigs(inputFile string) int {
	configHome := GuardianConfigHome()
	var buf bytes.Buffer
	fileToRead, err := os.OpenFile(inputFile, os.O_RDONLY, os.FileMode(0600))
	if err != nil {
		log.Fatalf("Failed to open backup file: %s\n", err)
		return -1
	}
	_, err = io.Copy(&buf, fileToRead)
	if err != nil {
		log.Fatalf("Failed loading backup file: %s\n", err)
		return -1
	}
	// TODO: optional AES decryption
	err = decompress(&buf, configHome)
	if err != nil {
		log.Fatalf("Decompression failed: %s\n", err)
		return -1
	}
	return 0
}
