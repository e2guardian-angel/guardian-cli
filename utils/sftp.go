package utils

import (
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func (s *SftpClient) PutFile(src string, dst string) error {

	dstFile, err := s.c.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	_, err = io.Copy(dstFile, srcFile)

	return err
}

func (s *SftpClient) PutDir(src string, dst string) error {
	err := filepath.Walk(src, func(srcPath string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relPath, _ := filepath.Rel(src, srcPath)
		dstPath := path.Join(dst, relPath)

		if info.IsDir() {
			return s.c.MkdirAll(dstPath)
		} else {
			return s.PutFile(srcPath, dstPath)
		}

		return nil
	})

	if err != nil {
		return err
	}

	return nil
}

type SftpClient struct {
	c *sftp.Client
}

func (s *SshClient) Put(src string, dst string) error {

	// open connection
	conn, err := ssh.Dial("tcp", s.Server, s.Config)
	if err != nil {
		return fmt.Errorf("Dial to %v failed %v", s.Server, err)
	}
	defer conn.Close()

	sftpc, err := sftp.NewClient(conn)
	if err != nil {
		return err
	}
	defer sftpc.Close()

	client := SftpClient{sftpc}

	file, err := os.Open(src)
	if err != nil {
		return err
	}

	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}

	if fileInfo.IsDir() {
		return client.PutDir(src, dst)
	} else {
		return client.PutFile(src, dst)
	}
}
