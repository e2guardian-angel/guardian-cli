package utils

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"syscall"

	"golang.org/x/term"
)

func UserHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func GuardianConfigHome() string {
	var guardianHome string = os.Getenv("GUARDIAN_HOME")
	var homePath string
	if guardianHome != "" {
		homePath = path.Join(guardianHome)
	} else {
		homePath = path.Join(UserHomeDir(), ".guardian")
	}
	return homePath
}

/*
 * Receive password from the command line
 */
func getUserCredentials() (string, error) {

	fmt.Print("Enter Password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	fmt.Println("")

	password := string(bytePassword)
	return password, nil
}
