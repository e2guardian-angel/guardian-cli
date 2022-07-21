package utils

import (
	"os"
	"path"
	"runtime"
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
