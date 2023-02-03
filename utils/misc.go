package utils

import (
	"fmt"
	"log"
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

/*
 * Get currently selected target
 */
func GetTargetSelection() (error, string) {
	targetSelectFile := path.Join(GuardianConfigHome(), ".target")
	content, err := os.ReadFile(targetSelectFile)
	return err, string(content)
}

/*
 * Choose target host to select for operations
 */
func SelectTargetHost(name string) int {

	targetSelectFile := path.Join(GuardianConfigHome(), ".target")

	if name == "show" {
		// Show currently selected target
		if _, err := os.Stat(targetSelectFile); err != nil {
			log.Println("No target currently selected")
		} else {
			err, target := GetTargetSelection()
			if err != nil {
				log.Fatalln("Failed to read target select file")
				return -1
			}
			log.Printf("Target '%s' is currently selected\n", target)
		}
		return 0
	} else if name == "none" {
		// Delete target file
		if err := os.Remove(targetSelectFile); err != nil {
			log.Fatalln("Failed to delete target select file")
			return -1
		}
		log.Println("Unselected target")
		return 0
	}

	_, err := getHostFilterConfig(name)
	if err != nil {
		log.Fatalf("Failed to get host config: for target '%s': %s \n", name, err)
		return -1
	}

	// Create config file
	f, err := os.Create(targetSelectFile)
	if err != nil {
		log.Fatal("Failed to create config file: ", err)
		return -1
	}
	defer f.Close()
	_, err = f.WriteString(name)
	if err != nil {
		log.Fatal("Failed to write config file: ", err)
		return -1
	}

	log.Printf("Selected target '%s' for operations\n", name)

	return 0
}
