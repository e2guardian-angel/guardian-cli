package utils

import (
	"fmt"
	"os"
	"path"

	"github.com/go-git/go-git/v5"
)

const playbookGit = "https://github.com/e2guardian-angel/guardian-playbook.git"

func Setup(host string, port int16) {

	var guardianHome string = os.Getenv("GUARDIAN_HOME")
	var homePath string
	var playbookDirs string
	if guardianHome != "" {
		homePath = path.Join(guardianHome)
	} else {
		homePath = path.Join(os.Getenv("HOME"), ".guardian")
	}
	playbookDirs = path.Join(homePath, "playbooks")

	os.RemoveAll(playbookDirs)
	os.MkdirAll(playbookDirs, 0o755)

	fmt.Printf("Cloning playbooks into \"%s\"...", playbookDirs)
	_, err := git.PlainClone(playbookDirs, false, &git.CloneOptions{
		URL:      playbookGit,
		Progress: os.Stdout,
	})

	if err != nil {
		fmt.Println("Failed to clone playbooks: ", err)
	}

}
