package utils

import (
	"fmt"
	"log"
	"os"
	"path"

	"github.com/go-git/go-git/v5"
)

const playbookGit = "https://github.com/e2guardian-angel/guardian-playbook.git"

func Setup(host string, port int16) int {

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

	log.Printf("Cloning playbooks into \"%s\"...\n", playbookDirs)
	_, err := git.PlainClone(playbookDirs, false, &git.CloneOptions{
		URL:      playbookGit,
		Progress: os.Stdout,
	})

	if err != nil {
		log.Fatal("Failed to clone playbooks: ", err)
		return -1
	}

	// Create hosts file
	f, err := os.Create(path.Join(playbookDirs, "hosts.yml"))
	if err != nil {
		log.Fatal(err)
		return -1
	}

	defer f.Close()

	f.WriteString(fmt.Sprintf("[%s]\n", host))
	f.WriteString(fmt.Sprintf("%s:%d\n", host, port))

	log.Printf("Executing playbook on target host \"%s\"...\n", host)

	return 0

}
