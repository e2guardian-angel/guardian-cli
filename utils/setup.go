package utils

import (
	"fmt"
	"log"
	"os"
	"path"

	"github.com/go-git/go-git/v5"
)

const playbookGit = "https://github.com/e2guardian-angel/guardian-playbook.git"

func Setup(name string) int {

	err := initLocal()
	if err != nil {
		return -1
	}

	err, config := loadConfig()
	if err != nil {
		return -1
	}

	_, target := FindHost(config, name)
	if target.Name != name {
		log.Fatal("Host ", name, " has not been configured. Add it first.")
		return -1
	}

	playbookDirs := path.Join(GuardianConfigHome(), "playbooks")

	os.RemoveAll(playbookDirs)
	os.MkdirAll(playbookDirs, 0o755)

	log.Printf("Cloning playbooks into \"%s\"...\n", playbookDirs)
	_, err = git.PlainClone(playbookDirs, false, &git.CloneOptions{
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

	f.WriteString(fmt.Sprintf("[%s]\n", target.Name))
	f.WriteString(fmt.Sprintf("%s:%d\n", target.Address, target.Port))

	log.Printf("Executing playbook on target host \"%s\"...\n", target.Name)

	return 0

}
