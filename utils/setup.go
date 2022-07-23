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

	playbookDir := path.Join(GuardianConfigHome(), "playbooks")

	/*
	 * TODO: instead of wiping the directory and re-cloning, just do a git pull
	 */
	os.RemoveAll(playbookDir)
	os.MkdirAll(playbookDir, 0o755)

	log.Printf("Cloning playbooks into \"%s\"...\n", playbookDir)
	_, err = git.PlainClone(playbookDir, false, &git.CloneOptions{
		URL:      playbookGit,
		Progress: os.Stdout,
	})

	if err != nil {
		log.Fatal("Failed to clone playbooks: ", err)
		return -1
	}

	// Create hosts file
	inventoryFile, err := os.Create(path.Join(playbookDir, "hosts.yml"))
	if err != nil {
		log.Fatal("Failed to create config file: ", err)
		return -1
	}
	defer inventoryFile.Close()
	inventoryFile.WriteString("[local]\n")
	inventoryFile.WriteString("127.0.0.1\n")

	// Create vars file
	varsFile, err := os.Create(path.Join(playbookDir, "extra.yml"))
	if err != nil {
		log.Fatal("Failed to create config file: ", err)
		return -1
	}
	defer varsFile.Close()
	varsFile.WriteString(fmt.Sprintf("home_dir: \"%s\"\n", target.HomePath))

	log.Printf("Copying playbook to remote host...")
	dstPath := path.Join(target.HomePath, ".guardian", "playbooks")

	sftpc, err := NewSshClient(target.Username, target.Address, int(target.Port), getPrivateKeyFilename(), "")
	if err != nil {
		log.Fatal("Failed to create SSH client: ", err)
		return -1
	}

	err = sftpc.Put(playbookDir, dstPath)
	if err != nil {
		log.Fatal("Failed to copy playbooks to target host: ", err)
		return -1
	}

	log.Printf("Executing playbook on target host \"%s\"...\n", target.Name)
	log.Printf("You will need to enter your password for sudo access.")
	password, err := getUserCredentials()
	if err != nil {
		log.Fatal("Failed to get password: ", err)
	}

	sshc, err := NewSshClient(target.Username, target.Address, int(target.Port), getPrivateKeyFilename(), "")
	if err != nil {
		log.Fatal("Failed to create SSH client: ", err)
		return -1
	}
	err = sshc.RunCommand(fmt.Sprintf("cd %s && sudo sh setup.sh", dstPath), password)
	if err != nil {
		log.Fatal("Failed to run playbook: ", err)
		return -1
	}

	return 0

}
