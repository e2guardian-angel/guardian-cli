package utils

import (
	"fmt"
	"log"
	"os"
	"os/exec"
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
	hostFileName := path.Join(playbookDir, "hosts.yml")
	hostsFile, err := os.Create(hostFileName)
	if err != nil {
		log.Fatal("Failed creating inventory file: ", err)
		return -1
	}
	defer hostsFile.Close()

	// Write a host entry for this host
	hostsFile.WriteString(fmt.Sprintf("[%s]\n", target.Name))
	hostsFile.WriteString(fmt.Sprintf("%s:%d\n", target.Address, target.Port))
	hostsFile.WriteString("")

	/*fmt.Println("A password will be needed for sudo access.")
	password, err := getUserCredentials()
	if err != nil {
		log.Fatal("Error fetching password: ", err)
		return -1
	}*/

	log.Printf("Executing playbook on target host \"%s\"...\n", target.Name)

	sshOptionsLine := fmt.Sprintf("-o UserKnownHostsFile=%s -i %s\n", getKnownHostsFile(), getPrivateKeyFilename())
	cmd := exec.Command("ansible-playbook", "-i", hostFileName, "-e", fmt.Sprintf("\"home_dir=%s\"", target.HomePath),
		"--ssh-extra-args", sshOptionsLine, "-u", target.Username, "-K", "site.yml")
	cmd.Dir = playbookDir
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		fmt.Println(err.Error())
		return -1
	}

	return 0

}
