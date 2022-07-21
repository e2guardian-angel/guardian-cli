package utils

import (
	"fmt"
	"log"
	"os"
	"path"

	"github.com/go-git/go-git/v5"
)

const playbookGit = "https://github.com/e2guardian-angel/guardian-playbook.git"

func getAnsibleDir() string {
	return path.Join(GuardianConfigHome(), "ansible")
}

func getAnsibleCfgFile() string {
	return path.Join(getAnsibleDir(), "ansible.cfg")
}

func getAnsibleHostsFile() string {
	return path.Join(getAnsibleDir(), "hosts.yml")
}

func initAnsibleDir(config Configuration) error {

	ansibleDir := getAnsibleDir()

	_, err := os.Stat(ansibleDir)
	if os.IsNotExist(err) {
		os.MkdirAll(ansibleDir, 0o755)
	}

	ansibleCfgFilename := getAnsibleCfgFile()
	// Generate an ansible config based on the current config
	cfgFile, err := os.Create(ansibleCfgFilename)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer cfgFile.Close()

	// Write ssh options
	sshOptionsLine := fmt.Sprintf("ssh_args = -o UserKnownHostsFile=%s -i %s\n", getKnownHostsFile(), getPrivateKeyFilename())
	cfgFile.WriteString(sshOptionsLine)
	// Write inventory line
	inventoryLine := fmt.Sprintf("inventory = %s\n", getAnsibleHostsFile())
	cfgFile.WriteString(inventoryLine)

	// Create hosts file
	hostFileName := getAnsibleHostsFile()
	hostsFile, err := os.Create(hostFileName)
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer hostsFile.Close()

	for _, host := range config.Hosts {
		hostsFile.WriteString(fmt.Sprintf("[%s]\n", host.Name))
		hostsFile.WriteString(fmt.Sprintf("%s:%d\n", host.Address, host.Port))
		hostsFile.WriteString("")
	}

	return nil
}

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

	err = initAnsibleDir(config)
	if err != nil {
		return -1
	}

	playbookDirs := path.Join(GuardianConfigHome(), "playbooks")

	/*
	 * TODO: instead of wiping the directory and re-cloning, just do a git pull
	 */
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

	log.Printf("Executing playbook on target host \"%s\"...\n", target.Name)

	return 0

}
