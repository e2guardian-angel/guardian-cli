package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"text/tabwriter"

	"github.com/justinschw/gofigure/crypto"
)

/*
 * DATA DEFINITIONS
 */

type Host struct {
	Name     string
	Address  string
	Username string
	Port     uint16
	HomePath string
}

type Configuration struct {
	Hosts []Host
}

/*
 * HELPER METHODS
 */

/*
 * load the config file
 */
func loadConfig() (Configuration, error) {
	guardianHome := GuardianConfigHome()
	configFile := path.Join(guardianHome, "config.json")
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return Configuration{}, err
	}
	var config Configuration
	err = json.Unmarshal([]byte(data), &config)
	if err != nil {
		log.Fatal("Failed to parse config file: ", err)
		return Configuration{}, err
	}
	return config, err
}

/*
 * Write in-memory configuration to file
 */
func writeConfig(config Configuration) error {

	guardianHome := GuardianConfigHome()
	configFile := path.Join(guardianHome, "config.json")

	jsonString, err := json.Marshal(config)
	if err != nil {
		log.Fatal("Failed to marshal default config: ", err)
		return err
	}

	// Create config file
	f, err := os.Create(configFile)
	if err != nil {
		log.Fatal("Failed to create config file: ", err)
		return err
	}
	defer f.Close()
	_, err = f.WriteString(string(jsonString))

	return err
}

/*
 * Find an existing host
 */
func FindHost(config Configuration, name string) (int, Host) {
	var result Host
	var index int = -1
	for i, element := range config.Hosts {
		if element.Name == name {
			result = element
			index = i
			break
		}
	}
	return index, result
}

func getHostDataDir(name string) string {
	guardianHome := GuardianConfigHome()
	return path.Join(guardianHome, "host_data", name)
}

func getCaPathDir(name string) string {
	hostData := getHostDataDir(name)
	return path.Join(hostData, "rootCa.crt")
}

/*
 * Initialize local guardian config
 */
func initLocal() error {
	guardianHome := GuardianConfigHome()

	_, err := os.Stat(guardianHome)
	if os.IsNotExist(err) {
		os.MkdirAll(guardianHome, 0o755)
		os.MkdirAll(path.Join(guardianHome, "host_data"), 0o755)
	}

	// If configuration file doesn't already exist, create a default one
	configFile := path.Join(guardianHome, "config.json")
	_, err = os.Stat(configFile)
	if os.IsNotExist(err) {

		// default config with no hosts
		var c Configuration
		err = writeConfig(c)
		if err != nil {
			return err
		}

	}

	return nil
}

/*
 * COMMAND METHODS
 */

/*
 * setup a new target host
 */
func AddHost(name string, host string, port uint16, username string, noPassword bool, homePath string) int {

	err := initLocal()
	if err != nil {
		return -1
	}

	config, err := loadConfig()
	if err != nil {
		return -1
	}

	_, foundHost := FindHost(config, name)
	hostExists := (foundHost.Name == name)
	if hostExists {
		log.Fatal("Host with name '", name, "' already exists, did you mean to update it?")
		return -1
	}

	var hostHomePath string
	if homePath != "" {
		hostHomePath = homePath
	} else {
		hostHomePath = fmt.Sprintf("/home/%s", username)
	}
	newHost := Host{name, host, username, port, hostHomePath}

	hostDataPath := getHostDataDir(newHost.Name)
	_, err = os.Stat(hostDataPath)
	if os.IsNotExist(err) {
		os.MkdirAll(hostDataPath, 0o755)
	}

	err = initSsh(4096)
	if err != nil {
		log.Fatal("Failed to retrieve user password: ", err)
		return -1
	}

	password := os.Getenv("NEWHOST_PASSWORD")
	if password == "" {
		fmt.Println("Need remote password to copy keys to remote host.")
		password, err = getUserCredentials()
		if err != nil {
			log.Fatal("Failed to retrieve user password: ", err)
			return -1
		}
	}

	// Copy SSH keys to remote host
	sshClient := crypto.SshClient{
		Address:         newHost.Address,
		Port:            newHost.Port,
		Username:        newHost.Username,
		HostKeyCallback: PromptAtKey,
		KnownHostsFile:  getKnownHostsFile(),
	}

	sshClient.SetPasswordAuth(password)

	err = sshClient.NewCryptoContext()
	if err != nil {
		log.Fatal("Failed to establish SSH connection: ", err)
		return -1
	}

	pair := crypto.SshKeyPair{
		PrivateKeyFile: getPrivateKeyFilename(),
		PublicKeyFile:  getPublicKeyFilename(),
		BitSize:        4096,
	}
	err = sshClient.CopyKeyToRemote(pair)
	if err != nil {
		log.Fatalf("Failed to copy keys: %s\n", err)
		return -1
	}

	config.Hosts = append(config.Hosts, newHost)
	err = writeConfig(config)
	if err != nil {
		log.Fatalf("Failed to write config: %s\n", err)
		return -1
	}

	fmt.Printf("Successfully added host '%s' as a target.\n", host)
	return 0

}

/*
 * Delete a target host
 */
func DeleteHost(name string) int {

	err := initLocal()
	if err != nil {
		return -1
	}

	config, err := loadConfig()
	if err != nil {
		return -1
	}

	index, _ := FindHost(config, name)
	if index >= 0 {
		config.Hosts = append(config.Hosts[:index], config.Hosts[index+1:]...)
	}

	err = writeConfig(config)
	if err != nil {
		return -1
	}

	fmt.Printf("Successfully deleted host '%s' from targets.\n", name)
	return 0

}

/*
 * Update a target host
 */
func UpdateHost(name string, host Host, noPassword bool) int {

	err := initLocal()
	if err != nil {
		return -1
	}

	config, err := loadConfig()
	if err != nil {
		return -1
	}

	if host.HomePath == "" {
		host.HomePath = fmt.Sprintf("/home/%s", host.Username)
	}

	index, _ := FindHost(config, name)
	if index >= 0 {
		newHosts := config.Hosts[:index]
		newHosts = append(newHosts, host)
		newHosts = append(newHosts, config.Hosts[index+1:]...)
		config.Hosts = newHosts
	} else {
		fmt.Printf("No target '%s' exists. Add it first.\n", name)
		return -1
	}

	password := os.Getenv(fmt.Sprintf("NEWHOST_PASSWORD_%s", host.Name))
	if password == "" {
		fmt.Println("Need remote password to copy keys to remote host.")
		password, err = getUserCredentials()
		if err != nil {
			log.Fatal("Failed to retrieve user password: ", err)
			return -1
		}
	}

	// Copy SSH keys to remote host
	sshClient := crypto.SshClient{
		Address:         host.Address,
		Port:            host.Port,
		Username:        host.Username,
		HostKeyCallback: PromptAtKey,
		KnownHostsFile:  getKnownHostsFile(),
	}

	sshClient.SetPasswordAuth(password)

	err = sshClient.NewCryptoContext()
	if err != nil {
		log.Fatal("Failed to establish SSH connection: ", err)
		return -1
	}

	pair := crypto.SshKeyPair{
		PrivateKeyFile: getPrivateKeyFilename(),
		PublicKeyFile:  getPublicKeyFilename(),
		BitSize:        4096,
	}
	err = sshClient.CopyKeyToRemote(pair)
	if err != nil {
		return -1
	}

	err = writeConfig(config)
	if err != nil {
		return -1
	}

	fmt.Printf("Successfully updated host '%s' in targets.\n", name)
	return 0

}

/*
 * list configured hosts - print to stdout
 */
func ListHosts() int {

	err := initLocal()
	if err != nil {
		return -1
	}

	config, err := loadConfig()
	if err != nil {
		return -1
	}

	fmt.Println("Configured Target Hosts")
	w := tabwriter.NewWriter(os.Stdout, 1, 1, 3, ' ', 0)
	fmt.Fprintln(w, "Name\tHostname/IP\tSSH port")
	for _, host := range config.Hosts {
		fmt.Fprintf(w, "%s\t%s\t%d\n", host.Name, host.Address, host.Port)
	}
	w.Flush()

	return 0

}
