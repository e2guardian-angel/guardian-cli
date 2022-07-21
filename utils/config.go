package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"text/tabwriter"
)

/*
 * DATA DEFINITIONS
 */

type Host struct {
	Name     string
	Address  string
	Username string
	Port     uint16
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
func loadConfig() (error, Configuration) {
	guardianHome := GuardianConfigHome()
	configFile := path.Join(guardianHome, "config.json")
	data, err := ioutil.ReadFile(configFile)
	if err != nil {
		return err, Configuration{}
	}
	var config Configuration
	err = json.Unmarshal([]byte(data), &config)
	if err != nil {
		log.Fatal("Failed to parse config file: ", err)
		return err, Configuration{}
	}
	return nil, config
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

	f.WriteString(string(jsonString))
	return nil
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
func AddHost(name string, host string, port uint16, username string, noPassword bool) int {

	err := initLocal()
	if err != nil {
		return -1
	}

	err, config := loadConfig()
	if err != nil {
		return -1
	}

	_, foundHost := FindHost(config, name)
	hostExists := (foundHost.Name == name)
	if hostExists {
		log.Fatal("Host with name '", name, "' already exists, did you mean to update it?")
		return -1
	}

	newHost := Host{name, host, username, port}
	err = copySshKeys(newHost, noPassword)
	if err != nil {
		return -1
	}

	config.Hosts = append(config.Hosts, newHost)
	err = writeConfig(config)
	if err != nil {
		return -1
	}

	fmt.Println("Successfully added host '", name, "' as a target.")
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

	err, config := loadConfig()
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

	fmt.Println("Successfully deleted host '", name, "' from targets.")
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

	err, config := loadConfig()
	if err != nil {
		return -1
	}

	index, _ := FindHost(config, name)
	if index >= 0 {
		newHosts := config.Hosts[:index]
		newHosts = append(newHosts, host)
		newHosts = append(newHosts, config.Hosts[index+1:]...)
		config.Hosts = newHosts
	} else {
		fmt.Println("No target '", name, "' exists. Add it first.")
		return -1
	}

	err = copySshKeys(host, noPassword)
	if err != nil {
		return -1
	}

	err = writeConfig(config)
	if err != nil {
		return -1
	}

	fmt.Println("Successfully update host '", name, "' in targets.")
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

	err, config := loadConfig()
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