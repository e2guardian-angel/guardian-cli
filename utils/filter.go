package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"path"
	"reflect"

	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v2"
)

const helmChartGit = "https://github.com/e2guardian-angel/guardian-helm.git"

type PhraseGroup struct {
	groupName string
	phrases   [][]string
	includes  []string
}

type SiteGroup struct {
	groupName string
	sites     []string
}

type RegexGroup struct {
	groupName string
	patterns  []string
}

type TypeGroup struct {
	groupName string
	types     []string
}

type ExtensionGroup struct {
	groupName  string
	extensions []string
}

type PhraseList struct {
	listName string
	groups   []PhraseGroup
}

type SiteLists struct {
	listName string
	groups   []SiteGroup
}

type RegexList struct {
	listName string
	groups   []RegexGroup
}

type TypeList struct {
	listName string
	groups   []TypeGroup
}

type ExtensionList struct {
	listName string
	groups   []ExtensionGroup
}

type AclRule struct {
	category string
	allow    bool
}

type E2guardianConfig struct {
	phraseLists    []PhraseList
	siteLists      []SiteGroup
	regexpurlists  []RegexGroup
	mimetypelists  []TypeGroup
	extensionslist []ExtensionGroup
}

type FilterConfig struct {
	// Host specific
	masterNode string
	volumePath string
	// Network
	localNetwork     string
	gatewayIP        string
	localTransparent bool
	// Lookup service
	lookupHostName    string // defunct
	internalHttpPort  int
	internalHttpsPort int
	guardianConfigDir string
	aclDatabaseFile   string // defunct
	guardianReplicas  int
	aclVolumeSize     string
	// Filter
	proxyHostName       string // defunct
	squidInternalPort   int
	squidPublicPort     int
	icapInternalPort    int
	squidConfigDir      string
	httpsEnabled        bool
	transparent         bool
	decryptHTTPS        bool
	allowRules          string
	decryptRules        string
	e2guardianConfigDir string
	phraseDir           string
	e2guardianConfig    string
	cacheTTL            int
	maxKeys             int
	filterReplicas      int
	phraseVolumeSize    string
	// DNS
	safeSearchEnforced bool
	publicDnsPort      int
	reverseDnsPort     int
	reverseDnsReplicas int
	// Postgres
	authDbHost         string
	persistentDbPath   string
	postgresUser       string
	postgresDbName     string
	dbInternalPort     int
	dbServicePort      int
	guardianDbReplicas int
	dbPassword         string
	dbVolumeSize       string
	// CA cert info
	caCountry    string
	caState      string
	caCity       string
	caOrg        string
	caOrgUnit    string
	caCommonName string
	caEmail      string
	caValidDays  int
	// Redis config
	redisHost     string
	redisPort     int
	redisReplicas int
	redisPassword string
}

var componentMap = map[string][]string{
	"guardian-angel": []string{
		"safeSearchEnforced",
	},
	"webfilter": []string{
		"transparent",
		"allowRules",
		"decryptRules",
		"e2guardianConfig",
		"cacheTTL",
		"maxKeys",
	},
	"guardian-db": []string{
		"dbPassword",
	},
	"dns": []string{
		"safeSearchEnforced",
	},
	"redis": []string{
		"redisHost",
		"redisPort",
		"redisReplicas",
		"redisPassword",
	},
}

func getHelmPath() string {
	guardianHome := GuardianConfigHome()
	return path.Join(guardianHome, "helm")
}

func getRemoteHelmPath(host Host) string {
	return path.Join(host.HomePath, ".guardian", "helm")
}

func checkoutHelm() error {

	helmPath := getHelmPath()
	/*
	 * TODO: instead of wiping the directory and re-cloning, just do a git pull
	 */
	os.RemoveAll(helmPath)
	os.MkdirAll(helmPath, 0o755)

	log.Printf("Cloning helm chart into \"%s\"...\n", helmPath)
	_, err := git.PlainClone(helmPath, false, &git.CloneOptions{
		URL:      helmChartGit,
		Progress: os.Stdout,
	})

	return err
}

/*
 * load a filter config from a YAML file
 */
func loadFilterConfig(fileName string) (FilterConfig, error) {
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		return FilterConfig{}, err
	}
	var config FilterConfig
	err = yaml.Unmarshal([]byte(data), &config)
	if err != nil {
		log.Fatal("Failed to parse config file: ", err)
		return FilterConfig{}, err
	}
	return config, err
}

/*
 * load the default filter config from values.json
 */
func loadDefaultFilterConfig() (FilterConfig, error) {
	helmPath := getHelmPath()
	defaultValuesFile := path.Join(helmPath, "guardian-angel", "values.yaml")
	config, err := loadFilterConfig(defaultValuesFile)
	return config, err
}

/*
 * load the filter config file for this host
 */
func loadHostFilterConfig(host string) (FilterConfig, error) {
	filterConfigPath := getHostDataDir(host)
	return loadFilterConfig(filterConfigPath)
}

/*
 * Find the diff between this config and the default
 */
func getFilterConfDiff(conf FilterConfig) ([]string, error) {

	var (
		diff        []string
		defaultConf FilterConfig
		confVal     reflect.Value
		defaultVal  reflect.Value
		err         error
	)

	if defaultConf, err = loadDefaultFilterConfig(); err != nil {
		return diff, err
	}

	// Ignore secrets and host-specific generated options
	defaultConf.masterNode = conf.masterNode
	defaultConf.dbPassword = conf.dbPassword
	defaultConf.redisPassword = conf.redisPassword

	confVal = reflect.ValueOf(conf)
	defaultVal = reflect.ValueOf(defaultConf)
	for i := 0; i < confVal.Type().NumField(); i++ {
		var (
			val1 reflect.Value = confVal.Index(i)
			val2 reflect.Value = defaultVal.Index(i)
		)
		if val1 != val2 {
			diff = append(diff, confVal.Type().Field(i).Name)
		}
	}

	return diff, nil

}

/*
 * Get the list of services to restart
 */

/*
 * Save the host's filter config
 */
func writeHostFilterConfig(host string, config FilterConfig) error {
	filterConfigPath := getHostDataDir(host)

	yamlString, err := yaml.Marshal(config)
	if err != nil {
		log.Fatal("Failed to marshal host filter config: ", err)
		return err
	}

	// Create config file
	f, err := os.Create(filterConfigPath)
	if err != nil {
		log.Fatal("Failed to create host filter config file: ", err)
		return err
	}
	defer f.Close()
	f.WriteString(string(yamlString))
	return nil
}

func getHostFilterConfigPath(host string) string {
	hostDataDir := getHostDataDir(host)
	return path.Join(hostDataDir, "overrides.yaml")
}

func randomString(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

type workerJson struct {
	items []struct {
		metadata struct {
			name string
		}
	}
}

/*
 * Init host config
 */
func initHostConfig(host Host) (FilterConfig, error) {

	err := checkoutHelm()
	if err != nil {
		return FilterConfig{}, err
	}

	hostFilterConfPath := getHostFilterConfigPath(host.Name)

	_, err = os.Stat(hostFilterConfPath)
	if os.IsNotExist(err) {

		// Use default config
		config, err := loadDefaultFilterConfig()
		if err != nil {
			return config, err
		}

		client, err := getHostSshClient(host)
		if err != nil {
			return FilterConfig{}, err
		}

		out, err := client.RunCommands([]string{
			"export KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
			"kubectl get nodes -o json",
		}, false)
		if err != nil {
			return FilterConfig{}, err
		}
		var result workerJson
		err = json.Unmarshal([]byte(out), &result)
		if err != nil {
			return FilterConfig{}, err
		} else if len(result.items) == 0 {
			return FilterConfig{}, errors.New("No nodes configured on remote host")
		}

		config.masterNode = result.items[0].metadata.name
		config.redisPassword = randomString(32)
		config.dbPassword = randomString(32)

		// Write config to file
		err = writeHostFilterConfig(host.Name, config)
		return config, err

	} else {
		return loadFilterConfig(host.Name)
	}

}

func copyHelmToRemote(host Host) error {

	srcPath := getHelmPath()
	overrides := getHostFilterConfigPath(host.Name)
	dstPath := getHostFilterConfigPath(host.Name)

	client, err := getHostSshClient(host)

	// delete existing remote helm to prevent conflicts
	_, err = client.RunCommands([]string{fmt.Sprintf("rm -rf %s", dstPath)}, false)
	if err != nil {
		return fmt.Errorf("Failed to wipe helm charts on remote target: %s", err)
	}

	err = client.Put(srcPath, dstPath)
	if err != nil {
		return err
	}

	overridesDst := path.Join(dstPath, "overrides.yaml")
	return client.Put(overrides, overridesDst)

}

/*
 * CLI methods
 */

func Deploy(host Host) int {

	_, err := initHostConfig(host)
	if err != nil {
		log.Fatal("Failed to initialize host filter config: ", err)
		return -1
	}

	// Copy helm files to remote host
	err = copyHelmToRemote(host)
	if err != nil {
		log.Fatal("Failed to copy helm data to remote host: ", err)
		return -1
	}

	// Run helm deploy
	client, err := getHostSshClient(host)
	if err != nil {
		log.Fatal("Failed to create SSH connection: ", err)
		return -1
	}

	// TODO: diff changes and generate commands for restarting services

	_, err = client.RunCommands([]string{
		fmt.Sprintf("cd %s", getRemoteHelmPath(host)),
		"export KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
		fmt.Sprintf("helm upgrade --install --create-namespace -f overrides.yaml -n filter guardian-angel guardian-angel"),
	}, true)
	if err != nil {
		log.Fatal("Failed to deploy filter config: ", err)
		return -1
	}

	return 0
}
