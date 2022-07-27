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

	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v2"
)

const helmChartGit = "https://github.com/e2guardian-angel/guardian-helm.git"

type PhraseGroup struct {
	GroupName string
	Phrases   [][]string
	Includes  []string
}

type SiteGroup struct {
	GroupName string
	Sites     []string
}

type RegexGroup struct {
	GroupName string
	Patterns  []string
}

type TypeGroup struct {
	GroupName string
	Types     []string
}

type ExtensionGroup struct {
	GroupName  string
	Extensions []string
}

type PhraseList struct {
	ListName string
	Groups   []PhraseGroup
}

type SiteLists struct {
	ListName string
	Groups   []SiteGroup
}

type RegexList struct {
	ListName string
	Groups   []RegexGroup
}

type TypeList struct {
	ListName string
	Groups   []TypeGroup
}

type ExtensionList struct {
	ListName string
	Groups   []ExtensionGroup
}

type AclRule struct {
	Category string
	Allow    bool
}

type E2guardianConfig struct {
	PhraseLists    []PhraseList
	SiteLists      []SiteGroup
	Regexpurlists  []RegexGroup
	Mimetypelists  []TypeGroup
	Extensionslist []ExtensionGroup
}

type TlsSecret struct {
	Cert string `yaml:"cert,omitempty"`
	Key  string `yaml:"key,omitempty"`
}

type FilterConfig struct {
	// Host specific
	MasterNode string `yaml:"masterNode"`
	VolumePath string `yaml:"volumePath"`
	// Network
	LocalNetwork     string `yaml:"localNetwork"`
	GatewayIP        string `yaml:"gatewayIP"`
	LocalTransparent bool   `yaml:"localTransparent"`
	// Lookup service
	GuardianReplicas int    `yaml:"guardianReplicas"`
	AclVolumeSize    string `yaml:"aclVolumeSize"`
	// Filter
	SquidPublicPort  int    `yaml:"squidPublicPort"`
	HttpsEnabled     bool   `yaml:"httpsEnabled"`
	Transparent      bool   `yaml:"transparent"`
	DecryptHTTPS     bool   `yaml:"decryptHTTPS"`
	AllowRules       string `yaml:"allowRules"`
	DecryptRules     string `yaml:"decryptRules"`
	E2guardianConfig string `yaml:"e2guardianConfig"`
	CacheTTL         int    `yaml:"cacheTTL"`
	MaxKeys          int    `yaml:"maxKeys"`
	FilterReplicas   int    `yaml:"filterReplicas"`
	PhraseVolumeSize string `yaml:"phraseVolumeSize"`
	// DNS
	SafeSearchEnforced bool `yaml:"safeSearchEnforced"`
	PublicDnsPort      int  `yaml:"publicDnsPort"`
	ReverseDnsPort     int  `yaml:"reverseDnsPort"`
	ReverseDnsReplicas int  `yaml:"reverseDnsReplicas"`
	// Postgres
	PostgresUser       string `yaml:"postgresUser"`
	PostgresDbName     string `yaml:"postgresDbName"`
	DbServicePort      int    `yaml:"dbServicePort"`
	GuardianDbReplicas int    `yaml:"guardianDbReplicas"`
	DbPassword         string `yaml:"dbPassword"`
	DbVolumeSize       string `yaml:"dbVolumeSize"`
	// CA cert info
	CaCountry    string `yaml:"caCountry"`
	CaState      string `yaml:"caState"`
	CaCity       string `yaml:"caCity"`
	CaOrg        string `yaml:"caOrg"`
	CaOrgUnit    string `yaml:"caOrgUnit"`
	CaCommonName string `yaml:"caCommonName"`
	CaEmail      string `yaml:"caEmail"`
	CaValidDays  int    `yaml:"caValidDays"`
	// Redis config
	RedisHost     string    `yaml:"redisHost"`
	RedisPort     int       `yaml:"redisPort"`
	RedisReplicas int       `yaml:"redisReplicas"`
	RedisPassword string    `yaml:"redisPassword"`
	Tls           TlsSecret `yaml:"tls,omitempty"`
}

func getHelmPath() string {
	guardianHome := GuardianConfigHome()
	return path.Join(guardianHome, "helm")
}

func getHostVolumePath(host Host) string {
	return path.Join(host.HomePath, ".guardian", "volumes")
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
	filterConfigPath := getHostFilterConfigPath(host)
	return loadFilterConfig(filterConfigPath)
}

/*
 * Save the host's filter config
 */
func writeHostFilterConfig(host string, config FilterConfig) error {
	filterConfigPath := getHostFilterConfigPath(host)

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
	Items []struct {
		Metadata struct {
			Name string
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
		} else if len(result.Items) == 0 {
			return FilterConfig{}, errors.New("no nodes configured on remote host")
		}

		config.MasterNode = result.Items[0].Metadata.Name
		config.VolumePath = getHostVolumePath(host)
		config.RedisPassword = randomString(32)
		config.DbPassword = randomString(32)

		// Write config to file
		err = writeHostFilterConfig(host.Name, config)
		return config, err

	} else {
		return loadHostFilterConfig(host.Name)
	}

}

func copyHelmToRemote(host Host) error {

	srcPath := getHelmPath()
	overrides := getHostFilterConfigPath(host.Name)
	dstPath := getRemoteHelmPath(host)

	client, err := getHostSshClient(host)
	if err != nil {
		return err
	}

	// delete existing remote helm to prevent conflicts
	_, err = client.RunCommands([]string{fmt.Sprintf("rm -rf %s", dstPath)}, false)
	if err != nil {
		return fmt.Errorf("failed to wipe helm charts on remote target: %s", err)
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

func Deploy(name string) int {

	config, err := loadConfig()
	if err != nil {
		log.Fatal("Failed to load config: ", err)
		return -1
	}

	_, host := FindHost(config, name)
	if host.Name != name {
		log.Fatalf("Host %s doesn't exist, create it first", name)
		return -1
	}

	_, err = initHostConfig(host)
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

	_, err = client.RunCommands([]string{
		fmt.Sprintf("cd %s", getRemoteHelmPath(host)),
		"export KUBECONFIG=/etc/rancher/k3s/k3s.yaml",
		"helm upgrade --install --create-namespace -f overrides.yaml -n filter guardian-angel guardian-angel",
	}, true)
	if err != nil {
		log.Fatal("Failed to deploy filter config: ", err)
		return -1
	}

	fmt.Println("Deployment successful.")
	return 0
}
