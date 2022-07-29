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
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v2"
)

const helmChartGit = "https://github.com/e2guardian-angel/guardian-helm.git"

type PhraseGroup struct {
	GroupName string     `json:"groupName"`
	Phrases   [][]string `json:"phrases"`
	Includes  []string   `json:"includes"`
}

type SiteGroup struct {
	GroupName string   `json:"groupName"`
	Sites     []string `json:"sites"`
}

type RegexGroup struct {
	GroupName string   `json:"groupName"`
	Patterns  []string `json:"patterns"`
}

type TypeGroup struct {
	GroupName string   `json:"groupName"`
	Types     []string `json:"types"`
}

type ExtensionGroup struct {
	GroupName  string   `json:"groupName"`
	Extensions []string `json:"extensions"`
}

type PhraseList struct {
	ListName string        `json:"listName"`
	Groups   []PhraseGroup `json:"groups"`
}

type SiteLists struct {
	ListName string      `json:"listName"`
	Groups   []SiteGroup `json:"groups"`
}

type RegexList struct {
	ListName string       `json:"listName"`
	Groups   []RegexGroup `json:"groups"`
}

type TypeList struct {
	ListName string      `json:"listName"`
	Groups   []TypeGroup `json:"groups"`
}

type ExtensionList struct {
	ListName string           `json:"listName"`
	Groups   []ExtensionGroup `json:"groups"`
}

type AclRule struct {
	Category string `json:"category"`
	Allow    bool   `json:"allow"`
}

type E2guardianConfig struct {
	PhraseLists     []PhraseList     `json:"phraseLists"`
	SiteLists       []SiteGroup      `json:"siteLists"`
	Regexpurlists   []RegexGroup     `json:"regexpurllists"`
	Mimetypelists   []TypeGroup      `json:"mimetypelists"`
	Extensionslists []ExtensionGroup `json:"extensionslists"`
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

func checkoutHelm(dumpOutput bool) error {

	helmPath := getHelmPath()
	/*
	 * TODO: instead of wiping the directory and re-cloning, just do a git pull
	 */
	os.RemoveAll(helmPath)
	os.MkdirAll(helmPath, 0o755)

	var outputStream *os.File
	if dumpOutput {
		outputStream = os.Stdout
		log.Printf("Cloning helm chart into \"%s\"...\n", helmPath)
	} else {
		outputStream = nil
	}

	_, err := git.PlainClone(helmPath, false, &git.CloneOptions{
		URL:      helmChartGit,
		Progress: outputStream,
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

	hostFilterConfPath := getHostFilterConfigPath(host.Name)

	_, err := os.Stat(hostFilterConfPath)
	if os.IsNotExist(err) {

		err = checkoutHelm(false)
		if err != nil {
			return FilterConfig{}, err
		}

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

	err := checkoutHelm(true)
	if err != nil {
		return err
	}

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

// Set the field by name string
// Copied from: https://gist.github.com/lelandbatey/a5c957b537bed39d1d6fb202c3b8de06
func SetField(item interface{}, fieldName string, value interface{}) error {
	v := reflect.ValueOf(item).Elem()
	if !v.CanAddr() {
		return fmt.Errorf("cannot assign to the item passed, item must be a pointer in order to assign")
	}
	// It's possible we can cache this, which is why precompute all these ahead of time.
	findYamlName := func(t reflect.StructTag) (string, error) {
		if jt, ok := t.Lookup("yaml"); ok {
			return strings.Split(jt, ",")[0], nil
		}
		return "", fmt.Errorf("tag provided does not define a yaml tag", fieldName)
	}
	fieldNames := map[string]int{}
	for i := 0; i < v.NumField(); i++ {
		typeField := v.Type().Field(i)
		tag := typeField.Tag
		jname, _ := findYamlName(tag)
		fieldNames[jname] = i
	}

	fieldNum, ok := fieldNames[fieldName]
	if !ok {
		return fmt.Errorf("field %s does not exist within the provided item", fieldName)
	}
	fieldVal := v.Field(fieldNum)
	fieldVal.Set(reflect.ValueOf(value))
	return nil
}

type e2gUpdateFunc func(e2gConf *E2guardianConfig) error

/* update a phrase list */
func updatePhraseList(targetName string, modifier e2gUpdateFunc) error {

	config, err := loadConfig()
	if err != nil {
		return fmt.Errorf("Failed to load config: %s", err)
	}

	_, host := FindHost(config, targetName)
	if host.Name != targetName {
		return fmt.Errorf("Host %s doesn't exist, create it first", targetName)
	}

	hostConfig, err := initHostConfig(host)
	if err != nil {
		return fmt.Errorf("Failed to initialize host filter config: %s", err)
	}

	e2gConfig := E2guardianConfig{}
	err = json.Unmarshal([]byte(hostConfig.E2guardianConfig), &e2gConfig)
	if err != nil {
		return fmt.Errorf("e2guardian config is in a bad format: %s", err)
	}

	err = modifier(&e2gConfig)
	if err != nil {
		return fmt.Errorf("failed to update e2guardian config: %s", err)
	}

	var e2gConfigData []byte
	e2gConfigData, err = json.Marshal(e2gConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal e2guardian config to json: ", err)
	}

	hostConfig.E2guardianConfig = string(e2gConfigData)
	return writeHostFilterConfig(targetName, hostConfig)

}

func findPhraseList(e2gConf *E2guardianConfig, listName string) (int, *PhraseList) {
	for i, value := range e2gConf.PhraseLists {
		if listName == value.ListName {
			return i, &e2gConf.PhraseLists[i]
		}
	}
	return -1, nil
}

func findPhraseGroup(list *PhraseList, groupName string) (int, *PhraseGroup) {
	for i, value := range list.Groups {
		if groupName == value.GroupName {
			return i, &list.Groups[i]
		}
	}
	return -1, nil
}

func findPhrase(group *PhraseGroup, phrase string) int {
	phraseA := strings.Split(phrase, ",")
	sort.Strings(phraseA)
	for i, phraseB := range group.Phrases {
		sort.Strings(phraseB)
		if len(phraseA) != len(phraseB) {
			continue
		}
		for j, term := range phraseA {
			if term != phraseB[j] {
				continue
			}
			if j == len(phraseA)-1 {
				// if we reached the end of the terms, then this phrase matches
				return i
			}
		}
	}
	return -1
}

/*
 * CLI methods
 */
/* Add a new phrase list */
func AddPhraseList(listName string, targetName string) int {

	err := updatePhraseList(targetName, func(e2gConf *E2guardianConfig) error {
		index, _ := findPhraseList(e2gConf, listName)
		if index != -1 {
			return fmt.Errorf("list %s already exists", listName)
		}
		e2gConf.PhraseLists = append(e2gConf.PhraseLists, PhraseList{
			ListName: listName,
			Groups:   []PhraseGroup{},
		})
		return nil
	})
	if err != nil {
		log.Fatal(err)
		return -1
	}

	log.Printf("Successfully added phrase list '%s'\n", listName)
	return 0

}

/* Add phrase to existing list */
func AddPhraseToList(listName string, phrase string, group string, targetName string) int {

	groupName := "default"
	if group != "" {
		groupName = group
	}

	err := updatePhraseList(targetName, func(e2gConf *E2guardianConfig) error {

		phraseListIndex, phraseList := findPhraseList(e2gConf, listName)
		if phraseListIndex == -1 {
			return fmt.Errorf("phrase list '%s' does not exist in the config", listName)
		}
		phraseGroupIndex, phraseGroup := findPhraseGroup(phraseList, groupName)
		if phraseGroupIndex == -1 {
			// Create a new group
			phraseList.Groups = append(phraseList.Groups, PhraseGroup{
				GroupName: groupName,
				Phrases:   [][]string{},
				Includes:  []string{},
			})
			phraseGroupIndex, phraseGroup = findPhraseGroup(phraseList, groupName)
		}
		phraseIndex := findPhrase(phraseGroup, phrase)
		if phraseIndex != -1 {
			return fmt.Errorf("phrase already exists")
		}
		phraseGroup.Phrases = append(phraseGroup.Phrases, strings.Split(phrase, ","))
		//e2gConf.PhraseLists[phraseListIndex] = *phraseList
		return nil
	})
	if err != nil {
		log.Fatal(err)
		return -1
	}

	return 0

}

/* Deploy changes to target */
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
		"dd if=/dev/null of=overrides.yaml",
		"rm overrides.yaml",
	}, true)
	if err != nil {
		log.Fatal("Failed to deploy filter config: ", err)
		return -1
	}

	fmt.Println("Deployment successful.")
	return 0
}
