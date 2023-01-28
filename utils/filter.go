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
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"gopkg.in/yaml.v2"
)

const helmChartGit = "https://github.com/e2guardian-angel/guardian-helm.git"

type PhraseGroup struct {
	GroupName string     `yaml:"groupName"`
	Phrases   [][]string `yaml:"phrases"`
	Includes  []string   `yaml:"includes"`
}

type SiteGroup struct {
	GroupName string   `yaml:"groupName"`
	Sites     []string `yaml:"sites"`
}

type RegexGroup struct {
	GroupName string   `yaml:"groupName"`
	Patterns  []string `yaml:"patterns"`
}

type TypeGroup struct {
	GroupName string   `yaml:"groupName"`
	Types     []string `yaml:"types"`
}

type ExtensionGroup struct {
	GroupName  string   `yaml:"groupName"`
	Extensions []string `yaml:"extensions"`
}

type PhraseList struct {
	ListName string        `yaml:"listName"`
	Groups   []PhraseGroup `yaml:"groups"`
}

type SiteLists struct {
	ListName string      `yaml:"listName"`
	Groups   []SiteGroup `yaml:"groups"`
}

type RegexList struct {
	ListName string       `yaml:"listName"`
	Groups   []RegexGroup `yaml:"groups"`
}

type TypeList struct {
	ListName string      `yaml:"listName"`
	Groups   []TypeGroup `yaml:"groups"`
}

type ExtensionList struct {
	ListName string           `yaml:"listName"`
	Groups   []ExtensionGroup `yaml:"groups"`
}

type AllowRule struct {
	Category string `yaml:"category"`
	Allow    bool   `yaml:"allow"`
}

type DecryptRule struct {
	Category string `yaml:"category"`
	Decrypt  bool   `yaml:"allow"`
}

type E2guardianConfig struct {
	PhraseLists     []PhraseList     `yaml:"phraseLists"`
	SiteLists       []SiteGroup      `yaml:"siteLists"`
	Regexpurlists   []RegexGroup     `yaml:"regexpurllists"`
	Mimetypelists   []TypeGroup      `yaml:"mimetypelists"`
	Extensionslists []ExtensionGroup `yaml:"extensionslists"`
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
	LocalNetwork string `yaml:"localNetwork"`
	// Lookup service
	GuardianReplicas int    `yaml:"guardianReplicas"`
	AclVolumeSize    string `yaml:"aclVolumeSize"`
	// Filter
	SquidPublicPort int              `yaml:"squidPublicPort"`
	Transparent     bool             `yaml:"transparent"`
	DecryptHTTPS    bool             `yaml:"decryptHTTPS"`
	AllowRules      []AllowRule      `yaml:"allowRules"`
	DecryptRules    []DecryptRule    `yaml:"decryptRules"`
	E2guardianConf  E2guardianConfig `yaml:"e2guardianConfig"`
	CacheTTL        int              `yaml:"cacheTTL"`
	MaxKeys         int              `yaml:"maxKeys"`
	FilterReplicas  int              `yaml:"filterReplicas"`
	// DNS
	SafeSearchEnforced bool `yaml:"safeSearchEnforced"`
	PublicDnsPort      int  `yaml:"publicDnsPort"`
	ReverseDnsReplicas int  `yaml:"reverseDnsReplicas"`
	// Postgres
	GuardianDbReplicas int    `yaml:"guardianDbReplicas"`
	DbPassword         string `yaml:"dbPassword"`
	DbVolumeSize       string `yaml:"dbVolumeSize"`
	// Redis config
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

	outputStream := os.Stdout
	log.Printf("Cloning helm chart into \"%s\"...\n", helmPath)

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

func getHostFilterConfig(hostName string) (FilterConfig, error) {

	guardianConf, err := loadConfig()
	if err != nil {
		return FilterConfig{}, err
	}

	_, host := FindHost(guardianConf, hostName)
	if host.Name != hostName {
		return FilterConfig{}, fmt.Errorf("Host '%s' is not configured", hostName)
	}

	filterConfig, err := initHostConfig(host)
	if err != nil {
		return FilterConfig{}, err
	}

	return filterConfig, nil
}

func (config *E2guardianConfig) findPhraseList(listName string) *PhraseList {
	for i := range config.PhraseLists {
		list := &config.PhraseLists[i]
		if list.ListName == listName {
			return list
		}
	}
	return nil
}

func (list *PhraseList) findPhraseGroup(groupName string) *PhraseGroup {
	for i := range list.Groups {
		group := &list.Groups[i]
		if group.GroupName == groupName {
			return group
		}
	}
	return nil
}

func phrasesMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	} else {
		sort.Strings(a)
		sort.Strings(b)
		for i, term := range a {
			if b[i] != term {
				return false
			}
		}
		return true
	}
}

func (group *PhraseGroup) findPhrase(phrase []string) *[]string {
	for _, currentPhrase := range group.Phrases {
		if phrasesMatch(currentPhrase, phrase) {
			return &currentPhrase
		}
	}
	return nil
}

/*
 * CLI methods
 */
/* Add a new phrase list */
func AddPhraseList(listName string, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList != nil {
		log.Fatalf("Phrase list '%s' already exists", listName)
		return -1
	}

	config.E2guardianConf.PhraseLists = append(config.E2guardianConf.PhraseLists, PhraseList{ListName: listName})

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully added phrase list '%s'\n", listName)
	return 0

}

/* Add phrase to existing list */
func AddPhraseToList(listName string, phrase string, group string, targetName string, weight int) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList == nil {
		log.Fatalf("Phrase list '%s' does not exist", listName)
		return -1
	}

	phraseGroup := phraseList.findPhraseGroup(group)
	if phraseGroup == nil {
		// Add this phrase group
		phraseList.Groups = append(phraseList.Groups, PhraseGroup{GroupName: group})
		phraseGroup = phraseList.findPhraseGroup(group)
	}

	terms := strings.Split(phrase, ",")
	existingPhrase := phraseGroup.findPhrase(terms)
	if existingPhrase != nil {
		// no name group displayed as 'default'
		groupName := "default"
		if group != "" {
			groupName = group
		}
		log.Fatalf("Phrase '%s' already exists in group '%s' of phrase list '%s'", phrase, groupName, listName)
		return -1
	}

	// TODO: format terms for e2guardian
	if weight != 0 {
		terms = append(terms, strconv.Itoa(weight))
	}
	phraseGroup.Phrases = append(phraseGroup.Phrases, terms)

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully added phrase to list '%s'\n", listName)
	return 0

}

/* Dump a given phrase list */
func ShowPhraseList(listName string, targetName string, group string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList == nil {
		log.Fatalf("Phrase list '%s' does not exist for target '%s", listName, targetName)
		return -1
	}

	var groups []PhraseGroup

	if group != "" {
		phraseGroup := phraseList.findPhraseGroup(group)
		if phraseGroup == nil {
			log.Fatalf("Group '%s' does not exist for phrase list '%s'", group, listName)
			return -1
		}
		groups = []PhraseGroup{*phraseGroup}
	} else {
		groups = phraseList.Groups
	}

	for i := range groups {
		group := groups[i]
		log.Printf("Group: %s", group.GroupName)
		log.Printf("=== INCLUDES ===")
		// Dump includes
		for j := range group.Includes {
			include := group.Includes[j]
			log.Println(include)
		}
		log.Printf("=== PHRASES ===")
		for j := range group.Phrases {
			phrase := group.Phrases[j]
			phraseString := ""
			for k := range phrase {
				term := phrase[k]
				weight, err := strconv.Atoi(term)
				if k == len(phrase)-1 && err == nil {
					phraseString = fmt.Sprintf("%s (weight=%d)", phraseString, weight)
				} else {
					phraseString = fmt.Sprintf("%s<%s>", phraseString, term)
				}
			}
			log.Println(phraseString)
		}
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
