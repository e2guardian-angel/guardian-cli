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

type Phrase struct {
	Phrase []string `yaml:"phrase"`
	Weight int      `yaml:"weight"`
}

type PhraseGroup struct {
	GroupName string   `yaml:"groupName"`
	Phrases   []Phrase `yaml:"phrases"`
}

type PhraseList struct {
	ListName  string        `yaml:"listName"`
	IncludeIn []string      `yaml:"includeIn"`
	Groups    []PhraseGroup `yaml:"groups"`
	Weighted  bool
}

type ContentGroup struct {
	GroupName string   `yaml:"name"`
	Items     []string `yaml:"items"`
}

type ContentList struct {
	ListName  string         `yaml:"list"`
	IncludeIn []string       `yaml:"includeIn"`
	Type      string         `yaml:"type"`
	Groups    []ContentGroup `yaml:"groups"`
}

type AllowRule struct {
	Category string `yaml:"category"`
	Allow    bool   `yaml:"allow"`
}

type DecryptRule struct {
	Category string `yaml:"category"`
	Decrypt  bool   `yaml:"decrypt"`
}

type E2guardianConfig struct {
	PhraseLists         []PhraseList  `yaml:"phraseLists"`
	WeightedPhraseLists []PhraseList  `yaml:"weightedPhraseLists"`
	Lists               []ContentList `yaml:"lists"`
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
	E2guardianConf  E2guardianConfig `yaml:"e2guardianConf"`
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
	RedisReplicas int    `yaml:"redisReplicas"`
	RedisPassword string `yaml:"redisPassword"`
	// Nginx
	NginxReplicas int    `yaml:"nginxReplicas"`
	WebCn         string `yaml:"webCn"`

	// CI/CD
	ReleaseTag string `yaml:"releaseTag,omitempty"`

	// Certificate
	CommonName   string `yaml:"commonName"`
	Organization string `yaml:"organization"`
	Country      string `yaml:"country"`
	State        string `yaml:"state"`
	Locality     string `yaml:"locality"`
}

var ListTypes = []string{"sitelist", "regexpurllist", "mimetypelist", "extensionslist"}
var AclActions = []string{"allow", "deny", "decrypt", "nodecrypt"}

var banLists = map[string]string{
	"sitelist":       "bannedsitelist",
	"regexpurllist":  "bannedregexpurllist",
	"mimetypelist":   "bannedmimetypelist",
	"extensionslist": "bannedextensionlist",
}

var allowLists = map[string]string{
	"sitelist":       "exceptionsitelist",
	"regexpurllist":  "exceptionregexpurllist",
	"mimetypelist":   "exceptionmimetypelist",
	"extensionslist": "exceptionextensionlist",
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
		return "", fmt.Errorf("tag '%s' provided does not define a yaml tag", fieldName)
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

func (config *E2guardianConfig) findWeightedPhraseList(listName string) *PhraseList {
	for i := range config.WeightedPhraseLists {
		list := &config.WeightedPhraseLists[i]
		if list.ListName == listName {
			return list
		}
	}
	return nil
}

func (config *E2guardianConfig) findContentList(listName string) *ContentList {
	for i := range config.Lists {
		list := &config.Lists[i]
		if list.ListName == listName {
			return list
		}
	}
	return nil
}

func (list *PhraseList) findPhraseGroup(groupName string) *PhraseGroup {
	for i := range list.Groups {
		group := &list.Groups[i]
		if group.GroupName == groupName || (groupName == "default" && group.GroupName == "") {
			return group
		}
	}
	return nil
}

func (list *ContentList) findContentGroup(groupName string) *ContentGroup {
	for i := range list.Groups {
		group := &list.Groups[i]
		if group.GroupName == groupName || (groupName == "default" && group.GroupName == "") {
			return group
		}
	}
	return nil
}

func (config *E2guardianConfig) deletePhraseList(listName string) bool {
	// First try the phrase lists
	for i := range config.PhraseLists {
		if config.PhraseLists[i].ListName == listName {
			config.PhraseLists = append(
				config.PhraseLists[:i],
				config.PhraseLists[i+1:]...)
			return true
		}
	}
	// Now try the weighted ones
	for i := range config.WeightedPhraseLists {
		if config.WeightedPhraseLists[i].ListName == listName {
			config.WeightedPhraseLists = append(
				config.WeightedPhraseLists[:i],
				config.WeightedPhraseLists[i+1:]...)
			return true
		}
	}
	return false
}

func (config *E2guardianConfig) deleteContentList(listName string) bool {
	for i := range config.Lists {
		if config.Lists[i].ListName == listName {
			config.Lists = append(
				config.Lists[:i],
				config.Lists[i+1:]...)
			return true
		}
	}
	return false
}

func (config *FilterConfig) AclRuleExists(category string, action string) bool {
	if action == "allow" || action == "deny" {
		allow := (action == "allow")
		for _, rule := range config.AllowRules {
			if rule.Allow == allow && rule.Category == category {
				return true
			}
		}
	} else if action == "decrypt" || action == "nodecrypt" {
		decrypt := (action == "decrypt")
		for _, rule := range config.DecryptRules {
			if rule.Category == category && rule.Decrypt == decrypt {
				return true
			}
		}
	}
	// Rule does not exist, or action string is wrong
	return false
}

func (config *FilterConfig) AddAclRule(category string, action string, pos int) {
	if action == "allow" || action == "deny" {
		allow := (action == "allow")
		i := pos
		if pos < 0 || pos > len(config.AllowRules) {
			i = len(config.AllowRules)
		}
		after := append([]AllowRule{{Category: category, Allow: allow}}, config.AllowRules[i:]...)
		config.AllowRules = append(config.AllowRules[:i], after...)
	} else {
		decrypt := (action == "decrypt")
		i := pos
		if pos < 0 || pos > len(config.DecryptRules) {
			i = len(config.DecryptRules)
		}
		after := append([]DecryptRule{{Category: category, Decrypt: decrypt}}, config.DecryptRules[i:]...)
		config.DecryptRules = append(config.DecryptRules[:i], after...)
	}
}

func (config *FilterConfig) DeleteAllowRule(category string, action string) []AllowRule {
	allow := (action == "allow")
	for i, rule := range config.AllowRules {
		if category == rule.Category && allow == rule.Allow {
			return append(config.AllowRules[:i], config.AllowRules[i+1:]...)
		}
	}
	return config.AllowRules
}

func (config *FilterConfig) DeleteDecryptRule(category string, action string) []DecryptRule {
	decrypt := (action == "decrypt")
	for i, rule := range config.DecryptRules {
		if category == rule.Category && decrypt == rule.Decrypt {
			return append(config.DecryptRules[:i], config.DecryptRules[i+1:]...)
		}
	}
	return config.DecryptRules
}

func (config *FilterConfig) shouldDecrypt() bool {
	for _, rule := range config.DecryptRules {
		if rule.Decrypt {
			return true
		}
	}
	return false
}

func phrasesMatch(a, b Phrase) bool {
	if len(a.Phrase) != len(b.Phrase) {
		return false
	} else {
		sort.Strings(a.Phrase)
		sort.Strings(b.Phrase)
		for i, term := range a.Phrase {
			if b.Phrase[i] != term {
				return false
			}
		}
		return true
	}
}

func (group *PhraseGroup) findPhrase(phrase Phrase) *Phrase {
	for _, currentPhrase := range group.Phrases {
		if phrasesMatch(currentPhrase, phrase) {
			return &currentPhrase
		}
	}
	return nil
}

func (group *ContentGroup) findEntry(entry string) string {
	for _, currentEntry := range group.Items {
		if currentEntry == entry {
			return entry
		}
	}
	return ""
}

func (group *PhraseGroup) removePhrase(phrase Phrase) []Phrase {
	for i, currentPhrase := range group.Phrases {
		if phrasesMatch(currentPhrase, phrase) {
			group.Phrases = append(group.Phrases[:i], group.Phrases[i+1:]...)
		}
	}
	return group.Phrases
}

func (group *ContentGroup) removeEntry(entry string) []string {
	for i, currentEntry := range group.Items {
		if currentEntry == entry {
			group.Items = append(group.Items[:i], group.Items[i+1:]...)
		}
	}
	return group.Items
}

func (list *PhraseList) findInclude(fileName string) string {
	for _, fname := range list.IncludeIn {
		if fname == fileName {
			return fname
		}
	}
	return ""
}

func (list *ContentList) findInclude(fileName string) string {
	for _, fname := range list.IncludeIn {
		if fname == fileName {
			return fname
		}
	}
	return ""
}

func (list *PhraseList) deleteGroup(groupName string) []PhraseGroup {
	for i, gname := range list.Groups {
		if gname.GroupName == groupName {
			list.Groups = append(list.Groups[:i], list.Groups[i+1:]...)
		}
	}
	return list.Groups
}

func (list *ContentList) deleteGroup(groupName string) []ContentGroup {
	for i, gname := range list.Groups {
		if gname.GroupName == groupName {
			list.Groups = append(list.Groups[:i], list.Groups[i+1:]...)
		}
	}
	return list.Groups
}

/*
 * CLI methods
 */
/* Add a new phrase list */
func AddPhraseList(listName string, weighted bool, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	var phraseList *PhraseList
	if weighted {
		phraseList = config.E2guardianConf.findWeightedPhraseList(listName)
	} else {
		phraseList = config.E2guardianConf.findPhraseList(listName)
	}
	if phraseList != nil {
		log.Fatalf("Phrase list '%s' already exists", listName)
		return -1
	}

	if weighted {
		config.E2guardianConf.WeightedPhraseLists = append(config.E2guardianConf.WeightedPhraseLists, PhraseList{ListName: listName, Weighted: true})
	} else {
		config.E2guardianConf.PhraseLists = append(config.E2guardianConf.PhraseLists, PhraseList{ListName: listName, Weighted: false})
	}

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully added phrase list '%s'\n", listName)
	return 0

}

/* Add a new phrase list */
func DeletePhraseList(listName string, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	deleted := config.E2guardianConf.deletePhraseList(listName)

	// If we are here, then the phrase list doesn't exist
	if deleted {
		log.Printf("Successfully deleted phrase list '%s' from config for target '%s'", listName, targetName)
		err = writeHostFilterConfig(targetName, config)
		if err != nil {
			log.Fatal("Failed to write host config: ", err)
			return -1
		}
		return 0
	} else {
		log.Fatalf("Phrase list '%s' doesn't exist\n", listName)
		return -1
	}

}

/* Add phrase to existing list */
func AddPhraseToList(listName string, phrase Phrase, group string, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	var phraseList *PhraseList

	if phrase.Weight > 0 {
		phraseList = config.E2guardianConf.findWeightedPhraseList(listName)
	} else {
		phraseList = config.E2guardianConf.findPhraseList(listName)
	}
	if phraseList == nil {
		phraseStr := "Phrase list"
		if phrase.Weight > 0 {
			phraseStr = "Weighted phrase list"
		}
		log.Fatalf("%s '%s' does not exist", phraseStr, listName)
		return -1
	}

	phraseGroup := phraseList.findPhraseGroup(group)
	if phraseGroup == nil {
		// Add this phrase group
		phraseList.Groups = append(phraseList.Groups, PhraseGroup{GroupName: group})
		phraseGroup = phraseList.findPhraseGroup(group)
	}

	existingPhrase := phraseGroup.findPhrase(phrase)
	if existingPhrase != nil {
		// no name group displayed as 'default'
		groupName := "default"
		if group != "" {
			groupName = group
		}
		if phrase.Weight > 0 {
			log.Printf("Weighted phrase '%s' already exists in group '%s' of weighted phrase list '%s'; updating weight to %d", phrase.Phrase, groupName, listName, phrase.Weight)
			phraseGroup.Phrases = phraseGroup.removePhrase(phrase)
		} else {
			log.Fatalf("Phrase '%s' already exists in group '%s' of phrase list '%s'", phrase.Phrase, groupName, listName)
			return -1
		}
	}

	phraseGroup.Phrases = append(phraseGroup.Phrases, phrase)

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully added phrase to list '%s'\n", listName)
	return 0

}

/* Delete phrase from existing list */
func DeletePhraseFromList(listName string, phrase Phrase, group string, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList == nil {
		if phraseList = config.E2guardianConf.findWeightedPhraseList(listName); phraseList == nil {
			log.Fatalf("Phrase list '%s' does not exist", listName)
			return -1
		}
	}

	phraseGroup := phraseList.findPhraseGroup(group)
	if phraseGroup == nil {
		// Add this phrase group
		phraseList.Groups = append(phraseList.Groups, PhraseGroup{GroupName: group})
		phraseGroup = phraseList.findPhraseGroup(group)
	}

	existingPhrase := phraseGroup.findPhrase(phrase)
	if existingPhrase == nil {
		// no name group displayed as 'default'
		groupName := "default"
		if group != "" {
			groupName = group
		}
		log.Fatalf("Phrase '%s' doesn't exist in group '%s' of phrase list '%s'", phrase.Phrase, groupName, listName)
		return -1
	} else {
		// Delete it here
		phraseGroup.Phrases = phraseGroup.removePhrase(phrase)
		if len(phraseGroup.Phrases) == 0 && phraseGroup.GroupName != "" {
			phraseList.Groups = phraseList.deleteGroup(phraseGroup.GroupName)
		}
		err = writeHostFilterConfig(targetName, config)
		if err != nil {
			log.Fatal("Failed to write host config: ", err)
			return -1
		}
		log.Printf("Successfully deleted phrase from list '%s'\n", listName)
		return 0
	}

}

/* Delete entry from existing list */
func DeleteEntryFromList(listName string, entry string, group string, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	contentList := config.E2guardianConf.findContentList(listName)
	if contentList == nil {
		if contentList = config.E2guardianConf.findContentList(listName); contentList == nil {
			log.Fatalf("Content list '%s' does not exist", listName)
			return -1
		}
	}

	contentGroup := contentList.findContentGroup(group)
	if contentGroup == nil {
		// Add this phrase group
		contentList.Groups = append(contentList.Groups, ContentGroup{GroupName: group})
		contentGroup = contentList.findContentGroup(group)
	}

	existingEntry := contentGroup.findEntry(entry)
	if existingEntry == "" {
		// no name group displayed as 'default'
		groupName := "default"
		if group != "" {
			groupName = group
		}
		log.Fatalf("Entry '%s' doesn't exist in group '%s' of content list '%s'", entry, groupName, listName)
		return -1
	} else {
		// Delete it here
		contentGroup.Items = contentGroup.removeEntry(entry)
		if len(contentGroup.Items) == 0 && contentGroup.GroupName != "" {
			contentList.Groups = contentList.deleteGroup(contentGroup.GroupName)
		}
		err = writeHostFilterConfig(targetName, config)
		if err != nil {
			log.Fatal("Failed to write host config: ", err)
			return -1
		}
		log.Printf("Successfully deleted phrase from list '%s'\n", listName)
		return 0
	}

}

/* Include a phrase list in one of the main lists */
func AddPhraseInclude(phraseList *PhraseList, config *FilterConfig, fileInclude string, targetName string) int {

	include := phraseList.findInclude(fileInclude)
	if include != "" {
		log.Fatalf("Phrase list '%s' is already included in '%s'\n", phraseList.ListName, include)
		return -1
	}

	phraseList.IncludeIn = append(phraseList.IncludeIn, fileInclude)

	err := writeHostFilterConfig(targetName, *config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully included phrase list '%s' in '%s'\n", phraseList.ListName, fileInclude)
	return 0

}

/* Include a content list in one of the main lists */
func AddInclude(contentList *ContentList, config *FilterConfig, fileInclude string, targetName string) int {

	include := contentList.findInclude(fileInclude)
	if include != "" {
		log.Fatalf("List '%s' is already included in '%s'\n", contentList.ListName, include)
		return -1
	}

	contentList.IncludeIn = append(contentList.IncludeIn, fileInclude)

	err := writeHostFilterConfig(targetName, *config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully included %s '%s' in '%s'\n", contentList.Type, contentList.ListName, fileInclude)
	return 0

}

/* Clear includes from phrase list */
func DeletePhraseIncludes(listName string, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: \n", err)
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList == nil {
		if phraseList = config.E2guardianConf.findWeightedPhraseList(listName); phraseList == nil {
			log.Fatalf("Phrase list '%s' does not exist", listName)
			return -1
		}
	}

	phraseList.IncludeIn = phraseList.IncludeIn[:0]

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully cleared includes for phrase list '%s'\n", listName)
	return 0

}

func BlacklistPhrase(listName string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: \n", err)
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList == nil {
		if phraseList = config.E2guardianConf.findWeightedPhraseList(listName); phraseList == nil {
			log.Fatalf("Phrase list '%s' does not exist", listName)
			return -1
		}
	}

	if phraseList.Weighted {
		return AddPhraseInclude(phraseList, &config, "weightedphraselist", targetName)
	} else {
		return AddPhraseInclude(phraseList, &config, "bannedphraselist", targetName)
	}
}

func WhitelistPhrase(listName string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: \n", err)
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList == nil {
		if phraseList = config.E2guardianConf.findWeightedPhraseList(listName); phraseList == nil {
			log.Fatalf("Phrase list '%s' does not exist", listName)
			return -1
		}
	}

	if phraseList.Weighted {
		log.Fatalf("Whitelist not supported for weighted; just apply negative weight to your terms")
		return -1
	} else {
		return AddPhraseInclude(phraseList, &config, "exceptionphraselist", targetName)
	}
}

func Blacklist(listName string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: \n", err)
		return -1
	}

	contentList := config.E2guardianConf.findContentList(listName)
	if contentList == nil {
		log.Fatalf("Content list '%s' does not exist", listName)
		return -1
	}

	return AddInclude(contentList, &config, banLists[contentList.Type], targetName)
}

func Whitelist(listName string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: \n", err)
		return -1
	}

	contentList := config.E2guardianConf.findContentList(listName)
	if contentList == nil {
		log.Fatalf("Content list '%s' does not exist", listName)
		return -1
	}

	return AddInclude(contentList, &config, allowLists[contentList.Type], targetName)
}

/* Clear includes from content list */
func DeleteIncludes(listName string, targetName string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: \n", err)
		return -1
	}

	contentList := config.E2guardianConf.findContentList(listName)
	if contentList == nil {
		log.Fatalf("Content list '%s' does not exist", listName)
		return -1
	}

	contentList.IncludeIn = contentList.IncludeIn[:0]

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully cleared includes for %s '%s'\n", contentList.Type, listName)
	return 0

}

/* Dump a given phrase list, or list all of them */
func ShowPhraseList(listName string, targetName string, group string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	if listName == "" {
		// Just show the names of all phrase lists
		log.Println("=== PHRASE LISTS ===")
		for i := range config.E2guardianConf.PhraseLists {
			log.Println(config.E2guardianConf.PhraseLists[i].ListName)
		}
		log.Println("=== WEIGHTED PHRASE LISTS ===")
		for i := range config.E2guardianConf.WeightedPhraseLists {
			log.Println(config.E2guardianConf.WeightedPhraseLists[i].ListName)
		}
		return -1
	}

	phraseList := config.E2guardianConf.findPhraseList(listName)
	if phraseList == nil {
		if phraseList = config.E2guardianConf.findWeightedPhraseList(listName); phraseList == nil {
			log.Fatalf("Phrase list '%s' does not exist", listName)
			return -1
		}
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

	// Dump includes
	log.Printf("=== INCLUDES ===")
	for _, inc := range phraseList.IncludeIn {
		log.Println(inc)
	}

	for i := range groups {
		group := groups[i]
		log.Printf("Group: %s", group.GroupName)

		// Dump includes

		log.Printf("=== PHRASES ===")
		for j := range group.Phrases {
			phrase := group.Phrases[j]
			phraseString := ""
			for k := range phrase.Phrase {
				term := phrase.Phrase[k]
				phraseString = fmt.Sprintf("%s<%s>", phraseString, term)
			}
			if phraseList.Weighted {
				phraseString = fmt.Sprintf("%s (weight=%d)", phraseString, phrase.Weight)
			}
			log.Println(phraseString)
		}
	}

	return 0
}

func AddContentList(listName string, listType string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	contentList := config.E2guardianConf.findContentList((listName))
	if contentList != nil {
		log.Fatalf("Content list '%s' already exists with type %s", listName, contentList.Type)
		return -1
	}

	config.E2guardianConf.Lists = append(config.E2guardianConf.Lists, ContentList{ListName: listName, Type: listType})

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully added %s '%s'\n", listType, listName)
	return 0
}

func DeleteContentList(listName string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	contentList := config.E2guardianConf.findContentList((listName))
	if contentList == nil {
		log.Fatalf("Content list '%s' does not exist", listName)
		return -1
	}

	config.E2guardianConf.deleteContentList(listName)

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully deleted %s '%s'\n", contentList.Type, listName)
	return 0
}

func AddEntryToContentList(listName string, group string, entry string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	contentList := config.E2guardianConf.findContentList((listName))
	if contentList == nil {
		log.Fatalf("Content list '%s' doesn't exist", listName)
		return -1
	}

	contentGroup := contentList.findContentGroup(group)
	if contentGroup == nil {
		// Add this phrase group
		contentList.Groups = append(contentList.Groups, ContentGroup{GroupName: group})
		contentGroup = contentList.findContentGroup(group)
	}

	existingEntry := contentGroup.findEntry(entry)
	if existingEntry != "" {
		// no name group displayed as 'default'
		groupName := "default"
		if group != "" {
			groupName = group
		}
		log.Fatalf("Entry '%s' already exists in group '%s' of %s '%s'", entry, groupName, contentList.Type, listName)
		return -1
	}

	contentGroup.Items = append(contentGroup.Items, entry)

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully added phrase to list '%s'\n", listName)
	return 0

}

/* Dump a given content list, or list all of them */
func ShowContentList(listName string, targetName string, group string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	if listName == "" {
		// Just show the names of all phrase lists
		log.Println("=== CONTENT LISTS ===")
		for i := range config.E2guardianConf.Lists {
			log.Printf("%s (type='%s')\n", config.E2guardianConf.Lists[i].ListName, config.E2guardianConf.Lists[i].Type)
		}
		return -1
	}

	contentList := config.E2guardianConf.findContentList(listName)
	if contentList == nil {
		log.Fatalf("Content list '%s' does not exist", listName)
		return -1
	}

	var groups []ContentGroup

	if group != "" {
		contentGroup := contentList.findContentGroup(group)
		if contentGroup == nil {
			log.Fatalf("Group '%s' does not exist for content list '%s'", group, listName)
			return -1
		}
		groups = []ContentGroup{*contentGroup}
	} else {
		groups = contentList.Groups
	}

	// Dump includes
	log.Printf("=== INCLUDES ===")
	for _, inc := range contentList.IncludeIn {
		log.Println(inc)
	}

	for i := range groups {
		group := groups[i]
		log.Printf("Group: %s", group.GroupName)

		// Dump includes

		log.Printf("=== ENTRIES ===")
		for j := range group.Items {
			item := group.Items[j]
			log.Println(item)
		}
	}

	return 0
}

func validAction(action string) bool {
	for _, a := range AclActions {
		if a == action {
			return true
		}
	}
	return false
}

func AddAclRule(category string, action string, targetName string, pos int) int {

	if !validAction(action) {
		log.Fatalf("Invalid action '%s', valid options are %s\n", action, strings.Join(AclActions, ", "))
		return -1
	}

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	if config.AclRuleExists(category, action) {
		log.Fatalf("Acl rule '%s=%s' already exists\n", category, action)
		return -1
	}

	config.AddAclRule(category, action, pos)

	// Set DecryptHTTPS if applicable
	config.DecryptHTTPS = config.shouldDecrypt()

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully added acl rule '%s=%s'\n", category, action)

	return 0
}

func DeleteAclRule(category string, action string, targetName string) int {

	if !validAction(action) {
		log.Fatalf("Invalid action '%s', valid options are %s\n", action, strings.Join(AclActions, ", "))
		return -1
	}

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	if !config.AclRuleExists(category, action) {
		log.Fatalf("Acl rule '%s=%s' doesn't exist\n", category, action)
		return -1
	}

	if action == "allow" || action == "deny" {
		config.AllowRules = config.DeleteAllowRule(category, action)
	} else {
		config.DecryptRules = config.DeleteDecryptRule(category, action)
	}

	// Set DecryptHTTPS if applicable
	config.DecryptHTTPS = config.shouldDecrypt()

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	log.Printf("Successfully deleted acl rule '%s=%s'\n", category, action)

	return 0
}

func ShowAclRules(targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	log.Printf("=== DECRYPT RULES ===")
	for i, rule := range config.DecryptRules {
		action := "decrypt"
		if !rule.Decrypt {
			action = "nodecrypt"
		}
		log.Printf("%d | Category: '%s', Action: '%s'\n", i, rule.Category, action)
	}

	log.Printf("=== ALLOW RULES ===")
	for i, rule := range config.AllowRules {
		action := "allow"
		if !rule.Allow {
			action = "deny"
		}
		log.Printf("%d | Category: '%s', Action: '%s'", i, rule.Category, action)
	}

	return 0
}

func SafeSearch(enforced string, targetName string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	switch enforced {
	case "show":
		current := config.SafeSearchEnforced
		if current {
			fmt.Println("Safesearch is enforced")
		} else {
			fmt.Println("Safesearch is not enforced")
		}
		return 0
	case "on":
		config.SafeSearchEnforced = true
		fmt.Println("SafeSearch has been enabled")
	case "off":
		config.SafeSearchEnforced = false
		fmt.Println("SafeSearch has been disabled")
	default:
		log.Fatalf("Unknown directive: '%s'", enforced)
		return -1
	}

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	return 0
}

func SetReleaseTag(targetName string, releaseTag string) int {
	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	config.ReleaseTag = releaseTag

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	fmt.Printf("Set release tag to %s\n", releaseTag)
	return 0
}

func SetupCertificate(targetName string, cn string, org string, country string, state string, locality string) int {

	config, err := getHostFilterConfig(targetName)
	if err != nil {
		log.Fatal("Failed to get host config: ", err)
		return -1
	}

	config.CommonName = cn
	config.Organization = org
	config.Country = country
	config.State = state
	config.Locality = locality

	err = writeHostFilterConfig(targetName, config)
	if err != nil {
		log.Fatal("Failed to write host config: ", err)
		return -1
	}

	fmt.Println("Decryption cert set up successfully.")

	return 0

}

func GetRootCa(targetName string) (string, error) {
	config, err := loadConfig()
	if err != nil {
		return "", err
	}

	_, host := FindHost(config, targetName)
	if host.Name != targetName {
		log.Fatalf("host '%s' not configured", targetName)
		return "", err
	}

	client, err := getHostSshClient(host)
	if err != nil {
		log.Fatal("Failed to create SSH connection: ", err)
		return "", err
	}
	err = client.NewCryptoContext()
	if err != nil {
		log.Fatal("Failed to create SSH connection: ", err)
		return "", err
	}

	certOutput, err := client.RunCommands([]string{
		"kubectl -n filter get secret guardian-ca-tls -o jsonpath='{.data.ca\\.crt}' | base64 -d",
	}, false)
	if err != nil {
		log.Fatal("Failed to run command: ", err)
		return "", err
	}

	return certOutput, nil
}

func CopyRootCa(targetName string, outputPath string) int {
	caPath := getCaPathDir(targetName)
	data, err := ioutil.ReadFile(caPath)
	if err != nil {
		log.Fatal("Failed to open root CA, have you already deployed?")
		return -1
	}
	f, err := os.Create(outputPath)
	if err != nil {
		log.Fatal("Failed to open output path for ca cert: ", err)
		return -1
	}
	defer f.Close()
	_, err = f.WriteString(string(data))
	if err != nil {
		log.Fatal("Failed to write ca certificate to disk: ", err)
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

	caCertOutputPath := getCaPathDir(name)
	caCertData, err := GetRootCa(name)
	if err != nil {
		log.Fatalf("Failed to fetch the root CA: %s\n", err)
		return -1
	}

	// Create caCert file
	f, err := os.Create(caCertOutputPath)
	if err != nil {
		log.Fatal("Failed to create host filter config file: ", err)
		return -1
	}
	defer f.Close()
	_, err = f.WriteString(string(caCertData))
	if err != nil {
		log.Fatal("Failed to write ca certificate to disk: ", err)
	}

	fmt.Println("Deployment successful.")
	return 0
}
