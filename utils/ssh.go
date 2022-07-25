package utils

import (
	"crypto/md5"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"

	"github.com/justinschw/gofigure/crypto"
	"github.com/manifoldco/promptui"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

/*
 * Key generation code copied from:
 * https://gist.github.com/devinodaniel/8f9b8a4f31573f428f29ec0e884e6673
 */

/*
 * get the directory of the SSH keypair
 */
func getSshKeysDir() string {
	guardianHome := GuardianConfigHome()
	sshKeysDir := path.Join(guardianHome, "ssh-keys")
	return sshKeysDir
}

/*
 * Get the path to the private key file
 */
func getPrivateKeyFilename() string {
	return path.Join(getSshKeysDir(), "id_rsa")
}

/*
 * Get the path to the public key file
 */
func getPublicKeyFilename() string {
	return path.Join(getSshKeysDir(), "id_rsa.pub")
}

/*
 * Get known_hosts file
 */
func getKnownHostsFile() string {
	return path.Join(getSshKeysDir(), "known_hosts")
}

/*
 * Get public key
 */
func getPublicKeyData() (error, string) {
	keyFile := getPublicKeyFilename()
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return err, ""
	}
	return nil, strings.TrimSpace(string(data))
}

/*
 * Initialize the ssh key directory, and keys if necessary
 */
func initSsh(bitSize int) error {

	err := initLocal()
	if err != nil {
		return err
	}

	sshKeysDir := getSshKeysDir()
	_, err = os.Stat(sshKeysDir)
	if os.IsNotExist(err) {
		os.MkdirAll(sshKeysDir, 0o755)
	}

	keyPair := crypto.SshKeyPair{
		PrivateKeyFile: getPrivateKeyFilename(),
		PublicKeyFile:  getPublicKeyFilename(),
		BitSize:        4096,
	}
	err = keyPair.CreateKeyPair("")
	if err != nil {
		log.Fatal("Failed to get SSH keys: %s", err)
	}

	_, privateKeyError := os.Stat(keyPair.PrivateKeyFile)
	_, publicKeyError := os.Stat(keyPair.PublicKeyFile)
	if os.IsNotExist(privateKeyError) || os.IsNotExist(publicKeyError) {

		log.Println("SSH Keypair not present, generating new ones")
		err := keyPair.GenerateNewKeyPair(keyPair.PrivateKeyPassword)
		if err != nil {
			log.Fatal("Failed generating private key: ", err)
			return err
		}
	}

	knownHostsFile := getKnownHostsFile()
	_, knownHostsError := os.Stat(knownHostsFile)
	if os.IsNotExist(knownHostsError) {
		// Create config file
		f, err := os.Create(knownHostsFile)
		if err != nil {
			log.Fatal("Failed to create config file: ", err)
			return err
		}
		// Output empty file
		f.WriteString("")
	}

	return nil
}

func knownHostContains(line string) (error, bool) {
	knownHostsFile, err := ioutil.ReadFile(getKnownHostsFile())
	if err != nil {
		log.Fatal("Failed to read known_hosts file: ", err)
		return err, false
	}
	contents := string(knownHostsFile)
	// check whether s contains substring text
	return nil, strings.Contains(contents, line)
}

func appendToKnownHosts(line string) error {
	knownHostsFile := getKnownHostsFile()
	f, err := os.OpenFile(knownHostsFile, os.O_APPEND|os.O_WRONLY, 0666)
	if err != nil {
		log.Fatal("Failed to open known_hosts file: ", err)
		return err
	}
	defer f.Close()
	_, err = f.WriteString(line)
	if err != nil {
		log.Fatal("Failed to append to known_hosts file: ", err)
		return err
	}
	return nil
}

// hexadecimal md5 hash grouped by 2 characters separated by colons
// Copy/pasted from: https://github.com/golang/go/issues/12292#issuecomment-255588529
func FingerprintMD5(key ssh.PublicKey) string {
	hash := md5.Sum(key.Marshal())
	out := ""
	for i := 0; i < 16; i++ {
		if i > 0 {
			out += ":"
		}
		out += fmt.Sprintf("%02x", hash[i]) // don't forget the leading zeroes
	}
	return out
}

// Host key callback to accept first key
func PromptAtKey(hostname string, remote net.Addr, key ssh.PublicKey) error {
	line := knownhosts.Line([]string{hostname}, key)

	fingerprint := FingerprintMD5(key)

	fmt.Printf("Remote target '%s' sent public key with fingerprint: %s\n", hostname, fingerprint)

	// For automation, allow auto acceptance of new public key
	autoAccept := os.Getenv("AUTOACCEPT_PUBKEY")
	if autoAccept == "" {
		// prompt for user input
		prompt := promptui.Select{
			Label: "Do you wish to accept this key and continue? (yes/no)",
			Items: []string{"yes", "no"},
		}
		_, result, err := prompt.Run()
		if err != nil {
			return err
		} else if result == "no" {
			return errors.New("User rejected public key.")
		}
	}

	err, exists := knownHostContains(line)
	if err != nil {
		return err
	}
	if !exists {
		err = appendToKnownHosts(line)
	}
	return err
}

/*
 * Reset SSH and delete all hosts
 */
func ResetSsh() int {
	fmt.Println("!!! WARNING !!! This will reset your SSH keys and delete all of your target hosts.")
	prompt := promptui.Select{
		Label: "Are you sure you want to proceed? (yes/no)",
		Items: []string{"yes", "no"},
	}

	_, result, err := prompt.Run()
	if err != nil {

		log.Fatal("Error receiving prompt: ", err)
		return -1

	} else if result == "no" {

		return 0

	} else {

		err := os.RemoveAll(getSshKeysDir())
		if err != nil {
			return -1
		}

		err, config := loadConfig()
		if err != nil {
			return -1
		}

		// delete hosts
		config.Hosts = nil
		err = writeConfig(config)
		if err != nil {
			return -1
		}

		return 0
	}
}

func TestSshCommand(name string) int {

	err, config := loadConfig()
	if err != nil {
		return -1
	}

	_, host := FindHost(config, name)
	if host.Name != name {
		log.Fatal(fmt.Sprintf("Host '%d' not configured", name))
		return -1
	}

	client := crypto.SshClient{
		Address:        host.Address,
		Port:           host.Port,
		Username:       host.Username,
		KnownHostsFile: getKnownHostsFile(),
	}

	client.SetPrivateKeyAuth(getPrivateKeyFilename(), "")
	err = client.NewCryptoContext()
	if err != nil {
		log.Fatal("Failed to create SSH context: ", err)
	}

	err, _ = client.RunCommands([]string{
		"ls -lh /",
	}, true)
	if err != nil {
		log.Fatal("Failed to run command: ", err)
		return -1
	}

	return 0

}
