package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"

	"golang.org/x/crypto/ssh"
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
func InitSsh(bitSize int) error {

	err := initLocal()
	if err != nil {
		return err
	}

	sshKeysDir := getSshKeysDir()
	_, err = os.Stat(sshKeysDir)
	if os.IsNotExist(err) {
		os.MkdirAll(sshKeysDir, 0o755)
	}

	publicKeyFile := getPublicKeyFilename()
	privateKeyFile := getPrivateKeyFilename()

	_, privateKeyError := os.Stat(privateKeyFile)
	_, publicKeyError := os.Stat(publicKeyFile)
	if os.IsNotExist(privateKeyError) || os.IsNotExist(publicKeyError) {

		log.Println("SSH Keypair not present, generating new ones")

		// Generate a new private key
		privateKey, err := generatePrivateKey(bitSize)
		if err != nil {
			log.Fatal("Failed generating private key: ", err)
			return err
		}

		// generate a new public key
		publicKeyBytes, err := generatePublicKey(&privateKey.PublicKey)
		if err != nil {
			log.Fatal("Failed generating public key: ", err)
			return err
		}

		privateKeyBytes := encodePrivateKeyToPEM(privateKey)

		err = writeKeyToFile(privateKeyBytes, privateKeyFile)
		if err != nil {
			log.Fatal("Failed writing private key to file: ", err)
			return err
		}

		err = writeKeyToFile([]byte(publicKeyBytes), publicKeyFile)
		if err != nil {
			log.Fatal("Failed writing public key to file: ", err)
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

func copySshKeys(host Host, noPassword bool) error {
	err := InitSsh(4096)
	if err != nil {
		return err
	}

	/*hostKeyCallback, err := knownhosts.New(getKnownHostsFile())
	if err != nil {
		log.Fatal(err)
		return err
	}*/

	var sshConfig ssh.ClientConfig
	if noPassword {
		// Use key auth
	} else {
		// Use password auth
		password, err := getUserCredentials()
		if err != nil {
			log.Fatal(err)
			return err
		}
		sshConfig = ssh.ClientConfig{
			User: host.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
	}

	// connect ot ssh server
	connStr := fmt.Sprintf("%s:%d", host.Address, host.Port)
	conn, err := ssh.Dial("tcp", connStr, &sshConfig)

	if err != nil {
		log.Fatal("Failed connecting to target host: ", err)
		return err
	}
	defer conn.Close()

	// Start SSH session
	session, err := conn.NewSession()
	if err != nil {
		log.Fatal(err)
		return err
	}
	defer session.Close()

	// configure terminal mode
	modes := ssh.TerminalModes{
		ssh.ECHO: 0, // supress echo
	}
	// run terminal session
	if err := session.RequestPty("xterm", 50, 80, modes); err != nil {
		log.Fatal(err)
		return err
	}

	// Dump public key to ssh config
	err, keyData := getPublicKeyData()
	if err != nil {
		log.Fatal("Failed to read key data: ", err)
		return err
	}

	copyCommand := fmt.Sprintf("if [ -z \"$(cat $HOME/.ssh/authorized_keys | grep '%s')\" ]; then echo '%s' >> $HOME/.ssh/authorized_keys; fi", keyData, keyData)
	if err := session.Run(copyCommand); err != nil {
		log.Fatal("Failed to copy key: ", err)
		return err
	}

	return nil
}

/*
 * Helper functions
 */

func generatePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func generatePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}

func encodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

func writeKeyToFile(keyBytes []byte, saveFileTo string) error {
	err := ioutil.WriteFile(saveFileTo, keyBytes, 0600)
	if err != nil {
		return err
	}

	return nil
}
