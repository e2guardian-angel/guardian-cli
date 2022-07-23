package utils

import (
	"bufio"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"path"
	"strings"

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

func knownHostContains(line string) (error, bool) {
	knownHostsFile, err := ioutil.ReadFile(getKnownHostsFile())
	if err != nil {
		log.Fatal("Failed to read known_hosts file: ", err)
		return err, false
	}
	contents := string(knownHostsFile)
	// //check whether s contains substring text
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

	err, exists := knownHostContains(line)
	if err != nil {
		return err
	}
	if !exists {
		err = appendToKnownHosts(line)
	}
	return err
}

func copySshKeys(host Host, noPassword bool) error {
	err := InitSsh(4096)
	if err != nil {
		return err
	}

	var sshConfig ssh.ClientConfig
	if noPassword {
		// TODO: support key auth
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
			HostKeyCallback: PromptAtKey,
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

/*
 * SSH session code
 * copied from: https://gist.github.com/stefanprodan/2d20d0c6fdab6f14ce8219464e8b4b9a
 */

type SshClient struct {
	Config *ssh.ClientConfig
	Server string
}

func NewSshClient(user string, host string, port int, privateKeyPath string, privateKeyPassword string) (*SshClient, error) {

	// read private key file
	pemBytes, err := ioutil.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("Reading private key file failed %v", err)
	}

	// create signer
	signer, err := signerFromPem(pemBytes, []byte(privateKeyPassword))
	if err != nil {
		return nil, err
	}

	hostKeyCallback, err := knownhosts.New(getKnownHostsFile())
	if err != nil {
		return nil, err
	}

	// build SSH client config
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: hostKeyCallback,
	}

	client := &SshClient{
		Config: config,
		Server: fmt.Sprintf("%v:%v", host, port),
	}

	return client, nil
}

// Opens a new SSH connection and runs the specified command
// Returns the combined output of stdout and stderr
func (s *SshClient) RunCommand(cmd string, sudoPass string) error {

	// open connection
	conn, err := ssh.Dial("tcp", s.Server, s.Config)
	if err != nil {
		return fmt.Errorf("Dial to %v failed %v", s.Server, err)
	}
	defer conn.Close()

	// open session
	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	if sudoPass != "" {

		modes := ssh.TerminalModes{
			ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
			ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
		}

		err = session.RequestPty("xterm", 80, 40, modes)
		if err != nil {
			return err
		}

		in, err := session.StdinPipe()
		if err != nil {
			log.Fatal(err)
		}

		out, err := session.StdoutPipe()
		if err != nil {
			log.Fatal(err)
		}

		var output []byte
		go func(in io.WriteCloser, out io.Reader, output *[]byte) {
			var (
				line string
				r    = bufio.NewReader(out)
			)
			for {
				b, err := r.ReadByte()
				if err != nil {
					break
				}

				*output = append(*output, b)

				if b == byte('\n') {
					log.Println(line)
					line = ""
					continue
				}

				line += string(b)

				if strings.HasPrefix(line, "[sudo] password for ") && strings.HasSuffix(line, ": ") {
					_, err = in.Write([]byte(sudoPass + "\n"))
					if err != nil {
						break
					}
				}
			}
		}(in, out, &output)
	} else {
		session.Stdout = os.Stdout
	}

	return session.Run(cmd)

}

func (s *SshClient) CopyFiles(host Host, srcPath string, dstPath string) error {

	return nil
}

func signerFromPem(pemBytes []byte, password []byte) (ssh.Signer, error) {

	// read pem block
	err := errors.New("Pem decode failed, no key found")
	pemBlock, _ := pem.Decode(pemBytes)
	if pemBlock == nil {
		return nil, err
	}

	// handle encrypted key
	if x509.IsEncryptedPEMBlock(pemBlock) {
		// decrypt PEM
		pemBlock.Bytes, err = x509.DecryptPEMBlock(pemBlock, []byte(password))
		if err != nil {
			return nil, fmt.Errorf("Decrypting PEM block failed %v", err)
		}

		// get RSA, EC or DSA key
		key, err := parsePemBlock(pemBlock)
		if err != nil {
			return nil, err
		}

		// generate signer instance from key
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			return nil, fmt.Errorf("Creating signer from encrypted key failed %v", err)
		}

		return signer, nil
	} else {
		// generate signer instance from plain key
		signer, err := ssh.ParsePrivateKey(pemBytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing plain private key failed %v", err)
		}

		return signer, nil
	}
}

func parsePemBlock(block *pem.Block) (interface{}, error) {
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing PKCS private key failed %v", err)
		} else {
			return key, nil
		}
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing EC private key failed %v", err)
		} else {
			return key, nil
		}
	case "DSA PRIVATE KEY":
		key, err := ssh.ParseDSAPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("Parsing DSA private key failed %v", err)
		} else {
			return key, nil
		}
	default:
		return nil, fmt.Errorf("Parsing private key failed, unsupported key type %q", block.Type)
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

	sshc, err := NewSshClient(host.Username, host.Address, int(host.Port), getPrivateKeyFilename(), "")
	if err != nil {
		log.Fatal("Failed to create SSH client: ", err)
		return -1
	}

	err = sshc.RunCommand("ls -lh /", "")
	if err != nil {
		log.Fatal("Failed to run command: ", err)
		return -1
	}

	return 0

}
