package main

import (
	"log"
	"os"

	"github.com/alecthomas/kong"
	"github.com/e2guardian-angel/guardian-cli/utils"
)

var CLI struct {
	Add struct {
		Name       string `arg name:"name" help:"Name to refer to target host"`
		Host       string `arg name:"host" help:"Target host address for install" type:"ip/hostname"`
		Username   string `arg name:"username" help:"Username for SSH login"`
		Port       uint16 `default:22 help:"SSH port"`
		NoPassword bool   `default:false help:"Don't use password auth for SSH key exchange"`
	} `cmd help:"Add a target host for installation"`
	Update struct {
		Name       string `arg name:"name" help:"Name of target host to update"`
		Host       string `arg name:"host" help:"Target host address for install" type:"ip/hostname"`
		Username   string `arg name:"username" help:"Username for SSH login"`
		Port       uint16 `default:22 help:"SSH port"`
		NoPassword bool   `default:false help:"Don't use password auth for SSH key exchange"`
	} `cmd help:"Updates a target host for installation"`
	Delete struct {
		Name string `arg name:"name" help:"Name of target host to delete"`
	} `cmd help:"Deletes a target host"`
	Setup struct {
		Name string `arg name:"name" help:"Target to select for setup"`
	} `cmd help:"Setup dependencies on host"`
	List struct {
	} `cmd help:"List configured target hosts"`
}

func main() {
	var code int = 0
	ctx := kong.Parse(&CLI)
	switch ctx.Command() {
	case "add <name> <host> <username>":
		code = utils.AddHost(CLI.Add.Name, CLI.Add.Host, CLI.Add.Port, CLI.Add.Username, CLI.Add.NoPassword)
		break
	case "update <name> <host>":
		host := utils.Host{CLI.Update.Name, CLI.Update.Host, CLI.Update.Username, CLI.Update.Port}
		code = utils.UpdateHost(CLI.Update.Name, host, CLI.Update.NoPassword)
	case "setup <name>":
		code = utils.Setup(CLI.Setup.Name)
		break
	case "delete <name>":
		code = utils.DeleteHost(CLI.Delete.Name)
		break
	case "list":
		code = utils.ListHosts()
		break
	default:
		log.Fatal("Unknown command. Use '--help' to get a list of valid commands.")
		code = -1
		break
	}

	os.Exit(code)
}
