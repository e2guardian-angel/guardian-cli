package main

import (
	"log"
	"os"

	"github.com/alecthomas/kong"
	"github.com/e2guardian-angel/guardian-cli/utils"
)

var CLI struct {
	Target struct {
		Add struct {
			Name       string `arg name:"name" help:"Name to refer to target host"`
			Host       string `arg name:"host" help:"Target host address for install" type:"ip/hostname"`
			Username   string `arg name:"username" help:"Username for SSH login"`
			Port       uint16 `default:22 help:"SSH port"`
			NoPassword bool   `default:false help:"Don't use password auth for SSH key exchange"`
			HomePath   string `help:"Custom home path on remote target installation"`
		} `cmd help:"Add a target host for installation"`
		Update struct {
			Name       string `arg name:"name" help:"Name of target host to update"`
			Host       string `arg name:"host" help:"Target host address for install" type:"ip/hostname"`
			Username   string `arg name:"username" help:"Username for SSH login"`
			Port       uint16 `default:22 help:"SSH port"`
			NoPassword bool   `default:false help:"Don't use password auth for SSH key exchange"`
			HomePath   string `help:"Custom home path on remote target installation"`
		} `cmd help:"Updates a target host for installation"`
		Delete struct {
			Name string `arg name:"name" help:"Name of target host to delete"`
		} `cmd help:"Deletes a target host"`
		Setup struct {
			Name string `arg name:"name" help:"Target to select for setup"`
		} `cmd help:"Setup dependencies on host"`
		List struct {
		} `cmd help:"List configured target hosts"`
		Reset struct {
		} `cmd help:"Reset SSH and clear all hosts"`
	} `cmd help:"Operations on target hosts"`
}

func main() {
	var code int = 0
	ctx := kong.Parse(&CLI)
	switch ctx.Command() {
	case "target add <name> <host> <username>":
		code = utils.AddHost(CLI.Target.Add.Name, CLI.Target.Add.Host, CLI.Target.Add.Port, CLI.Target.Add.Username, CLI.Target.Add.NoPassword, CLI.Target.Add.HomePath)
		break
	case "target update <name> <host>":
		host := utils.Host{CLI.Target.Update.Name, CLI.Target.Update.Host, CLI.Target.Update.Username, CLI.Target.Update.Port, CLI.Target.Update.HomePath}
		code = utils.UpdateHost(CLI.Target.Update.Name, host, CLI.Target.Update.NoPassword)
	case "target setup <name>":
		code = utils.Setup(CLI.Target.Setup.Name)
		break
	case "target delete <name>":
		code = utils.DeleteHost(CLI.Target.Delete.Name)
		break
	case "target list":
		code = utils.ListHosts()
		break
	case "target reset":
		code = utils.ResetSsh()
		break
	default:
		log.Fatal("Unknown command. Use '--help' to get a list of valid commands.")
		code = -1
		break
	}

	os.Exit(code)
}
