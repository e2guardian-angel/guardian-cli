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
			Name       string `arg:"" name:"name" help:"Name to refer to target host" required:"true"`
			Host       string `arg:"" name:"host" help:"Target host address for install" type:"ip/hostname" required:"true"`
			Username   string `arg:"" name:"username" help:"Username for SSH login" required:"true"`
			Port       uint16 `name:"port" help:"SSH port" default:"22"`
			NoPassword bool   `name:"no-password" help:"Don't use password auth for SSH key exchange" default:"false"`
			HomePath   string `name:"home-path" help:"Custom home path on remote target installation"`
		} `cmd:"" help:"Add a target host for installation" required:"true"`
		Update struct {
			Name       string `arg:"" name:"name" help:"Name of target host to update" required:"true"`
			Host       string `arg:"" name:"host" help:"Target host address for install" type:"ip/hostname" required:"true"`
			Username   string `arg:"" name:"username" help:"Username for SSH login" required:"true"`
			Port       uint16 `name:"port" help:"SSH port" default:"22"`
			NoPassword bool   `name:"no-password" help:"Don't use password auth for SSH key exchange" default:"false"`
			HomePath   string `help:"Custom home path on remote target installation"`
		} `cmd:"" help:"Updates a target host for installation"`
		Delete struct {
			Name string `arg:"" name:"name" help:"Name of target host to delete"`
		} `cmd:"" help:"Deletes a target host"`
		Setup struct {
			Name string `arg:"" name:"name" help:"Target to select for setup"`
		} `cmd:"" help:"Setup dependencies on host"`
		List struct {
		} `cmd:"" help:"List configured target hosts"`
		Reset struct {
		} `cmd:"" help:"Reset SSH and clear all hosts"`
		Test struct {
			Name string `arg:"" name:"name" help:"Name of target host to update"`
		} `cmd:"" help:"Run test ssh command"`
	} `cmd:"" help:"Operations on target hosts"`
}

func main() {
	var code int = 0
	ctx := kong.Parse(&CLI)
	switch ctx.Command() {
	case "target add <name> <host> <username>":
		code = utils.AddHost(CLI.Target.Add.Name, CLI.Target.Add.Host, CLI.Target.Add.Port, CLI.Target.Add.Username, CLI.Target.Add.NoPassword, CLI.Target.Add.HomePath)
	case "target update <name> <host> <username>":
		host := utils.Host{
			Name:     CLI.Target.Update.Name,
			Address:  CLI.Target.Update.Host,
			Username: CLI.Target.Update.Username,
			Port:     CLI.Target.Update.Port,
			HomePath: CLI.Target.Update.HomePath}
		code = utils.UpdateHost(CLI.Target.Update.Name, host, CLI.Target.Update.NoPassword)
	case "target setup <name>":
		code = utils.Setup(CLI.Target.Setup.Name)
	case "target delete <name>":
		code = utils.DeleteHost(CLI.Target.Delete.Name)
	case "target list":
		code = utils.ListHosts()
	case "target reset":
		code = utils.ResetSsh()
	case "target test <name>":
		code = utils.TestSshCommand(CLI.Target.Test.Name)
	default:
		log.Fatal("Unknown command. Use '--help' to get a list of valid commands.")
		code = -1
	}

	os.Exit(code)
}
