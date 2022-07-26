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
		} `cmd:"" name:"add" help:"Add a target host for installation" required:"true"`
		Update struct {
			Name       string `arg:"" name:"name" help:"Name of target host to update" required:"true"`
			Host       string `arg:"" name:"host" help:"Target host address for install" type:"ip/hostname" required:"true"`
			Username   string `arg:"" name:"username" help:"Username for SSH login" required:"true"`
			Port       uint16 `name:"port" help:"SSH port" default:"22"`
			NoPassword bool   `name:"no-password" help:"Don't use password auth for SSH key exchange" default:"false"`
			HomePath   string `name:"home-path" help:"Custom home path on remote target installation"`
		} `cmd:"" name:"update" help:"Updates a target host for installation"`
		Delete struct {
			Name string `arg:"" name:"name" help:"Name of target host to delete"`
		} `cmd:"" name:"delete" help:"Deletes a target host"`
		Setup struct {
			Name string `arg:"" name:"name" help:"Target to select for setup"`
		} `cmd:"" name:"setup" help:"Setup dependencies on host"`
		List struct {
		} `cmd:"" name:"list" help:"List configured target hosts"`
		Reset struct {
		} `cmd:"" name:"reset" help:"Reset SSH and clear all hosts"`
		Test struct {
			Name string `arg:"" name:"name" help:"Name of target host to test"`
		} `cmd:"" name:"test" help:"Run test ssh command"`
	} `cmd:"" name:"target" help:"Operations on target hosts"`
	Filter struct {
		Target string `name:"target" help:"Name of target host for changes" required:"true"`
		Deploy struct {
			RestoreBackup string `name:"restore-backup" help:"Restore configuration from a backup file" type:"filename"`
		} `cmd:"" name:"deploy" help:"Deploy filter stack to target host"`
		Backup struct {
			ToFile string `name:"to-file" help:"Restore configuration from a backup file" type:"filename" required:"true"`
		} `cmd:"" name:"deploy" help:"Backup target host's filter configuration"`
		Uninstall struct {
		} `cmd:"" name:"deploy" help:"Uninstall filter stack on target host"`
		SafeSearch struct {
			Force bool `arg:"" name:"force" help:"Safesearch is enforced" default:"false"`
		} `cmd:"" name:"safe-search" help:"Safe search option"`
		PhraseList struct {
			AddPhrase struct {
				Name   string `arg:"" name:"name" help:"Name of the phrase list to modify" required:"true"`
				Phrase string `arg:"" name:"phrase" help:"Phrase to add to the list" type:"comma separated list" required:"true"`
				Weight int    `name:"weight" help:"For weighted list, numeric weight associated with the phrase"`
			} `cmd:"" name:"add-phrase" help:"Add a phrase to an existing list"`
			RemovePhrase struct {
				Name   string `arg:"" name:"name" help:"Name of the phrase list to modify"`
				Phrase string `arg:"" name:"phrase" help:"Name of phrase to remove from an existing list" type:"comma separated list"`
			} `cmd:"" name:"remove-phrase" help:"Remove a phrase from an existing list"`
			AddList struct {
				Name        string `arg:"" name:"name" help:"Name of the phrase list to create"`
				Weighted    bool   `name:"weighted" help:"Indicates that phrase list is weiighted" type:"true/false" default:"false"`
				Naughtiness int    `name:"naughtiness" help:"For weighted lists, the naughtiness limit" type:"integer"`
			} `cmd:"" name:"add-list" help:"Create a new phrase list"`
			RemoveList struct {
				Name string `arg:"" name:"name" help:"Name of the phrase list to delete"`
			} `cmd:"" name:"remove-list" help:"Delete an existing phrase list"`
		} `cmd:"" name:"phrase-list" help:"Backup target host's filter configuration"`
	} `cmd:"" help:"Deployment and configuration of the web filter"`
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
