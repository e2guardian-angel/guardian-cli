package main

import (
	"log"
	"os"
	"strings"

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
		Select struct {
			Name string `arg:"" name:"name" help:"Name of target host to select"`
		} `cmd:"" name:"select" help:"Select target for operations"`
	} `cmd:"" name:"target" help:"Operations on target hosts"`
	Filter struct {
		Target string `name:"target" help:"Name of target host for changes"`
		Deploy struct {
		} `cmd:"" name:"deploy" help:"Deploy filter stack to target host"`
		Backup struct {
			ToFile string `name:"to-file" help:"path to backup file" type:"filename" required:"true"`
		} `cmd:"" name:"deploy" help:"Backup target host's filter configuration"`
		Restore struct {
			FromFile string `name:"from-file" help:"Restore configuration from a backup file" type:"filename" required:"true"`
		} `cmd:"" name:"deploy" help:"Restore target host's filter configuration from a backup file"`
		Uninstall struct {
		} `cmd:"" name:"deploy" help:"Uninstall filter stack on target host"`
		SafeSearch struct {
			Command string `arg:"" name:"command" help:"Safesearch is enforced (on/off/show)"`
		} `cmd:"" name:"safe-search" help:"Safe search option"`
		PhraseList struct {
			AddPhrase struct {
				Name   string `arg:"" name:"name" help:"Name of the phrase list to modify" required:"true"`
				Phrase string `arg:"" name:"phrase" help:"Phrase to add to the list" type:"comma separated list" required:"true"`
				Group  string `name:"group" help:"name of phrase group"`
				Weight int    `name:"weight" help:"For weighted list, numeric weight associated with the phrase"`
			} `cmd:"" name:"add-phrase" help:"Add a phrase to an existing list"`
			AddInclude struct {
				Name     string `arg:"" name:"name" help:"Name of the phrase list to modify" required:"true"`
				Filename string `arg:"" name:"filename" help:"Name of the phrase list file to include" required:"true"`
				Group    string `name:"group" help:"name of phrase group"`
			} `cmd:"" name:"add-include" help:"Include phraselist file to an existing list"`
			RemovePhrase struct {
				Name   string `arg:"" name:"name" help:"Name of the phrase list to modify"`
				Phrase string `arg:"" name:"phrase" help:"Name of phrase list file include to delete" type:"comma separated list"`
				Group  string `name:"group" help:"name of phrase group"`
			} `cmd:"" name:"remove-phrase" help:"Remove an include from an existing list"`
			DeleteInclude struct {
				Name     string `arg:"" name:"name" help:"Name of the phrase list" required:"true"`
				Filename string `arg:"" name:"filename" help:"Name of the phrase list to modify" required:"true"`
				Group    string `name:"group" help:"name of phrase group"`
			} `cmd:"" name:"remove-include" help:"Include phraselist file to an existing list"`
			AddList struct {
				Name     string `arg:"" name:"name" help:"Name of the phrase list to create"`
				Weighted bool   `name:"weighted" help:"phrase list is weighted" default:"false"`
			} `cmd:"" name:"add-list" help:"Create a new phrase list"`
			RemoveList struct {
				Name string `arg:"" name:"name" help:"Name of the phrase list to delete"`
			} `cmd:"" name:"remove-list" help:"Delete an existing phrase list"`
			Show struct {
				Name  string `name:"name" help:"Name of the phrase list to show"`
				Group string `name:"group" help:"name of phrase group"`
			} `cmd:"" name:"show" help:"Dump the contents of a phrase list"`
		} `cmd:"" name:"phrase-list" help:"Configure phrase lists for content scanning"`
		Acl struct {
		} `cmd:"" name:"acl" help:"Configure acl lists for proxy"`
	} `cmd:"" help:"Deployment and configuration of the web filter"`
}

func main() {
	var code int = 0
	ctx := kong.Parse(&CLI)

	// Get the target if it is a filter command
	target := CLI.Filter.Target
	if strings.Contains(ctx.Command(), "filter") && target == "" {
		var err error
		err, target = utils.GetTargetSelection()
		if err != nil {
			log.Fatalf("For filter commands, you must either use the '--target' flag, or select a target using 'guardian-cli target select'\n")
			os.Exit(-1)
		}
	}

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
	case "target select <name>":
		code = utils.SelectTargetHost(CLI.Target.Select.Name)
	case "filter deploy":
		code = utils.Deploy(target)
	case "filter phrase-list add-list <name>":
		code = utils.AddPhraseList(CLI.Filter.PhraseList.AddList.Name, CLI.Filter.PhraseList.AddList.Weighted, target)
	case "filter phrase-list remove-list <name>":
		code = utils.DeletePhraseList(CLI.Filter.PhraseList.RemoveList.Name, target)
	case "filter phrase-list add-phrase <name> <phrase>":
		terms := strings.Split(CLI.Filter.PhraseList.AddPhrase.Phrase, ",")
		phrase := utils.Phrase{
			Phrase: terms,
			Weight: CLI.Filter.PhraseList.AddPhrase.Weight,
		}
		code = utils.AddPhraseToList(CLI.Filter.PhraseList.AddPhrase.Name, phrase, CLI.Filter.PhraseList.AddPhrase.Group, target)
	case "filter phrase-list remove-phrase <name> <phrase>":
		terms := strings.Split(CLI.Filter.PhraseList.AddPhrase.Phrase, ",")
		phrase := utils.Phrase{
			Phrase: terms,
			Weight: 0,
		}
		code = utils.DeletePhraseFromList(CLI.Filter.PhraseList.RemovePhrase.Name, phrase, CLI.Filter.PhraseList.RemovePhrase.Group, target)
	case "filter phrase-list add-include <name> <filename>":
		code = utils.AddInclude(CLI.Filter.PhraseList.AddInclude.Name, CLI.Filter.PhraseList.AddInclude.Group, CLI.Filter.PhraseList.AddInclude.Filename, target)
	case "filter phrase-list remove-include <name> <filename>":
		code = utils.DeleteInclude(CLI.Filter.PhraseList.DeleteInclude.Name, CLI.Filter.PhraseList.DeleteInclude.Group, CLI.Filter.PhraseList.DeleteInclude.Filename, target)
	case "filter phrase-list show":
		code = utils.ShowPhraseList(CLI.Filter.PhraseList.Show.Name, target, CLI.Filter.PhraseList.Show.Group)
	case "filter safe-search <command>":
		code = utils.SafeSearch(CLI.Filter.SafeSearch.Command, target)
	default:
		log.Fatal("Unknown command. Use '--help' to get a list of valid commands.")
		code = -1
	}

	os.Exit(code)
}
