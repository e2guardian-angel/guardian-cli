package main

import (
	"log"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/e2guardian-angel/guardian-cli/utils"
)

var CLI struct {
	Config struct {
		Export struct {
			Output string `name:"output" help:"Output file path to export to" required:"true"`
		} `cmd:"" name:"export" help:"Exports config to file"`
		Import struct {
			Input string `name:"input" help:"Input file path to import from" required:"true"`
		} `cmd:"" name:"import" help:"Imports config from file"`
	} `cmd:"" help:"Export/Import configuration to file"`
	Target struct {
		Add struct {
			Name       string `arg:"" name:"name" help:"Name to refer to target host" required:"true"`
			Host       string `arg:"" name:"host" help:"Target host address for install" type:"ip/hostname" required:"true"`
			Username   string `arg:"" name:"username" help:"Username for SSH login" required:"true"`
			Port       uint16 `name:"port" help:"SSH port" default:"22"`
			NoPassword bool   `name:"no-password" help:"Don't use password auth for SSH key exchange" default:"false"`
			HomePath   string `name:"home-path" help:"Custom home path on remote target installation"`
		} `cmd:"" name:"add" help:"Add a target host for installation" required:"true"`
		Delete struct {
			Name string `arg:"" name:"name" help:"Name of target host to delete"`
		} `cmd:"" name:"delete" help:"Deletes a target host"`
		List struct {
		} `cmd:"" name:"list" help:"List configured target hosts"`
		Reset struct {
		} `cmd:"" name:"reset" help:"Reset SSH and clear all hosts"`
		Select struct {
			Name string `arg:"" name:"name" help:"Name of target host to select"`
		} `cmd:"" name:"select" help:"Select target for operations"`
		Setup struct {
			Name string `arg:"" name:"name" help:"Target to select for setup"`
		} `cmd:"" name:"setup" help:"Setup dependencies on host"`
		Test struct {
			Name string `arg:"" name:"name" help:"Name of target host to test"`
		} `cmd:"" name:"test" help:"Run test ssh command"`
		Update struct {
			Name       string `arg:"" name:"name" help:"Name of target host to update" required:"true"`
			Host       string `arg:"" name:"host" help:"Target host address for install" type:"ip/hostname" required:"true"`
			Username   string `arg:"" name:"username" help:"Username for SSH login" required:"true"`
			Port       uint16 `name:"port" help:"SSH port" default:"22"`
			NoPassword bool   `name:"no-password" help:"Don't use password auth for SSH key exchange" default:"false"`
			HomePath   string `name:"home-path" help:"Custom home path on remote target installation"`
		} `cmd:"" name:"update" help:"Updates a target host for installation"`
	} `cmd:"" name:"target" help:"Operations on target hosts"`
	Filter struct {
		Target string `name:"target" help:"Name of target host for changes"`
		Acl    struct {
			AddRule struct {
				Category string `arg:"" name:"category" help:"ACL rule category" required:"true"`
				Action   string `arg:"" name:"action" help:"ACL rule action (allow, deny, decrypt, nodecrypt)" required:"true"`
				Position int    `name:"position" help:"Position of rule in ordered acl list" default:"-1"`
			} `cmd:"" name:"add" help:"Adds an ACL rule"`
			DeleteRule struct {
				Category string `arg:"" name:"category" help:"ACL rule category" required:"true"`
				Action   string `arg:"" name:"action" help:"ACL rule action (allow, deny, decrypt, nodecrypt)" required:"true"`
				Position int    `name:"position" help:"Position of rule in ordered acl list" default:"-1"`
			} `cmd:"" name:"delete" help:"Deletes an ACL rule"`
			Show struct {
			} `cmd:"" name:"show" help:"Show all acl rules"`
			CategorizeDomain struct {
				Category string `arg:"" name:"category" help:"Category that a host belongs to"`
				Domain   string `arg:"" name:"domain" help:"Domain to be categorized (i.e. google.com)"`
			} `cmd:"" name:"categorize-domain" help:"Associate a domain with a category"`
			DecategorizeDomain struct {
				Category string `arg:"" name:"category" help:"Category that a host belongs to"`
				Domain   string `arg:"" name:"domain" help:"Domain to be decategorized (i.e. google.com)"`
			} `cmd:"" name:"decategorize-domain" help:"Remove association of a domain with a category"`
			ListCategories struct {
				Domain string `name:"domain" help:"Optional: show only categories that a domain belongs to" default:""`
			} `cmd:"" name:"list-categories" help:"List all existing categories in the database"`
			DeleteCategory struct {
				Category string `arg:"" name:"category" help:"Domain category to be deleted"`
			} `cmd:"" name:"delete-category" help:"Delete a domain category"`
			ClearDatabase struct {
			} `cmd:"" name:"clear-database" help:"Clear the domain category database"`
		} `cmd:"" name:"acl" help:"Configure acl lists for proxy"`
		Backup struct {
			ToFile string `name:"to-file" help:"path to backup file" type:"filename" required:"true"`
		} `cmd:"" name:"backup" help:"Backup target host's filter configuration"`
		Certificate struct {
			Configure struct {
				CommonName   string `name:"common-name" help:"Common Name for the certificate subject line" default:"guardian.angel"`
				Country      string `name:"country" help:"Country code for the certificate subject line" default:"US"`
				State        string `name:"state" help:"State/Province for the certificate subject line" default:"Texas"`
				Locality     string `name:"locality" help:"Locality (usually the city) for the certificate subject line" default:"Austin"`
				Organization string `name:"organization" help:"Organization name for the certificate subject line" default:"Security"`
			} `cmd:"" name:"configure" help:"Generates a new certificate/key pair for decryption"`
			GetRootCa struct {
				Output string `name:"output" help:"Output file path to export certificate to" required:"true"`
			} `cmd:"" name:"get-root-ca" help:"Fetch the root CA certificate and output to a file"`
		} `cmd:"" name:"certificate" help:"Manage decryption certificate"`
		ContentList struct {
			AddEntry struct {
				Name  string `arg:"" name:"name" help:"Name of the content list to modify"`
				Entry string `arg:"" name:"entry" help:"Line to add to the content list" type:"string" required:"true"`
				Group string `name:"group" help:"name of content group"`
			} `cmd:"" name:"add-entry" help:"Add an entry to an existing content list"`
			AddList struct {
				Type string `arg:"" name:"type" help:"Type of list"`
				Name string `arg:"" name:"name" help:"Name of the content list to create"`
			} `cmd:"" name:"add-list" help:"Add a content list"`
			Blacklist struct {
				Name string `arg:"" name:"name" help:"Name of the content list to be blacklisted" required:"true"`
			} `cmd:"" name:"blacklist" help:"Blacklist this content list"`
			Clear struct {
				Name string `arg:"" name:"name" help:"Name of the content list to be cleared" required:"true"`
			} `cmd:"" name:"clear" help:"Clear all includes from a content list"`
			RemoveList struct {
				Name string `arg:"" name:"name" help:"Name of the content list to delete"`
			} `cmd:"" name:"remove-list" help:"Delete an existing content list"`
			RemoveEntry struct {
				Name  string `arg:"" name:"name" help:"Name of the content list to modify"`
				Entry string `arg:"" name:"entry" help:"Entry to delete from content list" type:"string"`
				Group string `name:"group" help:"name of content group"`
			} `cmd:"" name:"remove-entry" help:"Remove an entry from an existing content list"`
			Show struct {
				Name  string `name:"name" help:"Name of the content list to show"`
				Group string `name:"group" help:"name of content group"`
			} `cmd:"" name:"show" help:"Dump the contents of a content list"`
			Whitelist struct {
				Name string `arg:"" name:"name" help:"Name of the content list to be whitelisted" required:"true"`
			} `cmd:"" name:"whitelist" help:"Whitelist this content list"`
		} `cmd:"" name:"content-list" help:"Configure content lists for content scanning"`
		Deploy struct {
		} `cmd:"" name:"deploy" help:"Deploy filter stack to target host"`
		PhraseList struct {
			AddList struct {
				Name     string `arg:"" name:"name" help:"Name of the phrase list to create"`
				Weighted bool   `name:"weighted" help:"phrase list is weighted" default:"false"`
			} `cmd:"" name:"add-list" help:"Create a new phrase list"`
			AddPhrase struct {
				Name   string `arg:"" name:"name" help:"Name of the phrase list to modify" required:"true"`
				Phrase string `arg:"" name:"phrase" help:"Phrase to add to the list" type:"comma separated list" required:"true"`
				Group  string `name:"group" help:"name of phrase group"`
				Weight int    `name:"weight" help:"For weighted list, numeric weight associated with the phrase"`
			} `cmd:"" name:"add-phrase" help:"Add a phrase to an existing list"`
			Blacklist struct {
				Name string `arg:"" name:"name" help:"Name of the phrase list to be blacklisted" required:"true"`
			} `cmd:"" name:"blacklist" help:"blacklist this phrase list"`
			Clear struct {
				Name string `arg:"" name:"name" help:"Name of the phrase list to be cleared" required:"true"`
			} `cmd:"" name:"clear" help:"remove this phrase list from whitelist/blacklist"`
			RemovePhrase struct {
				Name   string `arg:"" name:"name" help:"Name of the phrase list to modify"`
				Phrase string `arg:"" name:"phrase" help:"Name of phrase list file include to delete" type:"comma separated list"`
				Group  string `name:"group" help:"name of phrase group"`
			} `cmd:"" name:"remove-phrase" help:"Remove a phrase from an existing list"`
			RemoveList struct {
				Name string `arg:"" name:"name" help:"Name of the phrase list to delete"`
			} `cmd:"" name:"remove-list" help:"Delete an existing phrase list"`
			Show struct {
				Name  string `name:"name" help:"Name of the phrase list to show"`
				Group string `name:"group" help:"name of phrase group"`
			} `cmd:"" name:"show" help:"Dump the contents of a phrase list"`
			Whitelist struct {
				Name string `arg:"" name:"name" help:"Name of the phrase list to be whitelisted" required:"true"`
			} `cmd:"" name:"whitelist" help:"whitelist this phrase list"`
		} `cmd:"" name:"phrase-list" help:"Configure phrase lists for content scanning"`
		ReleaseTag struct {
			Tag string `arg:"" name:"tag" help:"Name of tag to apply to images"`
		} `cmd:"" name:"release-tag" help:"Release tag for CI/CD images"`
		Restore struct {
			FromFile string `name:"from-file" help:"Restore configuration from a backup file" type:"filename" required:"true"`
		} `cmd:"" name:"restore" help:"Restore target host's filter configuration from a backup file"`
		SafeSearch struct {
			Command string `arg:"" name:"command" help:"Safesearch is enforced (on/off/show)"`
		} `cmd:"" name:"safe-search" help:"Safe search option"`
		Uninstall struct {
		} `cmd:"" name:"uninstall" help:"Uninstall filter stack on target host"`
	} `cmd:"" help:"Deployment and configuration of the web filter"`
}

var listTypes = []string{"sitelist", "regexpurllist", "mimetypelist", "extensionslist"}

func main() {
	var code int = 0
	ctx := kong.Parse(&CLI)

	// Get the target if it is a filter command
	target := CLI.Filter.Target
	if strings.Contains(ctx.Command(), "filter") && target == "" {
		var err error
		target, err = utils.GetTargetSelection()
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
	case "filter phrase-list blacklist <name>":
		code = utils.BlacklistPhrase(CLI.Filter.PhraseList.Blacklist.Name, target)
	case "filter phrase-list whitelist <name>":
		code = utils.WhitelistPhrase(CLI.Filter.PhraseList.Whitelist.Name, target)
	case "filter phrase-list clear <name>":
		code = utils.DeletePhraseIncludes(CLI.Filter.PhraseList.Clear.Name, target)
	case "filter phrase-list show":
		code = utils.ShowPhraseList(CLI.Filter.PhraseList.Show.Name, target, CLI.Filter.PhraseList.Show.Group)
	case "filter content-list add-list <type> <name>":
		valid := false
		for _, t := range utils.ListTypes {
			if t == CLI.Filter.ContentList.AddList.Type {
				valid = true
			}
		}
		if !valid {
			log.Fatalf("Invalid list type: '%s' Valid options are: %s\n", CLI.Filter.ContentList.AddList.Type, strings.Join(listTypes, ", "))
			code = -1
		} else {
			code = utils.AddContentList(CLI.Filter.ContentList.AddList.Name, CLI.Filter.ContentList.AddList.Type, target)
		}
	case "filter content-list remove-list <name>":
		code = utils.DeleteContentList(CLI.Filter.ContentList.RemoveList.Name, target)
	case "filter content-list add-entry <name> <entry>":
		code = utils.AddEntryToContentList(CLI.Filter.ContentList.AddEntry.Name, CLI.Filter.ContentList.AddEntry.Group, CLI.Filter.ContentList.AddEntry.Entry, target)
	case "filter content-list remove-entry <name> <entry>":
		code = utils.DeleteEntryFromList(CLI.Filter.ContentList.RemoveEntry.Name, CLI.Filter.ContentList.RemoveEntry.Entry, CLI.Filter.ContentList.RemoveEntry.Group, target)
	case "filter content-list blacklist <name>":
		code = utils.Blacklist(CLI.Filter.ContentList.Blacklist.Name, target)
	case "filter content-list whitelist <name>":
		code = utils.Whitelist(CLI.Filter.ContentList.Whitelist.Name, target)
	case "filter content-list clear <name>":
		code = utils.DeleteIncludes(CLI.Filter.ContentList.Clear.Name, target)
	case "filter safe-search <command>":
		code = utils.SafeSearch(CLI.Filter.SafeSearch.Command, target)
	case "filter content-list show":
		code = utils.ShowContentList(CLI.Filter.ContentList.Show.Name, target, CLI.Filter.ContentList.Show.Group)
	case "filter acl add <category> <action>":
		code = utils.AddAclRule(CLI.Filter.Acl.AddRule.Category, CLI.Filter.Acl.AddRule.Action, target, CLI.Filter.Acl.AddRule.Position)
	case "filter acl delete <category> <action>":
		code = utils.DeleteAclRule(CLI.Filter.Acl.DeleteRule.Category, CLI.Filter.Acl.DeleteRule.Action, target)
	case "filter acl show":
		code = utils.ShowAclRules(target)
	case "filter acl categorize-domain <category> <domain>":
		code = utils.Categorize(target, CLI.Filter.Acl.CategorizeDomain.Domain, CLI.Filter.Acl.CategorizeDomain.Category)
	case "filter acl decategorize-domain <category> <domain>":
		code = utils.DeCategorize(target, CLI.Filter.Acl.DecategorizeDomain.Domain, CLI.Filter.Acl.DecategorizeDomain.Category)
	case "filter acl delete-category <category>":
		code = utils.DeleteCategory(target, CLI.Filter.Acl.DeleteCategory.Category)
	case "filter acl clear-database <category>":
		code = utils.ClearAll(target)
	case "filter acl list-categories":
		code = utils.ListCategory(target, CLI.Filter.Acl.ListCategories.Domain)
	case "filter release-tag <tag>":
		code = utils.SetReleaseTag(target, CLI.Filter.ReleaseTag.Tag)
	case "filter certificate configure":
		code = utils.SetupCertificate(target, CLI.Filter.Certificate.Configure.CommonName, CLI.Filter.Certificate.Configure.Organization, CLI.Filter.Certificate.Configure.Country, CLI.Filter.Certificate.Configure.State, CLI.Filter.Certificate.Configure.Locality)
	case "filter certificate get-root-ca":
		code = utils.CopyRootCa(target, CLI.Filter.Certificate.GetRootCa.Output)
	case "config import":
		code = utils.ImportConfigs(CLI.Config.Import.Input)
	case "config export":
		code = utils.ExportConfigs(CLI.Config.Export.Output)
	default:
		log.Fatal("Unknown command. Use '--help' to get a list of valid commands.")
		code = -1
	}

	os.Exit(code)
}
