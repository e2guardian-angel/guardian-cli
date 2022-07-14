package main

import (
	"github.com/alecthomas/kong"
	"github.com/e2guardian-angel/guardian-cli/utils"
)

var CLI struct {
	Setup struct {
		Port int16  `default:22 help:"SSH port"`
		Host string `arg name:"host" help:"Target host for install" type:"ip"`
	} `cmd help:"Setup dependencies on a target host"`
}

func main() {
	ctx := kong.Parse(&CLI)
	switch ctx.Command() {
	case "setup <host>":
		utils.Setup(CLI.Setup.Host, CLI.Setup.Port)
	default:
		panic(ctx.Command())
	}
}
