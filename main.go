package main

import (
	"os"

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
	var code int = 0
	ctx := kong.Parse(&CLI)
	switch ctx.Command() {
	case "setup <host>":
		code = utils.Setup(CLI.Setup.Host, CLI.Setup.Port)
	default:
		panic(ctx.Command())
	}

	os.Exit(code)
}
