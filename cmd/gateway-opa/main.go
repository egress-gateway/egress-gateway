package main

import (
	"os"

	"github.com/open-policy-agent/opa/cmd"

	"github.com/egress-gateway/egress-gateway/internal/opa"
)

func main() {
	opa.RegisterPlugins()
	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
