package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/daemon"
	"github.com/egress-gateway/egress-gateway/internal/inspection"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) > 0 && args[0] == "trust-init" {
		return trustInit(args[1:])
	}
	c, err := config.Load(os.LookupEnv)
	if err != nil {
		return err
	}
	if len(args) == 1 && args[0] == "ready" {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return daemon.Ready(ctx, c)
	}
	var policies []string
	for len(args) > 0 {
		if args[0] != "--policy" || len(args) < 2 {
			return errors.New("supported startup arguments: --policy /absolute/path (repeatable); OPA CLI passthrough has been removed")
		}
		policies = append(policies, args[1])
		args = args[2:]
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	return daemon.Run(ctx, c, policies)
}
func trustInit(args []string) error {
	flags := flag.NewFlagSet("trust-init", flag.ContinueOnError)
	base := flags.String("base", "", "base image's PEM trust bundle")
	ca := flags.String("ca", "", "published inspection CA")
	output := flags.String("output", "", "prepared application bundle path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *base == "" || *ca == "" || *output == "" {
		return errors.New("trust-init requires --base, --ca and --output")
	}
	basePEM, err := os.ReadFile(*base)
	if err != nil {
		return err
	}
	caPEM, err := os.ReadFile(*ca)
	if err != nil {
		return err
	}
	bundle, err := inspection.Bundle(basePEM, caPEM)
	if err != nil {
		return err
	}
	return inspection.WriteAtomic(*output, bundle, 0o644)
}
