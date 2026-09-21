package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/egress-gateway/egress-gateway/test/e2e/environment"
	"github.com/egress-gateway/egress-gateway/test/e2e/suite"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	f := flag.NewFlagSet("gateway-e2e", flag.ContinueOnError)
	mode := f.String("mode", "run", "run, up, test, or down")
	root := f.String("root", ".", "repository root")
	cluster := f.String("cluster", "gateway-e2e-local", "dedicated kind cluster")
	image := f.String("image", "egress-gateway:e2e", "local gateway image")
	artifacts := f.String("artifacts", ".e2e/artifacts", "public diagnostics directory")
	state := f.String("state", ".e2e/state", "private environment state directory")
	tags := f.String("tags", "", "Godog tag filter")
	if err := f.Parse(os.Args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	var err error
	for _, path := range []*string{root, artifacts, state} {
		*path, err = filepath.Abs(*path)
		if err != nil {
			return err
		}
	}
	c := environment.Config{Root: *root, Cluster: *cluster, Image: *image, Artifacts: *artifacts, StateDir: *state, Kubeconfig: filepath.Join(*state, "kubeconfig")}
	e := environment.New(c)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 25*time.Minute)
	defer cancel()
	switch *mode {
	case "run":
		return e.Run(ctx, false, func() error { return suite.Run(ctx, e, *tags) })
	case "up":
		return e.Up(ctx)
	case "test":
		return e.Run(ctx, true, func() error { return suite.Run(ctx, e, *tags) })
	case "down":
		return e.Down()
	default:
		return errors.New("mode must be run, up, test, or down")
	}
}
