// Package environment owns the single-suite environment lifecycle. Shell
// operations implement phases; this package decides ordering and ownership.
package environment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"
)

type Config struct{ Root, Cluster, Kubeconfig, Image, StateDir, Artifacts string }
type Environment struct {
	Config    Config
	operation func(context.Context, string) error
}

func New(c Config) *Environment { e := &Environment{Config: c}; e.operation = e.execute; return e }
func (e *Environment) arguments() []string {
	c := e.Config
	return []string{"--root", c.Root, "--cluster", c.Cluster, "--kubeconfig", c.Kubeconfig, "--image", c.Image, "--state-dir", c.StateDir, "--artifacts", c.Artifacts, "--config-dir", filepath.Join(c.Root, "test/e2e/config")}
}
func (e *Environment) execute(ctx context.Context, phase string) error {
	script := filepath.Join(e.Config.Root, "test/e2e/scripts", phase+".sh")
	args := append([]string{script}, e.arguments()...)
	bash := "bash"
	if runtime.GOOS == "darwin" {
		for _, candidate := range []string{"/opt/homebrew/bin/bash", "/usr/local/bin/bash"} {
			if _, err := os.Stat(candidate); err == nil {
				bash = candidate
				break
			}
		}
	}
	cmd := exec.CommandContext(ctx, bash, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) }
	cmd.WaitDelay = 5 * time.Second
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("phase %s: %w", phase, err)
	}
	return nil
}
func (e *Environment) Up(ctx context.Context) (err error) {
	if err := os.MkdirAll(e.Config.StateDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(e.Config.Artifacts, 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(e.Config.StateDir, "environment.json")); !errors.Is(err, os.ErrNotExist) {
		return errors.New("environment already retained; use test or down")
	}
	raw, err := json.MarshalIndent(e.Config, "", "  ")
	if err != nil {
		return err
	}
	// The record describes an attempted setup, not permission to delete a node.
	// Teardown independently requires the cluster-up operation's exact node ID.
	record, err := os.OpenFile(filepath.Join(e.Config.StateDir, "environment.json"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = record.Write(raw); err != nil {
		record.Close()
		return err
	}
	if err = record.Close(); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			if _, statErr := os.Stat(filepath.Join(e.Config.StateDir, "node-id")); statErr == nil {
				err = errors.Join(err, e.Diagnostics())
			}
			err = errors.Join(err, e.Down())
		}
	}()
	for _, phase := range []string{"cluster-up", "image-load", "mesh-install", "fixtures-deploy"} {
		if err = e.operation(ctx, phase); err != nil {
			return err
		}
	}
	return nil
}
func (e *Environment) Reuse(ctx context.Context) error {
	raw, err := os.ReadFile(filepath.Join(e.Config.StateDir, "environment.json"))
	if err != nil {
		return err
	}
	var saved Config
	if err = json.Unmarshal(raw, &saved); err != nil {
		return err
	}
	if saved != e.Config {
		return errors.New("retained environment inputs do not match")
	}
	return e.operation(ctx, "verify")
}
func (e *Environment) Diagnostics() error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return e.operation(ctx, "diagnostics")
}
func (e *Environment) Down() error {
	if _, err := os.Stat(filepath.Join(e.Config.StateDir, "node-id")); errors.Is(err, os.ErrNotExist) {
		err = os.Remove(filepath.Join(e.Config.StateDir, "environment.json"))
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := e.operation(ctx, "cluster-down"); err != nil {
		return err
	}
	return os.Remove(filepath.Join(e.Config.StateDir, "environment.json"))
}

// Run always collects diagnostics before deleting its own environment, including
// failed setup. Retained mode validates identity and leaves the environment intact.
func (e *Environment) Run(ctx context.Context, reuse bool, tests func() error) (err error) {
	if reuse {
		if err = e.Reuse(ctx); err != nil {
			return err
		}
		defer func() { err = errors.Join(err, e.Diagnostics()) }()
		return tests()
	}
	if err = e.Up(ctx); err != nil {
		return err
	}
	defer func() { err = errors.Join(err, e.Diagnostics(), e.Down()) }()
	return tests()
}
func (e *Environment) Kubectl(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{"--kubeconfig", e.Config.Kubeconfig, "--context", "kind-" + e.Config.Cluster, "--request-timeout=30s"}
	cmd := exec.CommandContext(ctx, "kubectl", append(base, args...)...)
	return cmd.CombinedOutput()
}
