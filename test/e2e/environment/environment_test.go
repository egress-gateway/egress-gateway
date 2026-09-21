package environment

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestFailureCollectsBeforeOwnedCleanup(t *testing.T) {
	for _, failed := range []string{"cluster-up", "image-load", "mesh-install", "fixtures-deploy", "tests"} {
		t.Run(failed, func(t *testing.T) {
			root := t.TempDir()
			e := New(Config{StateDir: filepath.Join(root, "state"), Artifacts: filepath.Join(root, "artifacts")})
			var got []string
			e.operation = func(_ context.Context, phase string) error {
				got = append(got, phase)
				if phase == "cluster-up" {
					if err := os.WriteFile(filepath.Join(e.Config.StateDir, "node-id"), []byte("owned"), 0o600); err != nil {
						return err
					}
				}
				if phase == failed {
					return errors.New("injected phase failure")
				}
				return nil
			}
			err := e.Run(t.Context(), false, func() error { got = append(got, "tests"); return errors.New("assertion failed") })
			if err == nil {
				t.Fatal("failure lost")
			}
			if !slices.Equal(got[len(got)-2:], []string{"diagnostics", "cluster-down"}) {
				t.Fatalf("ordering: %v", got)
			}
			if failed != "tests" && slices.Contains(got, "tests") {
				t.Fatal("ran tests after setup failure")
			}
		})
	}
}
func TestExistingStateNeverAcquiresOwnership(t *testing.T) {
	root := t.TempDir()
	e := New(Config{StateDir: root})
	os.WriteFile(filepath.Join(root, "environment.json"), []byte("external"), 0o600)
	e.operation = func(context.Context, string) error { t.Fatal("touched existing environment"); return nil }
	if err := e.Run(t.Context(), false, func() error { t.Fatal("ran tests"); return nil }); err == nil {
		t.Fatal("takeover accepted")
	}
}
func TestReuseDoesNotDelete(t *testing.T) {
	root := t.TempDir()
	e := New(Config{StateDir: root, Artifacts: filepath.Join(root, "artifacts")})
	var got []string
	e.operation = func(_ context.Context, phase string) error { got = append(got, phase); return nil }
	if err := e.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	got = nil
	err := e.Run(t.Context(), true, func() error { got = append(got, "tests"); return errors.New("test failure") })
	if err == nil || !slices.Equal(got, []string{"verify", "tests", "diagnostics"}) {
		t.Fatalf("retained behavior: %v %v", got, err)
	}
}
