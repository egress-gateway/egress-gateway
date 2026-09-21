package inspection

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/egress-gateway/egress-gateway/config"
)

func dirs(t *testing.T) (string, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "private"), filepath.Join(root, "public")
}
func TestVolumeLifetime(t *testing.T) {
	private, public := dirs(t)
	now := time.Now()
	a, err := Open(private, public, now)
	if err != nil {
		t.Fatal(err)
	}
	original := a.Certificate.Raw
	if _, err = Open(private, public, now); err == nil {
		t.Fatal("concurrent owner accepted")
	}
	a.Close()
	a, err = Open(private, public, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if !bytes.Equal(original, a.Certificate.Raw) {
		t.Fatal("container restart changed CA")
	}
	private2, public2 := dirs(t)
	a, err = Open(private2, public2, now)
	if err != nil {
		t.Fatal(err)
	}
	a.Close()
	if bytes.Equal(original, a.Certificate.Raw) {
		t.Fatal("fresh Pod reused CA")
	}
	entries, err := os.ReadDir(public)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != config.CACertificateFile {
		t.Fatal("public directory includes non-CA data")
	}
	info, err := os.Stat(filepath.Join(private, config.CAStateFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatal("state not private")
	}
}
func TestExistingInvalidStateNeverReplaced(t *testing.T) {
	for _, test := range []string{"corrupt", "missing", "expired", "permissions", "symlink"} {
		t.Run(test, func(t *testing.T) {
			private, public := dirs(t)
			now := time.Now()
			a, err := Open(private, public, now)
			if err != nil {
				t.Fatal(err)
			}
			a.Close()
			path := filepath.Join(private, config.CAStateFile)
			switch test {
			case "corrupt":
				if err = os.WriteFile(path, []byte("invalid"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "missing":
				os.Remove(path)
				os.WriteFile(filepath.Join(private, "residue"), nil, 0o600)
			case "expired":
				now = now.AddDate(11, 0, 0)
			case "permissions":
				os.Chmod(path, 0o644)
			case "symlink":
				os.Remove(path)
				os.Symlink(filepath.Join(public, config.CACertificateFile), path)
			}
			before, _ := os.ReadFile(path)
			if _, err = Open(private, public, now); err == nil {
				t.Fatal("accepted unusable state")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("invalid state replaced")
			}
		})
	}
}
func TestBundle(t *testing.T) {
	private, public := dirs(t)
	a, err := Open(private, public, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	ca, err := os.ReadFile(filepath.Join(public, config.CACertificateFile))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := Bundle(ca, ca)
	if err != nil || bytes.Count(bundle, []byte("BEGIN CERTIFICATE")) != 2 {
		t.Fatalf("merge: %v", err)
	}
	for _, invalid := range [][]byte{nil, []byte("garbage"), []byte("-----BEGIN PRIVATE KEY-----\nYQ==\n-----END PRIVATE KEY-----")} {
		if _, err := Bundle(invalid, ca); err == nil {
			t.Fatal("invalid trust accepted")
		}
	}
}

func TestPublishedTrustMustMatchPrivateState(t *testing.T) {
	privateA, publicA := dirs(t)
	privateB, publicB := dirs(t)
	now := time.Now()
	for _, pair := range [][2]string{{privateA, publicA}, {privateB, publicB}} {
		ca, err := Open(pair[0], pair[1], now)
		if err != nil {
			t.Fatal(err)
		}
		ca.Close()
	}
	path := filepath.Join(publicA, config.CACertificateFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(privateB, publicA, now); err == nil {
		t.Fatal("mismatched public trust accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("public trust changed on mismatch")
	}
	if err := os.WriteFile(path, []byte("corrupt public trust"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(privateA, publicA, now); err == nil {
		t.Fatal("malformed published trust accepted")
	}
	after, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != "corrupt public trust" {
		t.Fatal("corrupt trust silently repaired")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ca, err := Open(privateA, publicA, now)
	if err != nil {
		t.Fatal(err)
	}
	ca.Close()
	after, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("missing public file recovery changed CA")
	}
}
