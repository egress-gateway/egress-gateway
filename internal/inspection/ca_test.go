package inspection

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
			if err = os.WriteFile(filepath.Join(private, ".gateway-interrupted"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
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

func TestInterruptedInitialWriteCanRestart(t *testing.T) {
	for _, partial := range []string{"", `{"certificate":`} {
		t.Run(partial, func(t *testing.T) {
			private, public := dirs(t)
			if err := os.MkdirAll(private, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(private, ".gateway-interrupted"), []byte(partial), 0o600); err != nil {
				t.Fatal(err)
			}
			a, err := Open(private, public, time.Now())
			if err != nil {
				t.Fatalf("restart after interrupted initial write: %v", err)
			}
			original := a.Certificate.Raw
			a.Close()
			a, err = Open(private, public, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			if !bytes.Equal(original, a.Certificate.Raw) {
				t.Fatal("restart replaced the recovered CA")
			}
		})
	}
}

func TestMissingStateWithForeignEntriesRejected(t *testing.T) {
	for _, kind := range []string{"file", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			private, public := dirs(t)
			if err := os.MkdirAll(private, 0o700); err != nil {
				t.Fatal(err)
			}
			var err error
			switch kind {
			case "file":
				err = os.WriteFile(filepath.Join(private, "foreign-state"), nil, 0o600)
			case "directory":
				err = os.Mkdir(filepath.Join(private, ".gateway-directory"), 0o700)
			case "symlink":
				err = os.Symlink("missing", filepath.Join(private, ".gateway-symlink"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if a, err := Open(private, public, time.Now()); err == nil {
				a.Close()
				t.Fatal("created a CA over unknown state")
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
	bundle, err := Bundle(append([]byte("## Distribution root bundle\nRoot name\n==========\n"), ca...), ca)
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
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = Open(privateA, publicA, now)
	if err != nil {
		t.Fatal(err)
	}
	ca.Close()
	afterInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(info, afterInfo) {
		t.Fatal("matching public certificate was replaced")
	}
}

func TestConcurrentCertificatePublication(t *testing.T) {
	type material struct {
		authority *Authority
		pem       []byte
	}
	var candidates []material
	for range 2 {
		private, public := dirs(t)
		a, err := Open(private, public, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		a.Close()
		certificate, err := os.ReadFile(filepath.Join(public, config.CACertificateFile))
		if err != nil {
			t.Fatal(err)
		}
		candidates = append(candidates, material{a, certificate})
	}
	path := filepath.Join(t.TempDir(), config.CACertificateFile)
	start := make(chan struct{})
	type result struct {
		candidate int
		err       error
	}
	const publishers = 16
	results := make(chan result, publishers)
	for i := range publishers {
		go func() {
			<-start
			candidate := i % len(candidates)
			m := candidates[candidate]
			results <- result{candidate, publishCertificate(path, m.pem, m.authority.Certificate)}
		}()
	}
	close(start)
	var completed []result
	for range publishers {
		completed = append(completed, <-results)
	}
	published, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range completed {
		matches := bytes.Equal(published, candidates[r.candidate].pem)
		if matches && r.err != nil {
			t.Errorf("matching publisher failed: %v", r.err)
		}
		if !matches && (r.err == nil || !strings.Contains(r.err.Error(), "does not match private state")) {
			t.Errorf("conflicting publisher did not reject the winner: %v", r.err)
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != config.CACertificateFile {
		t.Fatal("publication left temporary files")
	}
}

func TestDirectoryPermissions(t *testing.T) {
	for _, target := range []string{"public", "private"} {
		for _, mode := range []os.FileMode{0o700, 0o750, 0o755, 0o775, 0o757, 0o777} {
			t.Run(fmt.Sprintf("%s/%o", target, mode), func(t *testing.T) {
				private, public := dirs(t)
				path := public
				forbidden := os.FileMode(0o022)
				if target == "private" {
					path, forbidden = private, 0o077
				}
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				a, err := Open(private, public, time.Now())
				if a != nil {
					a.Close()
				}
				if mode&forbidden != 0 {
					if err == nil || !strings.Contains(err.Error(), "unsafe directory permissions") {
						t.Fatalf("unsafe directory accepted or failed for another reason: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
				info, err := os.Stat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != mode {
					t.Fatal("existing directory permissions were changed")
				}
			})
		}
	}
}
