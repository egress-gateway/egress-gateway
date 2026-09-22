package inspection

import (
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServerNames(t *testing.T) {
	for _, name := range []string{"", "*.example.test", "127.0.0.1", "::1", "a..test", "-a.test", "a-.test", "a/b", "a:443", "a.test.", "x\x00.test", "例.test", strings.Repeat("a", 64) + ".test", strings.Repeat("a.", 127) + "test"} {
		if _, err := canonicalName(name); err == nil {
			t.Errorf("accepted invalid name %q", name)
		}
	}
	for _, name := range []string{"example.test", "NEW.Example.test", "xn--fsq.test", "localhost", "a-b.test"} {
		got, err := canonicalName(name)
		if err != nil || got != strings.ToLower(name) {
			t.Errorf("name %q: %q, %v", name, got, err)
		}
	}
}

func TestIssuedLeafVerifiesOnlyForItsTarget(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca, err := Open(filepath.Join(root, "private"), filepath.Join(root, "public"), now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ca.Close() })
	cert, key, err := ca.issue("new.example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	trust := x509.NewCertPool()
	trust.AddCert(ca.Certificate)
	options := x509.VerifyOptions{Roots: trust, DNSName: "new.example.test", CurrentTime: now}
	if _, err := pair.Leaf.Verify(options); err != nil {
		t.Fatal(err)
	}
	options.DNSName = "other.example.test"
	if _, err := pair.Leaf.Verify(options); err == nil {
		t.Fatal("leaf verified for a different target")
	}
	if pair.Leaf.IsCA || pair.Leaf.NotAfter.After(now.Add(time.Hour)) {
		t.Fatal("leaf exceeds signing or lifetime contract")
	}
	if _, _, err := ca.issue("new.example.test", ca.Certificate.NotAfter); err == nil {
		t.Fatal("expired CA issued a leaf")
	}
}
