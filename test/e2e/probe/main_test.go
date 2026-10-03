package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMeshVerificationRequiresTrustedChainAndExpectedIdentity(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := meshTLS(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, identity           string
		expired, untrusted, want bool
	}{
		{"expected", "spiffe://cluster.local/ns/gateway-test/sa/egress", false, false, true},
		{"wrong-role", "spiffe://cluster.local/ns/gateway-test/sa/workload", false, false, false},
		{"wrong-namespace", "spiffe://cluster.local/ns/other/sa/egress", false, false, false},
		{"expired", "spiffe://cluster.local/ns/gateway-test/sa/egress", true, false, false},
		{"untrusted", "spiffe://cluster.local/ns/gateway-test/sa/egress", false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			uri, err := url.Parse(tc.identity)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), URIs: []*url.URL{uri}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
			if tc.expired {
				leaf.NotAfter = now.Add(-time.Minute)
			}
			signer := key
			if tc.untrusted {
				signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			}
			parent := *root
			parent.PublicKey = &signer.PublicKey
			der, err := x509.CreateCertificate(rand.Reader, leaf, &parent, &key.PublicKey, signer)
			if err != nil {
				t.Fatal(err)
			}
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err = cfg.VerifyConnection(tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}); (err == nil) != tc.want {
				t.Fatalf("verification error = %v, want success %v", err, tc.want)
			}
		})
	}
	if cfg.VerifyConnection(tls.ConnectionState{}) == nil {
		t.Fatal("missing certificate accepted")
	}
}
