package inspection

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/netip"
	"strings"
	"time"
)

// canonicalName accepts DNS SNI names, not IP literals, wildcards, URLs, or
// filesystem paths. SNI is the untrusted input to the certificate service.
func canonicalName(name string) (string, error) {
	if len(name) == 0 || len(name) > 253 || strings.HasSuffix(name, ".") {
		return "", errors.New("invalid inspection server name")
	}
	name = strings.ToLower(name)
	if _, err := netip.ParseAddr(name); err == nil {
		return "", errors.New("inspection requires a DNS server name")
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("invalid inspection DNS label")
		}
		for _, c := range label {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", errors.New("invalid inspection DNS character")
			}
		}
	}
	return name, nil
}

// issue signs a previously validated DNS name. Leaf keys remain in memory and
// are sent only through the private SDS interface; they are never persisted.
func (a *Authority) issue(name string, now time.Time) (certificate, privateKey []byte, err error) {
	if now.Before(a.Certificate.NotBefore) || !now.Add(time.Minute).Before(a.Certificate.NotAfter) {
		return nil, nil, errors.New("inspection CA cannot issue a usable leaf")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	expiry := now.Add(time.Hour)
	if a.Certificate.NotAfter.Before(expiry) {
		expiry = a.Certificate.NotAfter
	}
	leaf := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name}, DNSNames: []string{name},
		NotBefore: now.Add(-time.Minute), NotAfter: expiry,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.Certificate, &key.PublicKey, a.key)
	if err != nil {
		return nil, nil, err
	}
	encodedKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encodedKey}), nil
}
