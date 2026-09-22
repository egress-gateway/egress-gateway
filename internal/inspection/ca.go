// Package inspection owns Pod-volume inspection trust. It does not handle TLS
// connections or mesh identity, and never replaces existing invalid state.
package inspection

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/egress-gateway/egress-gateway/config"
	"golang.org/x/sys/unix"
)

type Authority struct {
	Certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	lock        *os.File
}

func (a *Authority) Close() error { return a.lock.Close() }

type state struct {
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
}

// Open exclusively owns the private state directory until Close. Certificate
// and key are committed as one file, so interruption cannot split their versions.
func Open(privateDir, publicDir string, now time.Time) (_ *Authority, err error) {
	if err := Directory(privateDir, 0o700); err != nil {
		return nil, err
	}
	if err := Directory(publicDir, 0o755); err != nil {
		return nil, err
	}
	if privateDir == publicDir {
		return nil, errors.New("CA public and private directories must differ")
	}
	lock, err := openNoFollow(filepath.Join(privateDir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	if err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return nil, errors.New("inspection state is already owned by another process")
	}
	statePath := filepath.Join(privateDir, config.CAStateFile)
	raw, err := readPrivate(statePath)
	var s state
	if errors.Is(err, os.ErrNotExist) {
		if _, e := os.Lstat(filepath.Join(publicDir, config.CACertificateFile)); !errors.Is(e, os.ErrNotExist) {
			return nil, errors.New("private CA state missing while public trust exists; refusing replacement")
		}
		entries, e := os.ReadDir(privateDir)
		if e != nil {
			return nil, e
		}
		for _, entry := range entries {
			// A killed initial WriteAtomic can leave uncommitted temporary files.
			if entry.Name() == ".lock" || (strings.HasPrefix(entry.Name(), ".gateway-") && entry.Type().IsRegular()) {
				continue
			}
			return nil, errors.New("CA state missing from a nonempty private directory; refusing replacement")
		}
		s, err = generate(now)
		if err != nil {
			return nil, err
		}
		raw, err = json.Marshal(s)
		if err != nil {
			return nil, err
		}
		if err = WriteAtomic(statePath, raw, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else {
		if err = json.Unmarshal(raw, &s); err != nil {
			return nil, errors.New("invalid inspection CA state")
		}
	}
	pair, err := tls.X509KeyPair(s.Certificate, s.PrivateKey)
	if err != nil {
		return nil, errors.New("invalid or mismatched inspection CA material")
	}
	cert := pair.Leaf
	if cert == nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(cert.NotBefore) || !now.Add(time.Hour).Before(cert.NotAfter) {
		return nil, errors.New("inspection CA is not currently usable")
	}
	if err = cert.CheckSignatureFrom(cert); err != nil {
		return nil, errors.New("inspection CA is not self-signed")
	}
	key, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("unsupported inspection CA key")
	}
	publishedPath := filepath.Join(publicDir, config.CACertificateFile)
	if err = publishCertificate(publishedPath, s.Certificate, cert); err != nil {
		return nil, err
	}
	return &Authority{Certificate: cert, key: key, lock: lock}, nil
}

func publishCertificate(path string, certificate []byte, cert *x509.Certificate) error {
	// Linking a complete file publishes atomically without replacing another CA.
	err := writeAtomic(path, certificate, 0o644, os.Link)
	if !errors.Is(err, os.ErrExist) {
		return err
	}
	published, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	block, rest := pem.Decode(published)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 || !bytes.Equal(block.Bytes, cert.Raw) {
		return errors.New("published inspection CA does not match private state; refusing replacement")
	}
	return nil
}

func generate(now time.Time) (state, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return state{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return state{}, err
	}
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "Gateway Pod inspection CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return state{}, err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return state{}, err
	}
	return state{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})}, nil
}

// Directory rejects aliases and unsafe permissions rather than changing
// an existing mount's ownership or following a workload-controlled symlink.
func Directory(path string, mode os.FileMode) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("directory requires a clean absolute path")
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	actual, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	if actual != path {
		return fmt.Errorf("directory must not contain symlinks: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	forbidden := os.FileMode(0o022)
	if mode == 0o700 {
		forbidden = 0o077
	}
	if !info.IsDir() || info.Mode().Perm()&forbidden != 0 {
		return fmt.Errorf("unsafe directory permissions: %s", path)
	}
	return nil
}
func openNoFollow(path string, flags int, perm uint32) (*os.File, error) {
	fd, err := unix.Open(path, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, perm)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
func readPrivate(path string) ([]byte, error) {
	f, err := openNoFollow(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return nil, errors.New("unsafe inspection CA state file")
	}
	return io.ReadAll(io.LimitReader(f, 64<<10))
}
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	return writeAtomic(path, data, mode, os.Rename)
}

func writeAtomic(path string, data []byte, mode os.FileMode, publish func(string, string) error) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".gateway-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(mode); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = publish(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Bundle explicitly merges a declared base store with the inspection CA. Call
// during trust initialization, before starting the application.
func Bundle(base, inspectionCA []byte) ([]byte, error) {
	var bundle bytes.Buffer
	for _, input := range [][]byte{base, inspectionCA} {
		remaining := bytes.TrimSpace(input)
		count := 0
		for len(remaining) > 0 {
			// Distribution PEM stores may include comments and certificate
			// titles. Ignore annotations, but validate every actual PEM block.
			start := bytes.Index(remaining, []byte("-----BEGIN "))
			if start < 0 {
				break
			}
			remaining = remaining[start:]
			if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
				return nil, errors.New("trust input must contain only PEM certificates")
			}
			block, rest := pem.Decode(remaining)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				return nil, errors.New("invalid trust certificate PEM")
			}
			if _, err := x509.ParseCertificate(block.Bytes); err != nil {
				return nil, err
			}
			if err := pem.Encode(&bundle, block); err != nil {
				return nil, err
			}
			remaining = bytes.TrimSpace(rest)
			count++
		}
		if count == 0 {
			return nil, errors.New("trust input has no certificates")
		}
	}
	return bundle.Bytes(), nil
}
