// Package config defines the gateway startup and volume contract. It has no
// dependency on Kubernetes, Envoy, or the embedded policy runtime.
package config

import (
	"fmt"
	"path/filepath"
)

type Role string

const (
	Workload Role = "workload"
	Egress   Role = "egress"
)

type ProxyMode string

const (
	Standalone ProxyMode = "standalone"
	Istio      ProxyMode = "istio"
)

const (
	EnvRole           = "GATEWAY_ROLE"
	EnvProxyMode      = "GATEWAY_PROXY_MODE"
	EnvOPAConfig      = "OPA_CONFIG"
	EnvEnvoyConfig    = "ENVOY_CONFIG"
	EnvStateDir       = "GATEWAY_STATE_DIR"
	EnvPublicDir      = "GATEWAY_PUBLIC_DIR"
	EnvRuntimeDir     = "GATEWAY_RUNTIME_DIR"
	DefaultStateDir   = "/var/lib/gateway/private"
	DefaultPublicDir  = "/run/gateway/trust"
	DefaultRuntimeDir = "/run/gateway/private"
	CACertificateFile = "inspection-ca.pem"
	CAStateFile       = "inspection-ca.json"
	BundleFile        = "ca-bundle.pem"
)

// Config is resolved once at startup. Private and public directories must be
// separate mounts; only PublicDir may be mounted into an application.
type Config struct {
	Role        Role
	ProxyMode   ProxyMode
	OPAConfig   string
	EnvoyConfig string
	StateDir    string
	PublicDir   string
	RuntimeDir  string
}

func Defaults() Config {
	return Config{Role: Workload, ProxyMode: Istio,
		OPAConfig: "/etc/gateway/opa/workload.yaml", StateDir: DefaultStateDir,
		PublicDir: DefaultPublicDir, RuntimeDir: DefaultRuntimeDir}
}

// Load applies nonempty environment values over defaults. OPA_CONFIG defaults
// to the selected role's file. Explicit empty values are invalid, not defaults.
func Load(lookup func(string) (string, bool)) (Config, error) {
	c := Defaults()
	role, err := value(lookup, EnvRole, string(c.Role))
	if err != nil {
		return c, err
	}
	c.Role = Role(role)
	mode, err := value(lookup, EnvProxyMode, string(c.ProxyMode))
	if err != nil {
		return c, err
	}
	c.ProxyMode = ProxyMode(mode)
	for _, item := range []struct {
		name     string
		target   *string
		fallback string
	}{
		{EnvOPAConfig, &c.OPAConfig, "/etc/gateway/opa/" + role + ".yaml"},
		{EnvEnvoyConfig, &c.EnvoyConfig, ""}, {EnvStateDir, &c.StateDir, c.StateDir},
		{EnvPublicDir, &c.PublicDir, c.PublicDir}, {EnvRuntimeDir, &c.RuntimeDir, c.RuntimeDir},
	} {
		*item.target, err = value(lookup, item.name, item.fallback)
		if err != nil {
			return c, err
		}
	}
	return c, c.Validate()
}
func value(lookup func(string) (string, bool), name, fallback string) (string, error) {
	v, ok := lookup(name)
	if !ok {
		return fallback, nil
	}
	if v == "" {
		return "", fmt.Errorf("%s must not be empty", name)
	}
	return v, nil
}

func (c Config) Validate() error {
	if c.Role != Workload && c.Role != Egress {
		return fmt.Errorf("unsupported %s: %q", EnvRole, c.Role)
	}
	if c.ProxyMode != Standalone && c.ProxyMode != Istio {
		return fmt.Errorf("unsupported %s: %q", EnvProxyMode, c.ProxyMode)
	}
	for _, path := range []string{c.OPAConfig, c.StateDir, c.PublicDir, c.RuntimeDir} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			return fmt.Errorf("expected a clean absolute non-root path: %q", path)
		}
	}
	if c.ProxyMode == Standalone && c.EnvoyConfig == "" {
		return fmt.Errorf("standalone mode requires %s", EnvEnvoyConfig)
	}
	if c.ProxyMode == Istio && c.EnvoyConfig != "" {
		return fmt.Errorf("%s belongs to standalone mode; Istiod owns mesh configuration", EnvEnvoyConfig)
	}
	if c.EnvoyConfig != "" && (!filepath.IsAbs(c.EnvoyConfig) || filepath.Clean(c.EnvoyConfig) != c.EnvoyConfig) {
		return fmt.Errorf("%s must be a clean absolute path", EnvEnvoyConfig)
	}
	if contains(c.StateDir, c.RuntimeDir) || contains(c.RuntimeDir, c.StateDir) {
		return fmt.Errorf("CA state and runtime directories must not overlap")
	}
	for _, dir := range []string{c.StateDir, c.RuntimeDir} {
		if contains(c.PublicDir, dir) || contains(dir, c.PublicDir) {
			return fmt.Errorf("public trust and private directories must not overlap")
		}
	}
	return nil
}
func contains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && filepath.IsLocal(rel)
}
func (c Config) PublicCAPath() string   { return filepath.Join(c.PublicDir, CACertificateFile) }
func (c Config) OPAAddress() string     { return "unix://" + filepath.Join(c.RuntimeDir, "opa.sock") }
func (c Config) EnvoyAdminPath() string { return filepath.Join(c.RuntimeDir, "envoy-admin.sock") }
