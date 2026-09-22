package config_test

import (
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway/config"
)

func TestPublicContract(t *testing.T) {
	c, err := config.Load(func(string) (string, bool) { return "", false })
	if err != nil {
		t.Fatal(err)
	}
	if c != config.Defaults() {
		t.Fatalf("defaults differ: %+v", c)
	}
	if c.PublicCAPath() != config.DefaultPublicDir+"/inspection-ca.pem" {
		t.Fatal(c.PublicCAPath())
	}
	env := map[string]string{config.EnvRole: "egress", config.EnvProxyMode: "standalone", config.EnvEnvoyConfig: "/etc/envoy.yaml"}
	c, err = config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	if c.OPAConfig != "/etc/gateway/opa/egress.yaml" {
		t.Fatal(c.OPAConfig)
	}
	env[config.EnvOPAConfig] = "/custom/opa.yaml"
	c, err = config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
	if err != nil || c.OPAConfig != env[config.EnvOPAConfig] {
		t.Fatalf("override: %+v %v", c, err)
	}
}
func TestRejectInvalidContract(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"identity": {config.EnvIdentityProvider: "headers"},
		"role":     {config.EnvRole: "invalid"}, "empty": {config.EnvRole: ""},
		"mode": {config.EnvProxyMode: "other"}, "missing envoy": {config.EnvProxyMode: "standalone"},
		"mesh ownership": {config.EnvEnvoyConfig: "/etc/envoy.yaml"},
		"relative":       {config.EnvPublicDir: "trust"}, "root": {config.EnvPublicDir: "/"},
		"private under public": {config.EnvStateDir: config.DefaultPublicDir + "/private"},
		"public under private": {config.EnvPublicDir: config.DefaultStateDir + "/public"},
		"same path":            {config.EnvPublicDir: config.DefaultRuntimeDir},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(func(k string) (string, bool) { v, ok := env[k]; return v, ok })
			if err == nil || strings.TrimSpace(err.Error()) == "" {
				t.Fatal("accepted invalid config")
			}
		})
	}
}
