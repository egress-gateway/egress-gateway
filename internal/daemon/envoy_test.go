package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway/config"
)

func TestPrivateStandaloneInterfaces(t *testing.T) {
	dir := t.TempDir()
	c := config.Defaults()
	c.ProxyMode = config.Standalone
	c.EnvoyConfig = filepath.Join(dir, "envoy.yaml")
	c.RuntimeDir = dir
	source := `admin:
  address: {socket_address: {address: 127.0.0.1, port_value: 15000}}
static_resources:
  listeners: [{name: keep-me, filter_chains: []}]
  clusters:
  - name: opa
    type: STATIC
    load_assignment:
      cluster_name: opa
      endpoints: []
  - name: next_hop
    type: STRICT_DNS
`
	if err := os.WriteFile(c.EnvoyConfig, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	path, err := prepareEnvoy(c)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err = json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"envoy-admin.sock", "opa.sock", "keep-me", "STRICT_DNS"} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("lost %s", want)
		}
	}
	if strings.Contains(string(raw), "127.0.0.1") {
		t.Fatal("management remained on shared network")
	}
	if err = os.WriteFile(c.EnvoyConfig, []byte("dynamic_resources: {}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = prepareEnvoy(c); err == nil {
		t.Fatal("accepted competing discovery ownership")
	}
}

func TestSharedAuthorizationConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name, typed string
		invalid     bool
	}{
		{"fail-open", `{"failure_mode_allow":true}`, false},
		{"missing", `null`, true},
		{"wrong-type", `"invalid"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			c := config.Defaults()
			c.RuntimeDir, c.EnvoyConfig, c.WorkloadConfig = dir, filepath.Join(dir, "envoy.json"), "/trusted/runtime.json"
			filter := map[string]any{"name": "envoy.filters.http.ext_authz", "typed_config": json.RawMessage(tc.typed)}
			hcm := map[string]any{"name": "envoy.filters.network.http_connection_manager", "typed_config": map[string]any{"http_filters": []any{filter}}}
			bootstrap := map[string]any{"static_resources": map[string]any{"listeners": []any{map[string]any{"filter_chains": []any{map[string]any{"filters": []any{hcm}}}}}}}
			raw, err := json.Marshal(bootstrap)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(c.EnvoyConfig, raw, 0600); err != nil {
				t.Fatal(err)
			}
			path, err := prepareEnvoy(c)
			if tc.invalid {
				if err == nil || !strings.Contains(err.Error(), "ext_authz") {
					t.Fatalf("invalid authorization config: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			raw, err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			for _, required := range []string{`"failure_mode_allow":false`, `"encode_raw_headers":true`, `"allow_partial_message":false`, `"pack_as_bytes":true`, `"max_request_bytes":65536`} {
				if !strings.Contains(string(raw), required) {
					t.Fatalf("missing authorization invariant %s: %s", required, raw)
				}
			}
		})
	}
}
