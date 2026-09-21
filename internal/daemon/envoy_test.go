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
