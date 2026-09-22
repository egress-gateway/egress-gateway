package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/egress-gateway/egress-gateway/config"
)

func TestPrepareOPA(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "input.yaml")
	raw := []byte("services:\n  policies:\n    url: https://policies.test\nplugins:\n  envoy_ext_authz_grpc:\n    path: fixture/authz/allow\ndistributed_tracing:\n  type: grpc\n  address: native:4317\n")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	c := config.Config{OPAConfig: source, RuntimeDir: dir}
	path, err := prepareOPA(c)
	if err != nil || path != source {
		t.Fatalf("native changed: %s %v", path, err)
	}
	c.Tracing = &config.Tracing{Protocol: "grpc", Address: "collector:4317", ServiceName: "opa-test", SampleRatio: 1}
	path, err = prepareOPA(c)
	if err != nil {
		t.Fatal(err)
	}
	read := func() map[string]any {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		return got
	}
	got := read()
	tracing := got["distributed_tracing"].(map[string]any)
	if tracing["address"] != "collector:4317" || tracing["type"] != "grpc" || got["services"] == nil || got["plugins"] == nil {
		t.Fatalf("bad merge: %+v", got)
	}
	if tracing["batch_span_processor_options"].(map[string]any)["blocking"] != false {
		t.Fatal("exporter can block requests")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private config: %v %v", info, err)
	}
	c.Tracing.Disabled = true
	if _, err := prepareOPA(c); err != nil {
		t.Fatal(err)
	}
	if len(read()["distributed_tracing"].(map[string]any)) != 0 {
		t.Fatal("disable retained native exporter")
	}
	unchanged, _ := os.ReadFile(source)
	if string(unchanged) != string(raw) {
		t.Fatal("modified caller's native config")
	}
}
