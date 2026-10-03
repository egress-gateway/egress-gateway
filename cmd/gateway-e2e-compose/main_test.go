package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/internal/artifacts"

	core "k8s.io/api/core/v1"
	"sigs.k8s.io/yaml"
)

func TestFixtureUsesPublicCompositionBeforeCreation(t *testing.T) {
	raw, err := os.ReadFile("../../test/e2e/config/fixtures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts, err := os.ReadFile("../../test/e2e/config/enrollment.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opts = []byte(strings.NewReplacer("${GATEWAY_TEST_IMAGE}", "gateway:test", "${CURL_TEST_IMAGE}", "curl:test").Replace(string(opts)))
	output, err := compose(raw, opts)
	if err != nil {
		t.Fatal(err)
	}
	var list struct{ Items []json.RawMessage }
	if err := yaml.Unmarshal(output, &list); err != nil {
		t.Fatal(err)
	}
	policies := map[string]bool{}
	roles := map[string]bool{}
	shared := map[string]bool{}
	for _, item := range list.Items {
		var o struct {
			Kind     string
			Metadata struct{ Name string }
			Spec     struct{ Template core.PodTemplateSpec }
		}
		if err := json.Unmarshal(item, &o); err != nil {
			t.Fatal(err)
		}
		if o.Kind == "NetworkPolicy" {
			policies[o.Metadata.Name] = true
		}
		if o.Kind == "ConfigMap" && strings.HasSuffix(o.Metadata.Name, "-shared") {
			var cm core.ConfigMap
			if err := json.Unmarshal(item, &cm); err != nil {
				t.Fatal(err)
			}
			role := strings.TrimSuffix(cm.Name, "-shared")
			var cfg config.PolicyRuntime
			if err := json.Unmarshal([]byte(cm.Data["runtime.json"]), &cfg); err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			for name, data := range cm.BinaryData {
				if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg.Bundle = filepath.Join(dir, filepath.Base(cfg.Bundle))
			for i := range cfg.Descriptors {
				cfg.Descriptors[i].Path = filepath.Join(dir, filepath.Base(cfg.Descriptors[i].Path))
			}
			cfgRaw, err := json.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "runtime.json")
			if err := os.WriteFile(path, cfgRaw, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := artifacts.LoadWorkload(path, config.Role(role))
			if err != nil {
				t.Fatalf("%s actual runtime load: %v", role, err)
			}
			if len(loaded.Descriptors) != 2 {
				t.Fatal("distinct descriptor views missing")
			}
			shared[role] = true
		}
		if o.Kind == "Pod" && o.Metadata.Name == "workload" {
			if !policies["gateway-workload"] {
				t.Fatal("workload before policy")
			}
			var p core.Pod
			if err := json.Unmarshal(item, &p); err != nil {
				t.Fatal(err)
			}
			if len(p.Spec.InitContainers) != 6 || p.Spec.InitContainers[2].Image != "gateway:test" {
				t.Fatal("missing managed workload")
			}
			roles["workload"] = true
			assertSharedProxy(t, p.Spec, shared["workload"])
		}
		if o.Kind == "Deployment" && o.Metadata.Name == "egress" {
			if !policies["gateway-egress"] {
				t.Fatal("egress before policy")
			}
			if len(o.Spec.Template.Spec.Containers) != 1 || o.Spec.Template.Spec.Containers[0].Image != "gateway:test" {
				t.Fatal("missing managed egress")
			}
			roles["egress"] = true
			assertSharedProxy(t, o.Spec.Template.Spec, shared["egress"])
		}
	}
	if len(roles) != 2 {
		t.Fatal("missing role")
	}
}

func assertSharedProxy(t *testing.T, spec core.PodSpec, staged bool) {
	t.Helper()
	if !staged {
		t.Fatal("shared artifacts must precede the consumer")
	}
	found := false
	for _, c := range append(spec.InitContainers, spec.Containers...) {
		for _, env := range c.Env {
			if env.Name != config.EnvWorkloadConfig {
				continue
			}
			if c.Name != "istio-proxy" || len(c.Args) != 0 || env.Value != "/etc/gateway/shared/runtime.json" {
				t.Fatal("shared input leaked or fixture authorization retained")
			}
			found = true
		}
		for _, mount := range c.VolumeMounts {
			if mount.Name == "gateway-shared" && (c.Name != "istio-proxy" || !mount.ReadOnly) {
				t.Fatal("shared artifact mount not private and immutable")
			}
		}
	}
	if !found {
		t.Fatal("shared runtime input missing")
	}
}
