package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

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
		}
		if o.Kind == "Deployment" && o.Metadata.Name == "egress" {
			if !policies["gateway-egress"] {
				t.Fatal("egress before policy")
			}
			if len(o.Spec.Template.Spec.Containers) != 1 || o.Spec.Template.Spec.Containers[0].Image != "gateway:test" {
				t.Fatal("missing managed egress")
			}
			roles["egress"] = true
		}
	}
	if len(roles) != 2 {
		t.Fatal("missing role")
	}
}
