// gateway-e2e-compose is the static trusted consumer for the kind fixture. It
// resolves fixture inputs, emits policy before workload resources, and does no I/O
// against Kubernetes. fixtures-deploy owns resource writes and readiness.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/egress-gateway/egress-gateway/enrollment"
	apps "k8s.io/api/apps/v1"
	core "k8s.io/api/core/v1"
	network "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/yaml"
)

func main() {
	input := flag.String("input", "", "business resource List")
	options := flag.String("options", "", "trusted enrollment options keyed by workload/egress")
	flag.Parse()
	if err := run(*input, *options); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(input, options string) error {
	raw, err := os.ReadFile(input)
	if err != nil {
		return err
	}
	opts, err := os.ReadFile(options)
	if err != nil {
		return err
	}
	result, err := compose(raw, opts)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(result)
	return err
}
func compose(raw, opts []byte) ([]byte, error) {
	var list struct {
		APIVersion, Kind string
		Items            []json.RawMessage `json:"items"`
	}
	if err := yaml.UnmarshalStrict(raw, &list); err != nil {
		return nil, err
	}
	var options map[string]enrollment.Options
	if err := yaml.UnmarshalStrict(opts, &options); err != nil {
		return nil, err
	}
	var policies, resources []any
	seen := map[string]bool{}
	for _, item := range list.Items {
		var identity struct {
			Kind     string
			Metadata meta.ObjectMeta
		}
		if err := json.Unmarshal(item, &identity); err != nil {
			return nil, err
		}
		var business *core.Pod
		var deployment apps.Deployment
		switch {
		case identity.Kind == "Pod" && identity.Metadata.Name == "workload":
			business = &core.Pod{}
			if err := json.Unmarshal(item, business); err != nil {
				return nil, err
			}
		case identity.Kind == "Deployment" && identity.Metadata.Name == "egress":
			if err := json.Unmarshal(item, &deployment); err != nil {
				return nil, err
			}
			business = &core.Pod{ObjectMeta: *deployment.Spec.Template.ObjectMeta.DeepCopy(), Spec: *deployment.Spec.Template.Spec.DeepCopy()}
			business.Name = identity.Metadata.Name
			business.Namespace = identity.Metadata.Namespace
		default:
			resources = append(resources, item)
			continue
		}
		o, ok := options[business.Name]
		if !ok || seen[business.Name] {
			return nil, fmt.Errorf("missing/duplicate composition for %s", business.Name)
		}
		seen[business.Name] = true
		pod, policy, err := enrollment.ComposePod(business, o)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", business.Name, err)
		}
		policies = append(policies, network.NetworkPolicy{TypeMeta: meta.TypeMeta{APIVersion: "networking.k8s.io/v1", Kind: "NetworkPolicy"}, ObjectMeta: meta.ObjectMeta{Name: "gateway-" + business.Name, Namespace: business.Namespace}, Spec: policy.Spec})
		if identity.Kind == "Deployment" {
			deployment.Spec.Template.Spec = pod.Spec
			deployment.Spec.Template.Labels = pod.Labels
			deployment.Spec.Template.Annotations = pod.Annotations
			resources = append(resources, deployment)
		} else {
			resources = append(resources, pod)
		}
	}
	if !seen["workload"] || !seen["egress"] {
		return nil, fmt.Errorf("both fixture roles required")
	}
	return yaml.Marshal(map[string]any{"apiVersion": "v1", "kind": "List", "items": append(policies, resources...)})
}
