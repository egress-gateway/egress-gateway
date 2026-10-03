package enrollment_test

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"

	networking "github.com/egress-gateway/egress-gateway-networking/enrollment"
	"github.com/egress-gateway/egress-gateway/config"
	"github.com/egress-gateway/egress-gateway/enrollment"
	core "k8s.io/api/core/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func inputs() (*core.Pod, enrollment.Options) {
	p := &core.Pod{ObjectMeta: meta.ObjectMeta{Name: "business", Namespace: "apps"}, Spec: core.PodSpec{ServiceAccountName: "business", Containers: []core.Container{{Name: "app", Image: "app:trusted", SecurityContext: &core.SecurityContext{RunAsUser: new(int64(1000)), RunAsGroup: new(int64(1000)), AllowPrivilegeEscalation: new(false), Capabilities: &core.Capabilities{Drop: []core.Capability{"ALL"}}}}}}}
	o := enrollment.Options{Role: config.Workload, Image: "gateway:trusted", TrustImage: "app:trusted", TrustPath: "/etc/ssl/certs/ca-certificates.crt", TrustMounts: map[string]string{"app": "/etc/ssl/certs/ca-certificates.crt"}, DiscoveryAddress: "istiod.mesh.svc:15012", ProxyConfig: `{"discoveryAddress":"istiod.mesh.svc:15012"}`, Network: networking.Network{Namespace: "apps", Binding: "resolved"}}
	return p, o
}
func TestExternalComposition(t *testing.T) {
	for _, role := range []config.Role{config.Workload, config.Egress} {
		t.Run(string(role), func(t *testing.T) {
			p, o := inputs()
			o.Role = role
			if role == config.Egress {
				o.TrustMounts = nil
				o.OriginTrustConfigMap = "origin-ca"
				p.Spec.Containers = nil
			}
			original := p.DeepCopy()
			optionsBefore, _ := json.Marshal(o)
			result, policy, err := enrollment.ComposePod(p, o)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(p, original) {
				t.Fatal("mutated business input")
			}
			optionsAfter, _ := json.Marshal(o)
			if string(optionsBefore) != string(optionsAfter) {
				t.Fatal("mutated options")
			}
			again, policyAgain, err := enrollment.ComposePod(p, o)
			if err != nil || !reflect.DeepEqual(result, again) || !reflect.DeepEqual(policy, policyAgain) {
				t.Fatal("not deterministic", err)
			}
			if result.Labels[networking.BindingLabel] != "resolved" || len(policy.Spec.Egress) != 0 {
				t.Fatal("binding/default denial lost")
			}
			if result.Spec.AutomountServiceAccountToken == nil || *result.Spec.AutomountServiceAccountToken {
				t.Fatal("implicit API credentials")
			}
			var order []string
			for _, c := range result.Spec.InitContainers {
				order = append(order, c.Name)
			}
			expected := []string{"prepare-volumes", "management-init"}
			if role == config.Workload {
				expected = append(expected, "istio-proxy", "base-trust", "trust-init")
			}
			if !slices.Equal(order, expected) {
				t.Fatalf("startup order %v", order)
			}
			if role == config.Workload {
				m := result.Spec.Containers[0].VolumeMounts
				if len(m) != 1 || m[0].Name != "bundle" || !m[0].ReadOnly || m[0].SubPath != config.BundleFile {
					t.Fatal("application trust not isolated")
				}
			}
			result.Spec.InitContainers[0].Command[0] = "mutated"
			if reflect.DeepEqual(result, again) {
				t.Fatal("result alias")
			}
		})
	}
}
func TestBusinessBoundaryRejectsCollisions(t *testing.T) {
	tests := map[string]func(*core.Pod){
		"reserved uid":  func(p *core.Pod) { p.Spec.Containers[0].SecurityContext.RunAsUser = new(int64(1337)) },
		"inherited gid": func(p *core.Pod) { p.Spec.SecurityContext = &core.PodSecurityContext{RunAsGroup: new(int64(1337))} },
		"supplemental group": func(p *core.Pod) {
			p.Spec.SecurityContext = &core.PodSecurityContext{SupplementalGroups: []int64{1337}}
		},
		"fs group": func(p *core.Pod) { p.Spec.SecurityContext = &core.PodSecurityContext{FSGroup: new(int64(1337))} },
		"private mount": func(p *core.Pod) {
			p.Spec.Containers[0].VolumeMounts = []core.VolumeMount{{Name: "state", MountPath: "/stolen"}}
		},
		"policy mount": func(p *core.Pod) {
			p.Spec.Containers[0].VolumeMounts = []core.VolumeMount{{Name: "gateway-policy", MountPath: "/policy"}}
		},
		"volume substitution": func(p *core.Pod) {
			p.Spec.Volumes = []core.Volume{{Name: "state", VolumeSource: core.VolumeSource{EmptyDir: &core.EmptyDirVolumeSource{}}}}
		},
		"managed name": func(p *core.Pod) { p.Spec.Containers[0].Name = "istio-proxy" },
		"managed init": func(p *core.Pod) {
			p.Spec.InitContainers = []core.Container{{Name: "management-init", Image: "attacker"}}
		},
		"injection label": func(p *core.Pod) { p.Labels = map[string]string{"sidecar.istio.io/inject": "true"} },
		"capture annotation": func(p *core.Pod) {
			p.Annotations = map[string]string{"traffic.sidecar.istio.io/excludeOutboundIPRanges": "0.0.0.0/0"}
		},
		"network capability": func(p *core.Pod) {
			p.Spec.Containers[0].SecurityContext.Capabilities.Add = []core.Capability{"NET_ADMIN"}
		},
		"automount credentials": func(p *core.Pod) { p.Spec.AutomountServiceAccountToken = new(true) },
		"aliased token": func(p *core.Pod) {
			p.Spec.Volumes = []core.Volume{{Name: "alias", VolumeSource: core.VolumeSource{Projected: &core.ProjectedVolumeSource{Sources: []core.VolumeProjection{{ServiceAccountToken: &core.ServiceAccountTokenProjection{Audience: "istio-ca", Path: "token"}}}}}}}
		},
		"host network": func(p *core.Pod) { p.Spec.HostNetwork = true },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p, o := inputs()
			mutate(p)
			before := p.DeepCopy()
			pod, policy, err := enrollment.ComposePod(p, o)
			if err == nil || pod != nil || policy != nil {
				t.Fatalf("accepted invalid input: %v", err)
			}
			if !reflect.DeepEqual(before, p) {
				t.Fatal("mutated rejected input")
			}
		})
	}
}

func TestTrustedPolicyIsOnlyMountedByProxy(t *testing.T) {
	for _, role := range []config.Role{config.Workload, config.Egress} {
		t.Run(string(role), func(t *testing.T) {
			p, o := inputs()
			o.Role, o.PolicyConfigMap = role, "resolved-policy"
			if role == config.Egress {
				o.TrustMounts = nil
			}
			got, _, err := enrollment.ComposePod(p, o)
			if err != nil {
				t.Fatal(err)
			}
			for _, c := range append(slices.Clone(got.Spec.InitContainers), got.Spec.Containers...) {
				mount := slices.IndexFunc(c.VolumeMounts, func(m core.VolumeMount) bool { return m.Name == "gateway-policy" })
				if c.Name == "istio-proxy" {
					if mount < 0 || !c.VolumeMounts[mount].ReadOnly || !slices.Equal(c.Args, []string{"--policy", "/etc/gateway/policy/policy.rego"}) {
						t.Fatal("proxy does not load the trusted policy")
					}
				} else if mount >= 0 {
					t.Fatalf("policy exposed to %s", c.Name)
				}
			}
			index := slices.IndexFunc(got.Spec.Volumes, func(v core.Volume) bool { return v.Name == "gateway-policy" })
			if index < 0 || got.Spec.Volumes[index].ConfigMap == nil || got.Spec.Volumes[index].ConfigMap.Name != o.PolicyConfigMap {
				t.Fatal("policy source differs from the trusted caller's input")
			}
		})
	}
}
func TestBusinessInitAfterTrustedReadiness(t *testing.T) {
	p, o := inputs()
	init := *p.Spec.Containers[0].DeepCopy()
	init.Name = "business-init"
	p.Spec.InitContainers = []core.Container{init}
	got, _, err := enrollment.ComposePod(p, o)
	if err != nil {
		t.Fatal(err)
	}
	if got.Spec.InitContainers[5].Name != "business-init" {
		t.Fatal("business init precedes trust")
	}
}
func TestRejectRuntimeOverride(t *testing.T) {
	p, o := inputs()
	o.ProxyEnv = []core.EnvVar{{Name: "GATEWAY_RUNTIME_DIR", Value: "/shared"}}
	got, policy, err := enrollment.ComposePod(p, o)
	if err == nil || !strings.Contains(err.Error(), "override") || got != nil || policy != nil {
		t.Fatal("runtime override allowed")
	}
}
