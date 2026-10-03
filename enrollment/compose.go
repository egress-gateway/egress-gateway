// Package enrollment composes Gateway-owned Kubernetes components with business
// execution. Callers own resolved identities, immutable configuration and writes.
package enrollment

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	networking "github.com/egress-gateway/egress-gateway-networking/enrollment"
	"github.com/egress-gateway/egress-gateway/config"
	core "k8s.io/api/core/v1"
)

// Options must come from the trusted enrollment caller, independently of the
// business Pod. Referenced images and ConfigMaps require caller-owned integrity.
// This integration supports the existing Istio runtime with its default paths.
type Options struct {
	Role            config.Role     `json:"role"`
	Image           string          `json:"image"`
	ImagePullPolicy core.PullPolicy `json:"imagePullPolicy,omitempty"`
	// TrustImage contains the application's original system trust at TrustPath.
	TrustImage string `json:"trustImage,omitempty"`
	TrustPath  string `json:"trustPath,omitempty"`
	// TrustMounts selects regular business containers and their system trust paths.
	TrustMounts      map[string]string `json:"trustMounts,omitempty"`
	DiscoveryAddress string            `json:"discoveryAddress"`
	ProxyConfig      string            `json:"proxyConfig"`
	// ProxyEnv supplies trusted provider/telemetry inputs, never Gateway overrides.
	ProxyEnv             []core.EnvVar `json:"proxyEnv,omitempty"`
	OriginTrustConfigMap string        `json:"originTrustConfigMap,omitempty"`
	// PolicyConfigMap supplies policy.rego through the existing daemon --policy input.
	PolicyConfigMap string             `json:"policyConfigMap,omitempty"`
	Network         networking.Network `json:"network"`
}

//go:embed managed.json
var managedJSON []byte

// ComposePod returns an independent final Pod and the policy to install before
// creating it. It performs no I/O and returns neither output on any error.
func ComposePod(business *core.Pod, o Options) (*core.Pod, *networking.Policy, error) {
	fail := func(err error) (*core.Pod, *networking.Policy, error) { return nil, nil, err }
	if business == nil {
		return fail(fmt.Errorf("business Pod required"))
	}
	if o.Role != config.Workload && o.Role != config.Egress {
		return fail(fmt.Errorf("unsupported role %q", o.Role))
	}
	if o.Image == "" || o.DiscoveryAddress == "" || o.ProxyConfig == "" {
		return fail(fmt.Errorf("image, discovery address and proxy config required"))
	}
	if o.Role == config.Workload && (o.TrustImage == "" || !cleanPath(o.TrustPath)) {
		return fail(fmt.Errorf("application trust image and absolute trust path required"))
	}
	var managed core.PodSpec
	if err := json.Unmarshal(managedJSON, &managed); err != nil {
		return fail(err)
	}
	p := business.DeepCopy()
	if err := protectBusiness(p, managed); err != nil {
		return fail(err)
	}
	p.Spec.AutomountServiceAccountToken = new(false)
	if p.Annotations == nil {
		p.Annotations = map[string]string{}
	}
	p.Annotations["sidecar.istio.io/inject"] = "false"
	if o.Role == config.Workload {
		delete(p.Annotations, "sidecar.istio.io/inject") // Explicit sidecar status enables Istio CNI.
		p.Annotations["sidecar.istio.io/status"] = `{"initContainers":["istio-proxy"],"containers":[],"volumes":[],"imagePullSecrets":[],"revision":"default"}`
		p.Annotations["traffic.sidecar.istio.io/includeInboundPorts"] = ""
		p.Annotations["traffic.sidecar.istio.io/includeOutboundIPRanges"] = "*"
	}
	trusted := networking.TrustedSpec{Volumes: managed.Volumes, NetworkInitContainers: []string{"management-init"}}
	for _, c := range managed.InitContainers {
		c.Image = o.Image
		c.ImagePullPolicy = o.ImagePullPolicy
		if c.ImagePullPolicy == "" {
			c.ImagePullPolicy = core.PullIfNotPresent
		}
		if c.Name == "base-trust" {
			c.Image = o.TrustImage
			c.Command[1] = o.TrustPath
		}
		if o.Role == config.Egress && (c.Name == "base-trust" || c.Name == "trust-init") {
			continue
		}
		if c.Name == "istio-proxy" {
			if o.PolicyConfigMap != "" {
				c.Args = []string{"--policy", "/etc/gateway/policy/policy.rego"}
				c.VolumeMounts = append(c.VolumeMounts, core.VolumeMount{Name: "gateway-policy", MountPath: "/etc/gateway/policy", ReadOnly: true})
				trusted.Volumes = append(trusted.Volumes, core.Volume{Name: "gateway-policy", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: o.PolicyConfigMap}}}})
			}
			c.Env = proxyEnv(o)
			seen := map[string]bool{}
			for _, e := range c.Env {
				seen[e.Name] = true
			}
			for _, e := range o.ProxyEnv {
				if seen[e.Name] || strings.HasPrefix(e.Name, "GATEWAY_") || e.Name == "OPA_CONFIG" || e.Name == "ENVOY_CONFIG" {
					return fail(fmt.Errorf("proxy environment override %q prohibited", e.Name))
				}
				seen[e.Name] = true
				c.Env = append(c.Env, *e.DeepCopy())
			}
			if o.OriginTrustConfigMap != "" {
				c.VolumeMounts = append(c.VolumeMounts, core.VolumeMount{Name: "origin-trust", MountPath: "/etc/gateway/origin", ReadOnly: true})
				trusted.Volumes = append(trusted.Volumes, core.Volume{Name: "origin-trust", VolumeSource: core.VolumeSource{ConfigMap: &core.ConfigMapVolumeSource{LocalObjectReference: core.LocalObjectReference{Name: o.OriginTrustConfigMap}}}})
			}
			if o.Role == config.Egress {
				c.RestartPolicy = nil
				c.StartupProbe = nil
				trusted.Containers = append(trusted.Containers, c)
				continue
			}
		}
		trusted.InitContainers = append(trusted.InitContainers, c)
	}
	for name, mount := range o.TrustMounts {
		if o.Role != config.Workload || !cleanPath(mount) {
			return fail(fmt.Errorf("invalid application trust mount for %s", name))
		}
		index := slices.IndexFunc(p.Spec.Containers, func(c core.Container) bool { return c.Name == name })
		if index < 0 {
			return fail(fmt.Errorf("trust container %q missing", name))
		}
		c := &p.Spec.Containers[index]
		for _, m := range c.VolumeMounts {
			if m.MountPath == mount {
				return fail(fmt.Errorf("trust mount collision in %s", name))
			}
		}
		c.VolumeMounts = append(c.VolumeMounts, core.VolumeMount{Name: "bundle", MountPath: mount, SubPath: config.BundleFile, ReadOnly: true})
	}
	p.Spec.InitContainers = append(trusted.InitContainers, p.Spec.InitContainers...)
	p.Spec.Containers = append(p.Spec.Containers, trusted.Containers...)
	p.Spec.Volumes = append(p.Spec.Volumes, trusted.Volumes...)
	policy, err := networking.ExpandPolicy(o.Network)
	if err != nil {
		return fail(err)
	}
	p, err = networking.ExpandPod(p, networking.Options{Network: o.Network, Trusted: trusted})
	if err != nil {
		return fail(err)
	}
	return p, policy, nil
}
func cleanPath(p string) bool { return strings.HasPrefix(p, "/") && p != "/" && path.Clean(p) == p }
func protectBusiness(p *core.Pod, managed core.PodSpec) error {
	for key := range p.Labels {
		if strings.Contains(key, "istio.io/") {
			return fmt.Errorf("business label %q is Gateway-owned", key)
		}
	}
	for key := range p.Annotations {
		if strings.Contains(key, "istio.io/") {
			return fmt.Errorf("business annotation %q is Gateway-owned", key)
		}
	}
	if p.Spec.AutomountServiceAccountToken != nil && *p.Spec.AutomountServiceAccountToken {
		return fmt.Errorf("business service account token automount prohibited")
	}
	reserved := map[string]bool{"origin-trust": true, "gateway-policy": true}
	names := map[string]bool{}
	for _, v := range managed.Volumes {
		reserved[v.Name] = true
	}
	for _, c := range managed.InitContainers {
		names[c.Name] = true
	}
	for _, v := range p.Spec.Volumes {
		if reserved[v.Name] {
			return fmt.Errorf("business volume %q is Gateway-owned", v.Name)
		}
		if v.Projected != nil {
			for _, source := range v.Projected.Sources {
				if source.ServiceAccountToken != nil {
					return fmt.Errorf("business token projection %q exposes Gateway identity", v.Name)
				}
			}
		}
	}
	ps := p.Spec.SecurityContext
	if ps != nil {
		if reservedID(ps.RunAsUser) || reservedID(ps.RunAsGroup) || reservedID(ps.FSGroup) || slices.Contains(ps.SupplementalGroups, int64(1337)) {
			return fmt.Errorf("business Pod identity collides with Gateway UID/GID 1337")
		}
	}
	for _, group := range [][]core.Container{p.Spec.InitContainers, p.Spec.Containers} {
		for _, c := range group {
			if names[c.Name] {
				return fmt.Errorf("business container %q is Gateway-owned", c.Name)
			}
			if c.SecurityContext != nil && (reservedID(c.SecurityContext.RunAsUser) || reservedID(c.SecurityContext.RunAsGroup)) {
				return fmt.Errorf("business container %s collides with Gateway identity", c.Name)
			}
			for _, m := range c.VolumeMounts {
				if reserved[m.Name] {
					return fmt.Errorf("business mount %q is Gateway-owned", m.Name)
				}
			}
			for _, d := range c.VolumeDevices {
				if reserved[d.Name] {
					return fmt.Errorf("business device %q is Gateway-owned", d.Name)
				}
			}
		}
	}
	return nil
}
func reservedID(v *int64) bool { return v != nil && *v == 1337 }
func proxyEnv(o Options) []core.EnvVar {
	intercept := "REDIRECT"
	if o.Role == config.Egress {
		intercept = "NONE"
	}
	env := []core.EnvVar{{Name: config.EnvRole, Value: string(o.Role)}, {Name: config.EnvProxyMode, Value: string(config.Istio)},
		{Name: "ISTIO_META_WORKLOAD_NAME", Value: string(o.Role)}, {Name: "CA_ADDR", Value: o.DiscoveryAddress}, {Name: "JWT_POLICY", Value: "third-party-jwt"},
		{Name: "PILOT_CERT_PROVIDER", Value: "istiod"}, {Name: "ISTIO_META_CLUSTER_ID", Value: "Kubernetes"}, {Name: "ISTIO_META_MESH_ID", Value: "cluster.local"},
		{Name: "TRUST_DOMAIN", Value: "cluster.local"}, {Name: "ISTIO_META_INTERCEPTION_MODE", Value: intercept}, {Name: "PROXY_CONFIG", Value: o.ProxyConfig}}
	for _, f := range []struct{ name, path string }{{"POD_NAME", "metadata.name"}, {"POD_NAMESPACE", "metadata.namespace"}, {"INSTANCE_IP", "status.podIP"}, {"SERVICE_ACCOUNT", "spec.serviceAccountName"}} {
		env = append(env, core.EnvVar{Name: f.name, ValueFrom: &core.EnvVarSource{FieldRef: &core.ObjectFieldSelector{FieldPath: f.path}}})
	}
	return env
}
